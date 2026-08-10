"""
Gemini API client with model failover and exponential backoff.

Tries multiple Gemini models in order, with retries and a per-attempt
timeout, to handle enterprise rate limits and transient failures.
"""

import logging
import os
import re
import time
from typing import Callable

from google import genai
from google.genai import types

from .models import ReviewReport

logger = logging.getLogger(__name__)

# Models to try in priority order. Keep these explicit instead of using moving
# ``-latest`` aliases so an audit remains reproducible across releases.
FAILOVER_MODELS = [
    model.strip()
    for model in os.environ.get(
        "AEGISSCAN_GEMINI_MODELS",
        "gemini-3.6-flash,gemini-3.5-flash",
    ).split(",")
    if model.strip()
]

# Maximum retries per model
MAX_RETRIES = int(os.environ.get("AEGISSCAN_MAX_RETRIES", "3"))

# Timeout per individual API call (seconds)
API_TIMEOUT_SECONDS = int(os.environ.get("AEGISSCAN_API_TIMEOUT", "180"))

# Batches are bounded, but evidence ledgers can still be verbose. Both default
# models support a substantially larger output window than this conservative cap.
MAX_OUTPUT_TOKENS = int(os.environ.get("AEGISSCAN_MAX_OUTPUT_TOKENS", "16384"))

# Initial backoff delay (doubles on each retry)
INITIAL_BACKOFF_SECONDS = int(os.environ.get("AEGISSCAN_INITIAL_BACKOFF", "15"))


def _safe_error_summary(error: Exception, limit: int = 240) -> str:
    """Produce a compact provider error without exposing credentials in URLs."""
    summary = " ".join(str(error).split()) or type(error).__name__
    summary = re.sub(r"(?i)([?&](?:key|api_key)=)[^&\s]+", r"\1[REDACTED]", summary)
    summary = re.sub(r"AIza[0-9A-Za-z_-]{20,}", "[REDACTED_API_KEY]", summary)
    return summary[:limit]


def _is_retryable(error: Exception) -> bool:
    """Retry transient transport/provider failures, not permanent client errors."""
    code = getattr(error, "code", None)
    if not isinstance(code, int):
        return True
    return code in {408, 409, 429} or code >= 500


def call_gemini_with_failover(
    client: genai.Client,
    prompt: str,
    progress: Callable[[str], None] | None = None,
) -> ReviewReport:
    """
    Send the review prompt to Gemini, trying multiple models with retries.

    Uses structured JSON output mode with the ReviewReport schema.
    Each attempt has a 180-second timeout enforced via a thread pool.

    Args:
        client: An initialized google.genai Client.
        prompt: The fully assembled review prompt.

    Returns:
        A parsed ReviewReport from the LLM.

    Raises:
        RuntimeError: If all models and retries are exhausted.
    """
    safety_settings = [
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
    ]

    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        # ``response_schema`` uses Gemini's narrower OpenAPI-schema transport,
        # which rejects Pydantic's ``additionalProperties`` keyword. The JSON
        # Schema transport supports that keyword and preserves our strict model.
        response_json_schema=ReviewReport.model_json_schema(),
        max_output_tokens=MAX_OUTPUT_TOKENS,
        safety_settings=safety_settings,
        http_options=types.HttpOptions(timeout=API_TIMEOUT_SECONDS * 1000),
    )

    notify = progress or (lambda _message: None)
    last_failures: dict[str, str] = {}

    for model_name in FAILOVER_MODELS:
        retry_delay = INITIAL_BACKOFF_SECONDS
        for attempt in range(MAX_RETRIES):
            try:
                notify(
                    f"[AI] Model {model_name} · attempt {attempt + 1}/{MAX_RETRIES} · "
                    f"timeout {API_TIMEOUT_SECONDS}s"
                )
                logger.info(
                    f"Sending audit batch to Gemini ({model_name}) for structured analysis "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})..."
                )
                # The SDK enforces this at the HTTP transport layer, so a timed-out
                # attempt does not leave a worker thread that blocks executor shutdown.
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                )

                if response.parsed is None and not response.text:
                    raise ValueError(
                        "Structured JSON parsing failed (likely truncated). "
                        "Triggering retry."
                    )

                if isinstance(response.parsed, ReviewReport):
                    report = response.parsed
                elif response.parsed is not None:
                    report = ReviewReport.model_validate(response.parsed)
                else:
                    report = ReviewReport.model_validate_json(response.text)
                notify(
                    f"[AI] Model {model_name} returned a schema-valid ReviewReport "
                    f"with {len(report.issues)} candidate issues"
                )
                logger.info(
                    f"Received review from Gemini ({model_name}) "
                    f"with {len(report.issues)} issues."
                )
                return report

            except Exception as e:
                logger.warning(f"Request to {model_name} failed: {e}")
                reason = _safe_error_summary(e)
                last_failures[model_name] = reason
                notify(
                    f"[WARNING] Model {model_name} attempt {attempt + 1} failed: {reason}"
                )
                if not _is_retryable(e):
                    notify(
                        f"[WARNING] Provider returned non-retryable HTTP {e.code}; "
                        "skipping remaining attempts for this model"
                    )
                    break
                if attempt < MAX_RETRIES - 1:
                    notify(f"[AI] Retrying in {retry_delay}s with exponential backoff")
                    time.sleep(retry_delay)
                    retry_delay *= 2
        notify(f"[WARNING] Model {model_name} exhausted; moving to the next fallback model")

    details = "; ".join(
        f"{model}: {last_failures.get(model, 'no response')}"
        for model in FAILOVER_MODELS
    )
    raise RuntimeError(f"All Gemini models failed. {details}")
