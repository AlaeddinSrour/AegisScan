"""Pydantic models for structured LLM review output."""

from typing import List, Literal
from pydantic import BaseModel, ConfigDict, Field


CodeRole = Literal[
    "RUNTIME",
    "TEST",
    "FIXTURE",
    "GENERATED",
    "DEPENDENCY",
    "DOCUMENTATION",
    "IGNORED",
    "UNKNOWN",
]
FindingStatus = Literal[
    "CONFIRMED",
    "FALSE_POSITIVE",
    "NON_RUNTIME",
    "NEEDS_REVIEW",
]
FindingConfidence = Literal["HIGH", "MEDIUM", "LOW"]
RemediationType = Literal["AUTOMATIC", "MANUAL_REQUIRED"]


class ReviewIssue(BaseModel):
    """A single security issue identified during code review."""

    model_config = ConfigDict(extra="forbid")

    file: str = Field(
        description="The relative path to the file containing the issue."
    )
    line: int = Field(
        description=(
            "The line number (1-indexed) in the file where the issue is. "
            "MUST be a valid line number in the current version of the file."
        )
    )
    severity: Literal["CRITICAL", "HIGH", "WARNING", "INFO"] = Field(
        description="Vulnerability severity."
    )
    issue_name: str = Field(
        description=(
            "Short name of the issue, e.g. SQL Injection, "
            "Vulnerable Package Import / Deprecated Dependency Semantics."
        )
    )
    description: str = Field(
        description="Strictly 1-2 sentences explaining the bug and remediation."
    )
    original_code: str = Field(
        description=(
            "Strictly the 1-2 exact lines of code that need to be replaced. "
            "Do not include entire functions. Must match exactly."
        )
    )
    suggested_fix: str = Field(
        description=(
            "Strictly the 1-2 corrected lines to replace original_code. "
            "Do not include entire functions."
        )
    )
    finding_id: str = Field(
        default="",
        description="Stable candidate ID supplied with the Semgrep finding.",
    )
    rule_id: str = Field(default="", description="Originating Semgrep rule ID.")
    confidence: FindingConfidence = Field(
        default="MEDIUM",
        description="Confidence supported by the supplied data-flow evidence.",
    )
    code_role: CodeRole = Field(
        default="UNKNOWN",
        description="Deterministic role of the affected repository file.",
    )
    source_evidence: str = Field(
        default="",
        description="Exact untrusted source or attacker-controlled input evidence.",
    )
    sink_evidence: str = Field(
        default="",
        description="Exact sensitive sink or violated security boundary.",
    )
    sink_file: str = Field(
        default="",
        description=(
            "Relative path containing the canonical sensitive sink. This may differ "
            "from the originating detector location."
        ),
    )
    sink_line: int = Field(
        default=0,
        description=(
            "One-indexed line containing the canonical sensitive sink. Helper checks "
            "and exploit-detection lines are not sinks."
        ),
    )
    reachability_evidence: str = Field(
        default="",
        description="Concise runtime path connecting the source to the sink.",
    )
    remediation_type: RemediationType = Field(
        default="AUTOMATIC",
        description="Whether a deterministic local patch is appropriate.",
    )


class FindingDisposition(BaseModel):
    """A durable verdict for one raw Semgrep candidate."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    status: FindingStatus
    reason: str = Field(
        description="Concise evidence-backed reason for the disposition."
    )
    file: str = ""
    line: int = 0
    rule_id: str = ""
    message: str = ""
    code_role: CodeRole = "UNKNOWN"
    confidence: FindingConfidence = "LOW"


class ReviewReport(BaseModel):
    """Complete structured review report returned by the LLM."""

    model_config = ConfigDict(extra="forbid")

    analysis_scratchpad: str = Field(
        description=(
            "Concise evidence summary for the audited batch. Record relevant data-flow "
            "conclusions without hidden chain-of-thought or unrelated repository content."
        )
    )
    issues: List[ReviewIssue]
    dispositions: List[FindingDisposition] = Field(
        default_factory=list,
        description=(
            "Exactly one disposition for every supplied Semgrep candidate ID. "
            "Candidates must never disappear from the audit ledger."
        ),
    )
