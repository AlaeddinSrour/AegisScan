"""Shared attempt limits and content-free request timing for AI triage."""

from contextlib import contextmanager
from dataclasses import dataclass
import time


class AIBudgetExceeded(RuntimeError):
    pass


@dataclass
class RequestBudget:
    limit: int = 6
    used: int = 0
    batch: int = 0
    phase: str = "initial"

    def reserve(self) -> None:
        if self.used >= self.limit:
            raise AIBudgetExceeded(f"AI batch request limit ({self.limit}) reached")
        self.used += 1


def ensure_budget(telemetry, budget) -> None:
    """Fail before counting an attempt when a shared budget is exhausted."""
    if budget is None or budget.used < budget.limit:
        return
    if telemetry is not None:
        telemetry["budget_exhaustions"] = telemetry.get("budget_exhaustions", 0) + 1
    budget.reserve()


@contextmanager
def timed_request(telemetry, provider, budget=None):
    if budget is not None:
        try:
            budget.reserve()
        except AIBudgetExceeded:
            if telemetry is not None:
                telemetry["budget_exhaustions"] = telemetry.get("budget_exhaustions", 0) + 1
            raise
    started = time.monotonic()
    number = 0
    if telemetry is not None:
        number = telemetry.get("timed_requests", 0) + 1
        telemetry["timed_requests"] = number
    failed = 0
    try:
        yield
    except BaseException:
        failed = 1
        raise
    finally:
        if telemetry is not None:
            elapsed = max(0, round((time.monotonic() - started) * 1000))
            telemetry[f"request_{number}_{provider}_milliseconds"] = elapsed
            telemetry[f"request_{number}_transport_failed"] = failed
            if budget is not None:
                telemetry[f"request_{number}_batch"] = budget.batch
                telemetry[f"request_{number}_phase_{budget.phase}"] = 1
            telemetry["request_milliseconds"] = telemetry.get("request_milliseconds", 0) + elapsed
