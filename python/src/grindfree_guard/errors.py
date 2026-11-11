from __future__ import annotations

from typing import Any


class GuardConfigError(RuntimeError):
    code = "GUARD_CONFIG"


class GuardError(RuntimeError):
    code = "GUARD_ERROR"

    def __init__(self, message: str, *, service: str, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.service = service
        self.status = status
        self.body = body


class GuardDenied(RuntimeError):
    code = "GUARD_DENIED"
    verdict = "deny"

    def __init__(self, decision: Any, message: str | None = None) -> None:
        super().__init__(message or _default(decision, "denied"))
        self.service = decision.service
        self.decision = decision


class GuardReviewRequired(RuntimeError):
    code = "GUARD_REVIEW"
    verdict = "review"

    def __init__(self, decision: Any, message: str | None = None) -> None:
        super().__init__(message or _default(decision, "needs review"))
        self.service = decision.service
        self.decision = decision


def _default(decision: Any, kind: str) -> str:
    reasons = getattr(decision, "reasons", None) or []
    reason = reasons[0] if reasons else getattr(decision, "advice", None) or getattr(decision, "raw_decision", None) or getattr(decision, "risk", None) or kind
    return f"GrindFree {decision.service} {kind}: {reason}"
