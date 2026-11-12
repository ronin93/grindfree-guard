from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Literal

from .errors import GuardDenied, GuardError, GuardReviewRequired

Verdict = Literal["allow", "review", "deny"]
ReviewMode = Literal["throw", "allow", "deny"]
ErrorMode = Literal["deny", "throw", "allow"]
OnReview = ReviewMode | Callable[[Any], ReviewMode]


@dataclass
class NormalizedDecision:
    verdict: Verdict
    service: str
    endpoint: str
    raw_decision: str | None = None
    risk: str | None = None
    reasons: list[str] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    advice: str | None = None
    sanitized: str | None = None
    safe_text: str | None = None
    crawl_allowed: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def normalize_decision(service: str, endpoint: str, raw: dict[str, Any]) -> NormalizedDecision:
    if isinstance(raw.get("findings"), list):
        findings = raw["findings"]
    elif service == "saferead":
        findings = [*(raw.get("removed") or []), *(raw.get("flagged") or [])]
    else:
        findings = []
    reasons = _collect_reasons(raw, findings)
    raw_decision = raw.get("decision")
    if raw_decision is None and service == "saferead":
        raw_decision = raw.get("verdict")
    raw_decision = raw_decision.lower() if isinstance(raw_decision, str) else None
    risk = raw.get("risk") if raw.get("risk") in {"low", "medium", "high"} else None

    if service == "promptshield" and endpoint == "screen":
        verdict: Verdict = "deny" if risk == "high" else "review" if risk == "medium" else "allow"
    elif service == "crawlsafe":
        allowed = raw.get("crawl_allowed") is True or raw.get("crawlAllowed") is True
        verdict = "allow" if allowed else "deny"
    else:
        verdict = _map_raw(raw_decision)

    crawl_allowed = None
    if service == "crawlsafe":
        crawl_allowed = raw.get("crawl_allowed") is True or raw.get("crawlAllowed") is True

    return NormalizedDecision(
        verdict=verdict,
        service=service,
        endpoint=endpoint,
        raw_decision=raw_decision,
        risk=risk,
        reasons=reasons,
        findings=findings,
        advice=raw.get("advice") if isinstance(raw.get("advice"), str) else None,
        sanitized=raw.get("sanitized") if isinstance(raw.get("sanitized"), str) else None,
        safe_text=raw.get("safe_text") if isinstance(raw.get("safe_text"), str) else raw.get("safeText") if isinstance(raw.get("safeText"), str) else raw.get("content") if service == "saferead" and isinstance(raw.get("content"), str) else None,
        crawl_allowed=crawl_allowed,
        raw=raw,
    )


def _map_raw(raw: str | None) -> Verdict:
    if raw is None:
        return "review"
    if raw == "allow":
        return "allow"
    if raw in {"review", "warn"}:
        return "review"
    if raw in {"deny", "block"}:
        return "deny"
    return "review"


def _collect_reasons(raw: dict[str, Any], findings: list[Any]) -> list[str]:
    out: list[str] = []
    reasons = raw.get("reasons")
    if isinstance(reasons, list):
        for r in reasons:
            if isinstance(r, str):
                out.append(r)
            elif isinstance(r, dict) and isinstance(r.get("reason"), str):
                out.append(r["reason"])
    for f in findings:
        if isinstance(f, dict):
            rule, reason = f.get("rule"), f.get("reason")
            if isinstance(rule, str) and isinstance(reason, str):
                out.append(f"{rule}: {reason}")
            elif isinstance(rule, str):
                out.append(rule)
            elif isinstance(reason, str):
                out.append(reason)
        elif isinstance(f, str):
            out.append(f)
    return out


def enforce_sync(decision: NormalizedDecision, on_review: OnReview = "throw") -> NormalizedDecision:
    if decision.verdict == "allow":
        return decision
    if decision.verdict == "deny":
        raise GuardDenied(decision)
    mode = on_review(decision) if callable(on_review) else on_review
    if mode == "allow":
        return decision
    if mode == "deny":
        raise GuardDenied(decision, f"GrindFree {decision.service} review treated as deny")
    raise GuardReviewRequired(decision)


async def enforce(decision: NormalizedDecision, on_review: OnReview | Callable[[NormalizedDecision], Awaitable[ReviewMode]] = "throw") -> NormalizedDecision:
    if callable(on_review):
        result = on_review(decision)
        if hasattr(result, "__await__"):
            mode = await result  # type: ignore[misc]
            return enforce_sync(decision, on_review=lambda _d: mode)
    return enforce_sync(decision, on_review=on_review)  # type: ignore[arg-type]


def enforce_error(err: BaseException, service: str, on_error: ErrorMode = "deny") -> None:
    if isinstance(err, (GuardDenied, GuardReviewRequired)):
        raise err
    wrapped = err if isinstance(err, GuardError) else GuardError(str(err), service=service)
    if on_error == "throw":
        raise wrapped
    if on_error == "allow":
        raise wrapped
    raise GuardDenied(
        NormalizedDecision(
            verdict="deny",
            service=service,
            endpoint="error",
            reasons=[str(wrapped)],
            raw={"error": str(wrapped), "status": getattr(wrapped, "status", None)},
        ),
        f"GrindFree {service} failed closed: {wrapped}",
    )
