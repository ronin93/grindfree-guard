from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from .client import PostFn, create_post, DEFAULT_TIMEOUT
from .decisions import (
    ErrorMode,
    NormalizedDecision,
    OnReview,
    enforce_error,
    enforce_sync,
    normalize_decision,
)
from .errors import GuardDenied, GuardError, GuardReviewRequired
from .services import service_url

T = TypeVar("T")

# (url) -> dict for free GET endpoints (AskHuman status). Tests inject this.
GetFn = Callable[[str], dict[str, Any]]


def _default_get(timeout: float) -> GetFn:
    import json as _json
    import urllib.error
    import urllib.request

    def get(url: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "grindfree-guard-python"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https origin)
                return _json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            raise GuardError(f"askhuman status HTTP {e.code}", service="askhuman", status=e.code) from e

    return get


@dataclass
class HumanDecision:
    id: str
    status: str
    decision: str | None
    note: str | None
    edited_args: Any
    decided_at: str | None
    approved: bool
    raw: dict[str, Any]


@dataclass
class GuardedResult:
    value: Any
    decision: NormalizedDecision


def _clean(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if v is not None}


class GrindFreeGuard:
    def __init__(
        self,
        *,
        private_key: str | None = None,
        post: PostFn | None = None,
        policy: dict[str, Any] | None = None,
        on_review: OnReview = "throw",
        on_error: ErrorMode = "deny",
        timeout: float = DEFAULT_TIMEOUT,
        get: GetFn | None = None,
    ) -> None:
        self.policy = policy
        self.on_review = on_review
        self.on_error = on_error
        self.timeout = timeout
        self._post = create_post(private_key=private_key, post=post, timeout=timeout)
        self._get = get or _default_get(timeout + 30)

    def _call(self, service: str, endpoint: str, body: dict[str, Any]) -> NormalizedDecision:
        url = service_url(service, endpoint)
        try:
            raw = self._post(url, body)
            return normalize_decision(service, endpoint, raw)
        except Exception as err:
            if self.on_error == "allow" and not isinstance(err, GuardDenied):
                return NormalizedDecision(
                    verdict="allow",
                    service=service,
                    endpoint=endpoint,
                    reasons=[f"transport failure allowed by on_error=allow: {err}"],
                    raw={"error": str(err)},
                )
            enforce_error(err if isinstance(err, BaseException) else GuardError(str(err), service=service), service, self.on_error)
            raise  # pragma: no cover

    def _call_and_enforce(self, service: str, endpoint: str, body: dict[str, Any]) -> NormalizedDecision:
        return enforce_sync(self._call(service, endpoint, body), on_review=self.on_review)

    def evaluate_tool(self, input: dict[str, Any]) -> NormalizedDecision:
        body = _clean({**input, "policy": input.get("policy", self.policy)})
        return self._call("toolguard", "evaluate", body)

    def guard_tool_call(self, input: dict[str, Any], fn: Callable[[], T]) -> GuardedResult:
        decision = self._call_and_enforce("toolguard", "evaluate", _clean({**input, "policy": input.get("policy", self.policy)}))
        return GuardedResult(value=fn(), decision=decision)

    def wrap_tool(self, name: str, fn: Callable[..., T], classify: Callable[..., dict[str, Any]] | None = None) -> Callable[..., T]:
        def wrapped(*args: Any, **kwargs: Any) -> T:
            payload = classify(*args, **kwargs) if classify else {"tool": name}
            payload = {**payload, "tool": payload.get("tool", name)}
            return self.guard_tool_call(payload, lambda: fn(*args, **kwargs)).value

        wrapped.__name__ = getattr(fn, "__name__", name)
        wrapped.__doc__ = getattr(fn, "__doc__", None)
        return wrapped

    def check_command(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("commandguard", "command", _clean({**input, "policy": input.get("policy", self.policy)}))

    def guard_command(self, input: dict[str, Any], fn: Callable[[], T]) -> GuardedResult:
        decision = self._call_and_enforce("commandguard", "command", _clean({**input, "policy": input.get("policy", self.policy)}))
        return GuardedResult(value=fn(), decision=decision)

    def check_sql(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("commandguard", "sql", _clean({**input, "policy": input.get("policy", self.policy)}))

    def guard_sql(self, input: dict[str, Any], fn: Callable[[], T]) -> GuardedResult:
        decision = self._call_and_enforce("commandguard", "sql", _clean({**input, "policy": input.get("policy", self.policy)}))
        return GuardedResult(value=fn(), decision=decision)

    def screen_prompt(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("promptshield", "screen", input)

    def require_safe_prompt(self, input: dict[str, Any]) -> tuple[str, NormalizedDecision]:
        decision = self._call_and_enforce("promptshield", "screen", input)
        return decision.sanitized or str(input.get("content", "")), decision

    def check_crawl(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("crawlsafe", "check", input)

    def require_crawl_allowed(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call_and_enforce("crawlsafe", "check", input)

    def screen_memory(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("memoryguard", "screen", _clean({**input, "policy": input.get("policy", self.policy)}))

    def require_safe_memory(self, input: dict[str, Any]) -> tuple[str | None, NormalizedDecision]:
        decision = self._call_and_enforce("memoryguard", "screen", _clean({**input, "policy": input.get("policy", self.policy)}))
        return decision.sanitized or input.get("content"), decision

    def scan_output(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("wireshield", "scan", _clean({**input, "policy": input.get("policy", self.policy)}))

    def require_safe_output(self, input: dict[str, Any]) -> tuple[str, NormalizedDecision]:
        decision = self._call_and_enforce("wireshield", "scan", _clean({**input, "policy": input.get("policy", self.policy)}))
        return decision.sanitized or str(input.get("content", "")), decision

    def scan_document(self, input: dict[str, Any]) -> NormalizedDecision:
        return self._call("docshield", "scan", _clean({**input, "policy": input.get("policy", self.policy)}))

    def require_safe_document(self, input: dict[str, Any]) -> tuple[str | None, NormalizedDecision]:
        decision = self._call_and_enforce("docshield", "scan", _clean({**input, "policy": input.get("policy", self.policy)}))
        return decision.safe_text or decision.sanitized or input.get("content"), decision

    def read_url(self, input: dict[str, Any] | str) -> NormalizedDecision:
        """SafeRead: fetch a URL as clean Markdown/text (no enforcement)."""
        body = {"url": input} if isinstance(input, str) else _clean(dict(input))
        return self._call("saferead", "read", body)

    def safe_read(self, input: dict[str, Any] | str) -> tuple[str, NormalizedDecision]:
        """Clean text with injected instructions already removed. Does not raise on block; inspect decision."""
        decision = self.read_url(input)
        return decision.safe_text or "", decision

    def require_safe_read(self, input: dict[str, Any] | str) -> tuple[str, NormalizedDecision]:
        """Like safe_read but enforces: block -> GuardDenied, warn -> on_review policy."""
        body = {"url": input} if isinstance(input, str) else _clean(dict(input))
        decision = self._call_and_enforce("saferead", "read", body)
        return decision.safe_text or "", decision

    # --- AskHuman: human-in-the-loop approval ($0.03 per request; status is free) ---
    def ask_human(self, input: dict[str, Any]) -> dict[str, Any]:
        """Put one proposed action in front of a human. Returns the ticket (id, poll_token, approval_url, ...)."""
        try:
            return self._post(service_url("askhuman", "request"), _clean(dict(input)))
        except GuardError:
            raise
        except Exception as err:  # pragma: no cover
            raise GuardError(str(err), service="askhuman") from err

    def get_human_decision(self, ticket: dict[str, Any], wait: int = 0) -> HumanDecision:
        from urllib.parse import quote

        url = f"https://askhuman.grindfree.net/status/{quote(str(ticket['id']))}?token={quote(str(ticket['poll_token']))}"
        if wait:
            url += f"&wait={max(1, min(25, int(wait)))}"
        raw = self._get(url)
        status = str(raw.get("status"))
        return HumanDecision(
            id=str(raw.get("id", ticket["id"])), status=status, decision=raw.get("decision"), note=raw.get("note"),
            edited_args=raw.get("edited_args"), decided_at=raw.get("decided_at"), approved=status in ("approved", "edited"), raw=raw,
        )

    def wait_for_human(self, ticket: dict[str, Any], max_wait: float | None = None, poll_seconds: int = 25) -> HumanDecision:
        """Long-poll until decided or expired (fails closed: expired is not approved)."""
        import time

        deadline = time.monotonic() + (max_wait if max_wait is not None else 86400 + 60)
        while True:
            d = self.get_human_decision(ticket, poll_seconds)
            if d.status != "pending" or time.monotonic() >= deadline:
                return d

    def require_human_approval(self, input: dict[str, Any], max_wait: float | None = None) -> HumanDecision:
        """Ask + wait; raise GuardDenied unless approved/edited. Use edited_args when status == 'edited'."""
        d = self.wait_for_human(self.ask_human(input), max_wait=max_wait)
        if d.approved:
            return d
        raise GuardDenied(
            NormalizedDecision(verdict="deny", service="askhuman", endpoint="request", reasons=[f"human {d.status}" + (f": {d.note}" if d.note else "")], raw=d.raw),
            f"AskHuman: request {d.status}",
        )

    def with_human_approval(self, input: dict[str, Any], fn: Callable[[HumanDecision], T], review_error: GuardReviewRequired | None = None) -> tuple[T, HumanDecision]:
        """Run fn only after a human approves. Pass a GuardReviewRequired to show the human why it was held."""
        if review_error is not None and "guard_decision" not in input:
            dec = review_error.decision
            input = {**input, "guard_decision": {"service": dec.service, "verdict": getattr(dec, "raw_decision", None) or dec.verdict, "reasons": list(dec.reasons)[:10]}}
        d = self.require_human_approval(input)
        return fn(d), d


def create_guard(**kwargs: Any) -> GrindFreeGuard:
    return GrindFreeGuard(**kwargs)


def guard_tool_call(input: dict[str, Any], fn: Callable[[], T], **kwargs: Any) -> GuardedResult:
    return create_guard(**kwargs).guard_tool_call(input, fn)
