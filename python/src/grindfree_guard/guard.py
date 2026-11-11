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
from .errors import GuardDenied, GuardError
from .services import service_url

T = TypeVar("T")


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
    ) -> None:
        self.policy = policy
        self.on_review = on_review
        self.on_error = on_error
        self.timeout = timeout
        self._post = create_post(private_key=private_key, post=post, timeout=timeout)

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


def create_guard(**kwargs: Any) -> GrindFreeGuard:
    return GrindFreeGuard(**kwargs)


def guard_tool_call(input: dict[str, Any], fn: Callable[[], T], **kwargs: Any) -> GuardedResult:
    return create_guard(**kwargs).guard_tool_call(input, fn)
