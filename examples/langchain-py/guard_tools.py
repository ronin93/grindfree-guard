"""
LangChain Python: wrap tools / use a callback so checks run before the action.
    pip install 'grindfree-guard[x402]' langchain-core
    export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY

The API is advisory; this wrapper enforces allow/review/deny. Never embed keys.
"""
from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

from grindfree_guard import (
    GuardDenied,
    GuardReviewRequired,
    create_guard,
)

guard = create_guard(
    policy={
        "allow_tools": ["http.fetch", "shell.exec"],
        "allow_hosts": ["api.example.com"],
        "require_https": True,
    }
)


def with_tool_guard(name: str, fn: Callable[..., Any], classify: Callable[..., dict] | None = None):
    """Run ToolGuard, then fn, only if the verdict allows it."""

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        payload = classify(*args, **kwargs) if classify else {"tool": name}
        payload.setdefault("tool", name)
        return guard.guard_tool_call(payload, lambda: fn(*args, **kwargs)).value

    wrapped.__name__ = getattr(fn, "__name__", name)
    wrapped.__doc__ = getattr(fn, "__doc__", None)
    return wrapped


# Optional LangChain StructuredTool / @tool usage
try:
    from langchain_core.tools import tool
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # the example still works without LangChain installed
    tool = None
    BaseCallbackHandler = object  # type: ignore


def _fetch(url: str) -> str:
    import urllib.request

    with urllib.request.urlopen(url, timeout=15) as res:  # noqa: S310 - gated by ToolGuard allowlist
        return res.read().decode("utf-8", "replace")


fetch_url = with_tool_guard(
    "http.fetch",
    _fetch,
    classify=lambda url: {
        "tool": "http.fetch",
        "destination": {"host": urlparse(url).hostname, "scheme": urlparse(url).scheme, "port": urlparse(url).port or 443},
        "arg_classes": ["url"],
    },
)


def run_shell(command: str) -> str:
    """CommandGuard ($0.001) runs first; the command is not executed on block."""
    try:
        return guard.guard_command({"command": command, "shell": "bash"}, lambda: f"(example) would run: {command}").value
    except GuardDenied as err:
        return f"blocked: {'; '.join(err.decision.reasons)}"
    except GuardReviewRequired as err:
        return f"needs review: {'; '.join(err.decision.reasons)}"


if tool is not None:

    @tool
    def http_fetch(url: str) -> str:
        """Fetch a public HTTPS URL (ToolGuard-gated)."""
        return fetch_url(url)

    @tool
    def shell_exec(command: str) -> str:
        """Run a shell command after CommandGuard. Blocked commands are not executed."""
        return run_shell(command)


class GrindFreeToolCallback(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback: evaluate ToolGuard when a tool starts. Raise to abort."""

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        from grindfree_guard import enforce_sync

        name = (serialized or {}).get("name") or "tool"
        decision = guard.evaluate_tool({"tool": name, "arg_classes": ["input"]})
        # Fail closed: deny and (default) review raise before the tool body.
        enforce_sync(decision)
