# grindfree-guard (Python)

Python twin of [`@grindfree/guard`](https://github.com/ronin93/grindfree-guard). Screens GrindFree x402 agent-security APIs before an action runs. The caller’s Base USDC wallet pays; this package never ships GrindFree keys.

```bash
pip install 'grindfree-guard[x402]'   # when published; until then: pip install -e '.[x402]'
export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
```

```python
from grindfree_guard import create_guard, GuardDenied

guard = create_guard(policy={"allow_tools": ["http.fetch"], "allow_hosts": ["api.example.com"], "require_https": True})

try:
    result = guard.guard_tool_call(
        {"tool": "http.fetch", "destination": {"host": "api.example.com", "scheme": "https"}},
        lambda: fetch_items(),
    )
    print(result.value)
except GuardDenied as err:
    print("blocked", err.decision.reasons)

# Read a web page safely (SafeRead, $0.003): clean Markdown, injected instructions removed.
text, decision = guard.safe_read("https://example.com/blog/post")

# Ask the owner first (AskHuman, $0.03): one-tap approve/deny link; raises GuardDenied on deny/timeout.
human = guard.require_human_approval({
    "action": {"title": "Refund order #1234", "args": {"amount": 82.10}, "risk": "medium"},
    "notify": {"ntfy_topic": "my-agent-approvals-7f3a"},
    "timeout_seconds": 900,
})
```

Unit tests inject a mock `post` and never make a funded call. See the repo README for LangChain, OpenAI Agents, and MCP examples, prices, and enforcement rules.
