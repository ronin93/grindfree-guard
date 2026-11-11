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
```

Unit tests inject a mock `post` and never make a funded call. See the repo README for LangChain, OpenAI Agents, and MCP examples, prices, and enforcement rules.
