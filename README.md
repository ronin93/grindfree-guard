# @grindfree/guard

Drop-in guards that screen **[GrindFree](https://grindfree.net)** x402 agent-security APIs **before** an agent acts, then enforce `allow | review | deny`. Payments use the **caller’s** Base USDC wallet via the official [`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch) / Python `x402` clients. This repo never ships or accepts GrindFree keys.

| Service | Endpoint | Price | What it checks |
|---|---|---|---|
| **PromptShield** | `POST https://promptshield.grindfree.net/v1/screen` · `/v1/clean` | $0.002 | Prompt-injection screen + HTML→LLM clean text |
| **CrawlSafe** | `POST https://crawlsafe.grindfree.net/v1/check` | $0.002 | robots.txt / X-Robots-Tag crawl gate (not malware scanning) |
| **ToolGuard** | `POST https://toolguard.grindfree.net/v1/evaluate` | $0.002 | Pre-tool-call `allow \| review \| deny` vs owner policy |
| **CommandGuard** | `POST https://commandguard.grindfree.net/v1/command` · `/v1/sql` | $0.001 | Shell + SQL check: `allow \| warn \| block` |
| **MemoryGuard** | `POST https://memoryguard.grindfree.net/v1/screen` | $0.002 | Content before it is written to agent memory |
| **WireShield** | `POST https://wireshield.grindfree.net/v1/scan` | $0.002 | Outbound leak check on agent output |
| **DocShield** | `POST https://docshield.grindfree.net/v1/scan` | $0.004 | Hidden instructions in PDF / Office / HTML / Markdown |
| **SafeRead** | `POST https://saferead.grindfree.net/v1/read` | $0.003 | Fetch a URL as clean Markdown with hidden text + prompt injections removed (`allow \| warn \| block`) |
| **AskHuman** | `POST https://askhuman.grindfree.net/v1/request` | $0.03 | Human-in-the-loop: one-tap approve / deny / edit link to the owner (ntfy, Slack, Discord, webhook); free status polling; fails closed |
| **TrifectaGate** | `POST https://trifectagate.grindfree.net/v1/check` | $0.002 | Session exfiltration gate: private data + untrusted content + outbound action → allow / review / block |

Network: Base (`eip155:8453`). The remote API is advisory — **your adapter must enforce the decision**. This package does that: `deny` / `block` / high risk throws `GuardDenied` and does not run the action; `review` / `warn` / medium risk throws `GuardReviewRequired` unless you set `onReview: "allow"`. Transport failures **fail closed** (`onError: "deny"` by default).

Also available: the MCP server [`@grindfree/agent-security-mcp`](https://github.com/ronin93/grindfree-agent-security) (`npx -y @grindfree/agent-security-mcp`).

Contact: [rob@grindfree.net](mailto:rob@grindfree.net) · [@grindfreelabs](https://x.com/grindfreelabs)

---

## Install

```bash
npm i @grindfree/guard
```

```bash
pip install 'grindfree-guard[x402]'
# until PyPI is published: pip install -e 'python/[x402]'
```

Set the **caller’s** funded Base USDC key (never commit it):

```bash
export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
# PRIVATE_KEY and EVM_PRIVATE_KEY are also accepted
```

## Quickstart (TypeScript)

```ts
import { createGuard, GuardDenied, GuardReviewRequired } from "@grindfree/guard";

const guard = createGuard({
  policy: { allow_tools: ["http.fetch"], allow_hosts: ["api.example.com"], require_https: true },
});

const { value } = await guard.guardToolCall(
  { tool: "http.fetch", destination: { host: "api.example.com", scheme: "https", port: 443 }, arg_classes: ["url"] },
  () => fetch("https://api.example.com/items").then((r) => r.json()),
);

// Shell: CommandGuard runs first. A wipe like `rm -rf $HOME` throws GuardDenied and is not executed.
await guard.guardCommand({ command: "ls -la" }, () => runShell("ls -la"));

// Web pages: SafeRead fetches the URL for you and returns clean Markdown with injected
// instructions already removed. safeRead never throws on "block"; requireSafeRead does.
const page = await guard.safeRead("https://example.com/blog/post");
console.log(page.title, page.decision.verdict, page.text);

// Human approval: AskHuman ($0.03) sends the owner a one-tap approve/deny link and waits
// (free long-poll). Throws GuardDenied on deny or timeout. Great for GuardReviewRequired.
try {
  await guard.guardToolCall(toolCall, () => sendRefund());
} catch (err) {
  if (!(err instanceof GuardReviewRequired)) throw err;
  await guard.withHumanApproval(
    { action: { title: "Refund order #1234", tool: "stripe.refunds.create", args, risk: "medium" },
      notify: { ntfy_topic: "my-agent-approvals-7f3a" }, timeout_seconds: 900 },
    () => sendRefund(),
    err,
  );
}

// Exfiltration gate: TrifectaGate remembers what the session touched (events are queued
// locally and sent with the next check) and blocks the lethal trifecta. $0.002 per action.
const session = guard.session({ policy: { allow_hosts: ["api.mycompany.com"] } });
session.privateData("gmail.read");
session.untrusted("web.fetch", "https://blog.example/post", page.decision.rawDecision as any);
await session.gate({ type: "http_request", destination: "https://collector.example/c", method: "POST" }, () => postIt());
// → GuardDenied (LETHAL_TRIFECTA); review → GuardReviewRequired (escalate with withHumanApproval)
```

Python: `text, decision = guard.safe_read("https://example.com/blog/post")` (or `require_safe_read` to enforce); `guard.require_human_approval({...})` / `guard.with_human_approval({...}, fn, review_error)` for AskHuman; `s = guard.session(); s.private_data(...); s.untrusted(...); s.gate({...}, fn)` for TrifectaGate.

`createGuard({ fetch })` (JS) or `create_guard(post=...)` (Python) injects a mock for tests — unit tests in this repo never make a funded call.

### Verdicts

| Service result | Normalized `verdict` | Default handling |
|---|---|---|
| ToolGuard `allow`; CommandGuard `allow`; PromptShield `low`; CrawlSafe `crawl_allowed: true` | `allow` | run the action |
| ToolGuard `review`; CommandGuard `warn`; PromptShield `medium`; Memory/Wire/Doc `review` | `review` | throw `GuardReviewRequired` (or set `onReview: "allow"` / `"deny"` / a callback) |
| ToolGuard `deny`; CommandGuard `block`; PromptShield `high`; CrawlSafe not allowed; Memory/Wire/Doc `block` | `deny` | throw `GuardDenied`, do not run the action |
| Timeout / HTTP error | (fail closed) | throw `GuardDenied` unless `onError: "throw"` or `"allow"` |

## Framework examples

Copy-paste starters (wallet still comes from `X402_PRIVATE_KEY`):

- [`examples/basic.ts`](examples/basic.ts) — `guardToolCall` + `guardCommand`
- [`examples/langchain-js/guard-tools.ts`](examples/langchain-js/guard-tools.ts) — wrap LangChain JS tools
- [`examples/langchain-py/guard_tools.py`](examples/langchain-py/guard_tools.py) — LangChain Python wrapper + callback
- [`examples/openai-agents/guardrails.ts`](examples/openai-agents/guardrails.ts) — OpenAI Agents SDK input/output guardrails
- [`examples/mcp-client/wrap-mcp.ts`](examples/mcp-client/wrap-mcp.ts) — wrap `client.callTool` (CommandGuard for shell/SQL tools, ToolGuard otherwise)

```ts
import { wrapMcpClient } from "@grindfree/guard";
const client = wrapMcpClient(mcpClient, { policy: { allow_tools: ["mcp.search"] } });
// Shell/SQL-named tools go through CommandGuard; everything else through ToolGuard.
```

Python twin (`guard_tool_call`, `guard_command`, `require_safe_prompt`, …) lives in [`python/`](python/).

## API (JS)

```ts
const guard = createGuard({
  privateKey,          // optional; otherwise env
  fetch,               // optional mock / pre-wrapped paid fetch
  policy,              // default owner policy
  onReview: "throw",   // or "allow" | "deny" | async (d) => "allow"
  onError: "deny",     // or "throw" | "allow"
  timeoutMs: 15_000,
});

await guard.guardToolCall(call, fn);
guard.wrapTool(name, fn, classify?);
await guard.guardCommand({ command }, fn);
await guard.guardSql({ sql }, fn);
await guard.requireSafePrompt({ content, format });
await guard.requireCrawlAllowed({ url });
await guard.requireSafeMemory({ content, source });
await guard.requireSafeOutput({ content, format });
await guard.requireSafeDocument({ content, format });
// plus evaluateTool / checkCommand / screenPrompt / … for inspect-only
```

## Honest limits

- Heuristic / policy layers, not a full security program.
- CrawlSafe is not malware, phishing, or legal advice.
- Deterministic rule packs can miss novel phrasing. Decisions are advisory at the API; **this library enforces them in-process** and cannot stop a caller who bypasses it.
- DocShield parses structure and text; it does not OCR images. Legacy `.doc` / `.xls` / `.ppt` return 415 and are not charged.
- Missing ToolGuard policy → `review`.
- Unit tests mock payment. Do not point tests at the live paid endpoints without a separate spend approval.

## License

MIT — see [LICENSE](./LICENSE).
