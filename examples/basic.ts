/**
 * Copy-paste quickstart. Payments use the CALLER'S Base USDC wallet.
 *   export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
 *   npx tsx examples/basic.ts
 * Never commit a real key. This file does not embed one.
 */
import { createGuard, GuardDenied, GuardReviewRequired } from "@grindfree/guard";

const guard = createGuard({
  policy: {
    allow_tools: ["http.fetch"],
    allow_hosts: ["api.example.com"],
    require_https: true,
  },
});

async function main() {
  try {
    const { value, decision } = await guard.guardToolCall(
      {
        tool: "http.fetch",
        destination: { host: "api.example.com", scheme: "https", port: 443 },
        arg_classes: ["url"],
      },
      () => fetch("https://api.example.com/items").then((r) => r.json()),
    );
    console.log("allowed", decision.verdict, value);
  } catch (err) {
    if (err instanceof GuardDenied) {
      console.error("blocked", err.decision.reasons);
      return;
    }
    if (err instanceof GuardReviewRequired) {
      console.error("needs a human", err.decision.reasons);
      return;
    }
    throw err;
  }

  // Shell and SQL: CommandGuard is $0.001 / call. Do not run on deny.
  await guard.guardCommand({ command: "ls -la" }, async () => {
    /* run the command only if this callback is entered */
  });
}
main();
