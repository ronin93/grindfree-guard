/**
 * LangChain JS: wrap tools so ToolGuard (and CommandGuard) run before invoke.
 * npm i @grindfree/guard @langchain/core
 * export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
 *
 * Decisions are advisory at the API; this wrapper enforces them. A model
 * cannot grant itself permission.
 */
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";
import { createGuard, GuardDenied, GuardReviewRequired } from "@grindfree/guard";

const guard = createGuard({
  policy: { allow_tools: ["http.fetch", "shell.exec"], allow_hosts: ["api.example.com"], require_https: true },
  onReview: "throw", // pause for a human; set "allow" only if you accept warnings
});

/** Wrap any LangChain tool so ToolGuard evaluates metadata before the tool body runs. */
export function withToolGuard<T extends { name: string; invoke: (...args: any[]) => Promise<any> }>(
  tool: T,
  classify: (input: unknown) => Parameters<typeof guard.guardToolCall>[0] = () => ({ tool: tool.name }),
): T {
  const invoke = tool.invoke.bind(tool);
  tool.invoke = (async (input: unknown, ...rest: unknown[]) => {
    const { value } = await guard.guardToolCall(classify(input), () => invoke(input, ...rest));
    return value;
  }) as T["invoke"];
  return tool;
}

export const fetchUrl = withToolGuard(
  new DynamicStructuredTool({
    name: "http.fetch",
    description: "Fetch a public HTTPS URL (ToolGuard-gated).",
    schema: z.object({ url: z.string().url() }),
    func: async ({ url }) => {
      const res = await fetch(url);
      return await res.text();
    },
  }),
  (input) => {
    const url = new URL((input as { url: string }).url);
    return {
      tool: "http.fetch",
      destination: { host: url.host, scheme: url.protocol.replace(":", ""), port: url.port ? Number(url.port) : 443 },
      arg_classes: ["url"],
    };
  },
);

export const shellExec = new DynamicStructuredTool({
  name: "shell.exec",
  description: "Run a shell command after CommandGuard ($0.001). Blocked commands are not executed.",
  schema: z.object({ command: z.string() }),
  func: async ({ command }) => {
    try {
      const { value } = await guard.guardCommand({ command, shell: "bash" }, async () => {
        // Replace with your executor. This callback is skipped on block/review.
        return `(example) would run: ${command}`;
      });
      return value;
    } catch (err) {
      if (err instanceof GuardDenied) return `blocked: ${err.decision.reasons.join("; ")}`;
      if (err instanceof GuardReviewRequired) return `needs review: ${err.decision.reasons.join("; ")}`;
      throw err;
    }
  },
});
