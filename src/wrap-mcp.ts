/**
 * MCP client wrapper: evaluate ToolGuard before client.callTool, and
 * CommandGuard when the tool looks like a shell/SQL execution.
 *
 * No MCP SDK dependency. Pass any client with callTool().
 * export X402_PRIVATE_KEY=0xYOUR_BASE_USDC_PRIVATE_KEY
 */
import { createGuard, type GrindFreeGuard } from "./guard.js";
import { GuardDenied, GuardReviewRequired } from "./errors.js";

export type WrapMcpOptions = {
  guard?: GrindFreeGuard;
  /** Tool names treated as shell execution (CommandGuard). */
  commandTools?: string[];
  /** Tool names treated as SQL execution (CommandGuard /v1/sql). */
  sqlTools?: string[];
  policy?: Record<string, unknown>;
};

const DEFAULT_COMMAND_TOOLS = ["shell", "bash", "sh", "terminal", "run_command", "execute_command", "command"];
const DEFAULT_SQL_TOOLS = ["sql", "query", "execute_sql", "run_sql"];

function nameOf(tool: { name?: string } | string): string {
  return typeof tool === "string" ? tool : tool.name ?? "tool";
}

function looksLike(name: string, list: string[]): boolean {
  const n = name.toLowerCase();
  return list.some((t) => n === t || n.endsWith(`.${t}`) || n.endsWith(`_${t}`) || n.includes(t));
}

/**
 * Wrap an MCP client so every callTool is screened first. The original
 * client is returned for chaining; callTool is replaced in place.
 */
export function wrapMcpClient<T extends { callTool: (...args: any[]) => any }>(client: T, opts: WrapMcpOptions = {}): T {
  const guard = opts.guard ?? createGuard({ policy: opts.policy });
  const commandTools = opts.commandTools ?? DEFAULT_COMMAND_TOOLS;
  const sqlTools = opts.sqlTools ?? DEFAULT_SQL_TOOLS;
  const original = client.callTool.bind(client);

  client.callTool = async (params, ...rest) => {
    const toolName = nameOf((params as { name?: string }) ?? {});
    const args = ((params as { arguments?: Record<string, unknown> })?.arguments ?? {}) as Record<string, unknown>;
    try {
      if (looksLike(toolName, commandTools) && typeof (args.command ?? args.cmd ?? args.input) === "string") {
        const command = String(args.command ?? args.cmd ?? args.input);
        await guard.guardCommand({ command }, async () => undefined);
      } else if (looksLike(toolName, sqlTools) && typeof (args.sql ?? args.query ?? args.statement) === "string") {
        const sql = String(args.sql ?? args.query ?? args.statement);
        await guard.guardSql({ sql }, async () => undefined);
      } else {
        await guard.guardToolCall(
          { tool: `mcp.${toolName}`, arg_classes: Object.keys(args) },
          async () => undefined,
        );
      }
    } catch (err) {
      if (err instanceof GuardDenied || err instanceof GuardReviewRequired) throw err;
      throw err;
    }
    return original(params, ...rest);
  };

  return client;
}
