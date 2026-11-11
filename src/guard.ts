import { createPaidFetch, postJson, type ClientOptions, type PaidFetch } from "./client.js";
import { enforce, enforceError, normalizeDecision, type EnforceOptions, type NormalizedDecision } from "./decisions.js";
import { GuardDenied, GuardError } from "./errors.js";
import { serviceUrl, type ServiceName } from "./services.js";

export type ToolCallInput = {
  tool: string;
  destination?: { host?: string; scheme?: string; port?: number; path_class?: string };
  arg_classes?: string[];
  taint?: string[];
  secret_labels?: string[];
  policy?: Record<string, unknown>;
  policy_hash?: string;
  rule_pack?: string;
};

export type CommandInput = {
  command: string;
  shell?: "bash" | "sh" | "zsh" | "fish" | "powershell" | "cmd";
  policy?: Record<string, unknown>;
};

export type SqlInput = {
  sql: string;
  dialect?: "postgres" | "mysql" | "mariadb" | "sqlite" | "mssql" | "snowflake" | "bigquery" | "other";
  policy?: Record<string, unknown>;
};

export type PromptInput = { content: string; format?: "text" | "html" };

export type CrawlInput = { url: string; user_agent?: string; check_page?: boolean };

export type MemoryInput = {
  content?: string;
  source?: "user" | "assistant" | "tool" | "web" | "document" | "email" | "retrieved" | "mcp" | "unknown";
  memory_type?: "fact" | "preference" | "instruction" | "episodic" | "summary";
  entries?: Array<{ key?: string; content: string; source?: string }>;
  policy?: Record<string, unknown>;
};

export type OutputInput = {
  content: string;
  format?: "markdown" | "text" | "html" | "json";
  allowed_domains?: string[];
  canaries?: string[];
  system_prompt?: string;
  policy?: Record<string, unknown>;
};

export type DocumentInput = {
  content?: string;
  content_base64?: string;
  format?: "html" | "markdown" | "text";
  filename?: string;
  include_text?: boolean;
  policy?: Record<string, unknown>;
};

export type GuardOptions = ClientOptions &
  EnforceOptions & {
    /** Default ToolGuard / CommandGuard policy sent when a call omits one. */
    policy?: Record<string, unknown>;
  };

export type GuardedResult<T> = {
  value: T;
  decision: NormalizedDecision;
};

function clean<T extends Record<string, unknown>>(obj: T): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

export class GrindFreeGuard {
  readonly options: GuardOptions;
  private readonly paidFetch: PaidFetch;

  constructor(options: GuardOptions = {}) {
    this.options = options;
    this.paidFetch = createPaidFetch(options);
  }

  private enforceOpts(): EnforceOptions {
    return { onReview: this.options.onReview, onError: this.options.onError };
  }

  private async call(service: ServiceName, endpoint: string, body: unknown): Promise<NormalizedDecision> {
    const url = serviceUrl(service, endpoint);
    try {
      const raw = await postJson(this.paidFetch, url, body, {
        timeoutMs: this.options.timeoutMs,
        service,
      });
      return normalizeDecision(service, endpoint, raw);
    } catch (err) {
      if (this.options.onError === "allow") {
        if (err instanceof GuardDenied) throw err;
        const message = err instanceof Error ? err.message : String(err);
        return {
          verdict: "allow",
          service,
          endpoint,
          reasons: [`transport failure allowed by onError=allow: ${message}`],
          findings: [],
          raw: { error: message },
        };
      }
      enforceError(err, service, this.enforceOpts());
    }
  }

  private async callAndEnforce(service: ServiceName, endpoint: string, body: unknown): Promise<NormalizedDecision> {
    const decision = await this.call(service, endpoint, body);
    return enforce(decision, this.enforceOpts());
  }

  /** ToolGuard evaluate only (no enforcement). */
  evaluateTool(input: ToolCallInput): Promise<NormalizedDecision> {
    const body = clean({ ...input, policy: input.policy ?? this.options.policy });
    return this.call("toolguard", "evaluate", body);
  }

  /**
   * Screen a tool call with ToolGuard, enforce allow/review/deny, then run `fn`.
   * On deny (or review with default onReview=throw) `fn` is not called.
   */
  async guardToolCall<T>(input: ToolCallInput, fn: () => Promise<T> | T): Promise<GuardedResult<T>> {
    const decision = await this.callAndEnforce("toolguard", "evaluate", clean({ ...input, policy: input.policy ?? this.options.policy }));
    const value = await fn();
    return { value, decision };
  }

  /**
   * Wrap any tool function so ToolGuard runs first.
   * `classify` maps arguments to a ToolGuard body; defaults to `{ tool: name }`.
   */
  wrapTool<Args extends unknown[], R>(
    name: string,
    fn: (...args: Args) => Promise<R> | R,
    classify?: (...args: Args) => ToolCallInput | Promise<ToolCallInput>,
  ): (...args: Args) => Promise<R> {
    return async (...args: Args) => {
      const input = classify ? await classify(...args) : { tool: name };
      const { value } = await this.guardToolCall({ ...input, tool: input.tool ?? name }, () => fn(...args));
      return value;
    };
  }

  checkCommand(input: CommandInput): Promise<NormalizedDecision> {
    return this.call("commandguard", "command", clean({ ...input, policy: input.policy ?? this.options.policy }));
  }

  async guardCommand<T>(input: CommandInput, fn: () => Promise<T> | T): Promise<GuardedResult<T>> {
    const decision = await this.callAndEnforce("commandguard", "command", clean({ ...input, policy: input.policy ?? this.options.policy }));
    return { value: await fn(), decision };
  }

  checkSql(input: SqlInput): Promise<NormalizedDecision> {
    return this.call("commandguard", "sql", clean({ ...input, policy: input.policy ?? this.options.policy }));
  }

  async guardSql<T>(input: SqlInput, fn: () => Promise<T> | T): Promise<GuardedResult<T>> {
    const decision = await this.callAndEnforce("commandguard", "sql", clean({ ...input, policy: input.policy ?? this.options.policy }));
    return { value: await fn(), decision };
  }

  screenPrompt(input: PromptInput): Promise<NormalizedDecision> {
    return this.call("promptshield", "screen", input);
  }

  /**
   * Screen untrusted text/HTML. Throws on high risk (deny). Returns sanitized
   * text (or the original when the service did not supply one).
   */
  async requireSafePrompt(input: PromptInput): Promise<{ text: string; decision: NormalizedDecision }> {
    const decision = await this.callAndEnforce("promptshield", "screen", input);
    return { text: decision.sanitized ?? input.content, decision };
  }

  async cleanHtml(content: string): Promise<{ text: string; raw: Record<string, unknown> }> {
    try {
      const raw = await postJson(this.paidFetch, serviceUrl("promptshield", "clean"), { content }, {
        timeoutMs: this.options.timeoutMs,
        service: "promptshield",
      });
      return { text: typeof raw.text === "string" ? raw.text : "", raw };
    } catch (err) {
      if (this.options.onError === "allow") {
        return { text: content, raw: { error: err instanceof Error ? err.message : String(err) } };
      }
      enforceError(err, "promptshield", this.enforceOpts());
    }
  }

  checkCrawl(input: CrawlInput): Promise<NormalizedDecision> {
    return this.call("crawlsafe", "check", input);
  }

  async requireCrawlAllowed(input: CrawlInput): Promise<NormalizedDecision> {
    return this.callAndEnforce("crawlsafe", "check", input);
  }

  screenMemory(input: MemoryInput): Promise<NormalizedDecision> {
    return this.call("memoryguard", "screen", clean({ ...input, policy: input.policy ?? this.options.policy }));
  }

  async requireSafeMemory(input: MemoryInput): Promise<{ text?: string; decision: NormalizedDecision }> {
    const decision = await this.callAndEnforce("memoryguard", "screen", clean({ ...input, policy: input.policy ?? this.options.policy }));
    return { text: decision.sanitized ?? input.content, decision };
  }

  scanOutput(input: OutputInput): Promise<NormalizedDecision> {
    return this.call("wireshield", "scan", clean({ ...input, policy: input.policy ?? this.options.policy }));
  }

  async requireSafeOutput(input: OutputInput): Promise<{ text: string; decision: NormalizedDecision }> {
    const decision = await this.callAndEnforce("wireshield", "scan", clean({ ...input, policy: input.policy ?? this.options.policy }));
    return { text: decision.sanitized ?? input.content, decision };
  }

  scanDocument(input: DocumentInput): Promise<NormalizedDecision> {
    return this.call("docshield", "scan", clean({ ...input, policy: input.policy ?? this.options.policy }));
  }

  async requireSafeDocument(input: DocumentInput): Promise<{ text?: string; decision: NormalizedDecision }> {
    const decision = await this.callAndEnforce("docshield", "scan", clean({ ...input, policy: input.policy ?? this.options.policy }));
    return { text: decision.safeText ?? decision.sanitized ?? input.content, decision };
  }
}

export function createGuard(options: GuardOptions = {}): GrindFreeGuard {
  return new GrindFreeGuard(options);
}

/** Convenience wrapper around `createGuard(...).guardToolCall`. */
export function guardToolCall<T>(
  input: ToolCallInput,
  fn: () => Promise<T> | T,
  options: GuardOptions = {},
): Promise<GuardedResult<T>> {
  return createGuard(options).guardToolCall(input, fn);
}

/**
 * Express/fetch-style middleware: evaluate an outbound tool described by
 * `classify(request)` and only call `next` when the verdict allows it.
 */
export function createGuardMiddleware(options: GuardOptions = {}) {
  const guard = createGuard(options);
  return async function grindfreeMiddleware<Req, Res>(
    classify: (req: Req) => ToolCallInput | Promise<ToolCallInput>,
    next: (req: Req) => Promise<Res> | Res,
    req: Req,
  ): Promise<GuardedResult<Res>> {
    const input = await classify(req);
    return guard.guardToolCall(input, () => next(req));
  };
}
