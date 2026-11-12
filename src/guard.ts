import {
  askHuman as askHumanCall,
  waitForHuman as waitForHumanCall,
  enforceHuman,
  guardDecisionFrom,
  type AskHumanInput,
  type AskHumanTicket,
  type AskHumanDecision,
  type WaitOptions,
} from "./askhuman.js";
import type { GuardReviewRequired } from "./errors.js";
import { newSessionId, type EgressAction, type EgressInput, type TrifectaEvent, type TrifectaPolicy } from "./trifecta.js";
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

export type ReadInput = {
  url: string;
  format?: "markdown" | "text";
  mode?: "strip" | "flag";
  max_chars?: number;
  include_links?: boolean;
  include_images?: boolean;
  main_content?: boolean;
  policy?: Record<string, unknown>;
};

export type SafeReadResult = {
  /** Clean Markdown/text with hidden content and injected instructions removed (strip mode). */
  text: string;
  title?: string;
  finalUrl?: string;
  decision: NormalizedDecision;
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

  /** SafeRead raw call (no enforcement): fetch a URL as clean Markdown/text. */
  readUrl(input: ReadInput | string): Promise<NormalizedDecision> {
    return this.call("saferead", "read", clean({ ...toReadInput(input) }));
  }

  /**
   * Fetch a URL through SafeRead and return clean text. Does NOT throw on a
   * "block" verdict: injected instructions are already removed from `text`;
   * inspect `decision.verdict` / `decision.findings` to see what was taken out.
   */
  async safeRead(input: ReadInput | string): Promise<SafeReadResult> {
    return toReadResult(await this.readUrl(input));
  }

  /** Like safeRead, but enforces: block → GuardDenied, warn → onReview policy. */
  async requireSafeRead(input: ReadInput | string): Promise<SafeReadResult> {
    return toReadResult(await this.callAndEnforce("saferead", "read", clean({ ...toReadInput(input) })));
  }

  /** AskHuman: put one proposed action in front of a human ($0.03). Returns a ticket; poll with waitForHuman. */
  askHuman(input: AskHumanInput): Promise<AskHumanTicket> {
    return askHumanCall(this.paidFetch, input, this.options.timeoutMs);
  }

  /** Free long-poll until the human decides or the request expires. */
  waitForHuman(ticket: Pick<AskHumanTicket, "id" | "poll_token">, opts?: WaitOptions): Promise<AskHumanDecision> {
    return waitForHumanCall(this.paidFetch, ticket, opts);
  }

  /** Ask, wait, and throw GuardDenied unless approved/edited. Returns the decision (use edited_args when status is "edited"). */
  async requireHumanApproval(input: AskHumanInput, opts?: WaitOptions): Promise<AskHumanDecision> {
    const ticket = await this.askHuman(input);
    return enforceHuman(await this.waitForHuman(ticket, opts));
  }

  /**
   * Run fn only after a human approves. Typical use: catch GuardReviewRequired from another
   * guard and escalate: guard.withHumanApproval({ action, notify }, fn, err).
   */
  async withHumanApproval<T>(
    input: AskHumanInput,
    fn: (decision: AskHumanDecision) => Promise<T> | T,
    reviewError?: GuardReviewRequired,
    opts?: WaitOptions,
  ): Promise<{ value: T; human: AskHumanDecision }> {
    const human = await this.requireHumanApproval(
      reviewError && !input.guard_decision ? { ...input, guard_decision: guardDecisionFrom(reviewError) } : input,
      opts,
    );
    return { value: await fn(human), human };
  }

  /** TrifectaGate raw check (no enforcement). */
  checkEgress(input: EgressInput): Promise<NormalizedDecision> {
    return this.call("trifectagate", "check", clean({ ...input }));
  }

  /** TrifectaGate enforced: block → GuardDenied, review → onReview policy; runs fn only when allowed. */
  async gateEgress<T>(input: EgressInput, fn: () => Promise<T> | T): Promise<GuardedResult<T>> {
    const decision = await this.callAndEnforce("trifectagate", "check", clean({ ...input }));
    return { value: await fn(), decision } as GuardedResult<T>;
  }

  /**
   * A per-session gate. Queue events as the agent touches data (free, local), and they are
   * sent with the next guarded action (one $0.002 call per outbound action).
   */
  session(opts: { sessionId?: string; policy?: TrifectaPolicy; ttlSeconds?: number } = {}): TrifectaSession {
    return new TrifectaSession(this, opts.sessionId ?? newSessionId(), opts.policy, opts.ttlSeconds);
  }
}

export class TrifectaSession {
  private pending: TrifectaEvent[] = [];
  constructor(
    private readonly guard: GrindFreeGuard,
    readonly sessionId: string,
    private readonly policy?: TrifectaPolicy,
    private readonly ttlSeconds?: number,
  ) {}
  /** Record that the agent read private data (inbox, DB, files, CRM...). */
  privateData(source: string, labels?: string[]): this {
    this.pending.push(clean({ type: "private_data", source, labels }) as TrifectaEvent);
    return this;
  }
  /** Record that the agent ingested untrusted content (web page, email body, doc, tool output). */
  untrusted(source: string, origin?: string, verdict?: TrifectaEvent["verdict"]): this {
    this.pending.push(clean({ type: "untrusted_content", source, origin, verdict }) as TrifectaEvent);
    return this;
  }
  /** If the service never decided (transport/HTTP error), keep the events for the next call. */
  private requeueIfUnseen(body: EgressInput, err: unknown): void {
    const d = (err as { decision?: NormalizedDecision })?.decision;
    const serverDecided = d && d.endpoint !== "error" && typeof d.raw?.decision === "string";
    if (body.events?.length && !serverDecided) this.pending.unshift(...body.events);
  }
  private body(action: EgressAction): EgressInput {
    const events = this.pending.splice(0, 50);
    return clean({ session_id: this.sessionId, session_ttl_seconds: this.ttlSeconds, events: events.length ? events : undefined, action, policy: this.policy }) as EgressInput;
  }
  /** Check an outbound action (no enforcement). Events are re-queued if the call fails. */
  async check(action: EgressAction): Promise<NormalizedDecision> {
    const body = this.body(action);
    try {
      return await this.guard.checkEgress(body);
    } catch (err) {
      this.requeueIfUnseen(body, err);
      throw err;
    }
  }
  /** Run fn only if TrifectaGate allows the action (block → GuardDenied, review → onReview). */
  async gate<T>(action: EgressAction, fn: () => Promise<T> | T): Promise<GuardedResult<T>> {
    const body = this.body(action);
    try {
      return await this.guard.gateEgress(body, fn);
    } catch (err) {
      this.requeueIfUnseen(body, err);
      throw err;
    }
  }
}

function toReadInput(input: ReadInput | string): ReadInput {
  return typeof input === "string" ? { url: input } : input;
}

function toReadResult(decision: NormalizedDecision): SafeReadResult {
  const raw = decision.raw;
  return {
    text: decision.safeText ?? "",
    title: typeof raw.title === "string" ? raw.title : undefined,
    finalUrl: typeof raw.final_url === "string" ? raw.final_url : undefined,
    decision,
  };
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
