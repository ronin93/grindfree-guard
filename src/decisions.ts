import type { ServiceName } from "./services.js";
import { GuardDenied, GuardError, GuardReviewRequired } from "./errors.js";

/** Unified verdict used by every GrindFree check. */
export type Verdict = "allow" | "review" | "deny";

export type ReviewMode = "throw" | "allow" | "deny";
export type ErrorMode = "deny" | "throw" | "allow";

export interface NormalizedDecision {
  /** allow = proceed; review = pause for a human (CommandGuard "warn", medium risk); deny = do not proceed (block / high risk). */
  verdict: Verdict;
  service: ServiceName;
  endpoint: string;
  /** Raw service decision when present (allow/review/deny/warn/block). */
  rawDecision?: string;
  /** PromptShield risk when present. */
  risk?: "low" | "medium" | "high";
  reasons: string[];
  findings: unknown[];
  advice?: string;
  sanitized?: string;
  safeText?: string;
  crawlAllowed?: boolean;
  raw: Record<string, unknown>;
}

export type EnforceOptions = {
  onReview?: ReviewMode | ((d: NormalizedDecision) => ReviewMode | Promise<ReviewMode>);
  onError?: ErrorMode;
};

export function normalizeDecision(
  service: ServiceName,
  endpoint: string,
  raw: Record<string, unknown>,
): NormalizedDecision {
  const findings = Array.isArray(raw.findings)
    ? raw.findings
    : service === "saferead"
      ? [...(Array.isArray(raw.removed) ? raw.removed : []), ...(Array.isArray(raw.flagged) ? raw.flagged : [])]
      : [];
  const reasons = collectReasons(raw, findings);
  const sanitized = asString(raw.sanitized);
  const safeText = asString(raw.safe_text) ?? asString(raw.safeText) ?? (service === "saferead" ? asString(raw.content) : undefined);
  const advice = asString(raw.advice);
  const rawDecision =
    typeof raw.decision === "string"
      ? raw.decision.toLowerCase()
      : service === "saferead" && typeof raw.verdict === "string"
        ? raw.verdict.toLowerCase()
        : undefined;
  const risk = asRisk(raw.risk);

  let verdict: Verdict;
  if (service === "promptshield" && endpoint === "screen") {
    verdict = risk === "high" ? "deny" : risk === "medium" ? "review" : "allow";
  } else if (service === "crawlsafe") {
    const allowed = raw.crawl_allowed === true || raw.crawlAllowed === true;
    verdict = allowed ? "allow" : "deny";
  } else {
    verdict = mapRawDecision(rawDecision);
  }

  const crawlAllowed =
    service === "crawlsafe" ? raw.crawl_allowed === true || raw.crawlAllowed === true : undefined;

  return {
    verdict,
    service,
    endpoint,
    rawDecision,
    risk,
    reasons,
    findings,
    advice,
    sanitized,
    safeText,
    crawlAllowed,
    raw,
  };
}

function mapRawDecision(raw?: string): Verdict {
  if (!raw) return "review";
  if (raw === "allow") return "allow";
  if (raw === "review" || raw === "warn") return "review";
  if (raw === "deny" || raw === "block") return "deny";
  return "review";
}

function collectReasons(raw: Record<string, unknown>, findings: unknown[]): string[] {
  const out: string[] = [];
  if (Array.isArray(raw.reasons)) {
    for (const r of raw.reasons) {
      if (typeof r === "string") out.push(r);
      else if (r && typeof r === "object" && "reason" in r && typeof (r as { reason: unknown }).reason === "string") {
        out.push((r as { reason: string }).reason);
      }
    }
  }
  for (const f of findings) {
    if (f && typeof f === "object") {
      const rec = f as Record<string, unknown>;
      const rule = typeof rec.rule === "string" ? rec.rule : undefined;
      const reason = typeof rec.reason === "string" ? rec.reason : undefined;
      if (rule && reason) out.push(`${rule}: ${reason}`);
      else if (rule) out.push(rule);
      else if (reason) out.push(reason);
    } else if (typeof f === "string") {
      out.push(f);
    }
  }
  return out;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function asRisk(v: unknown): "low" | "medium" | "high" | undefined {
  if (v === "low" || v === "medium" || v === "high") return v;
  return undefined;
}

/**
 * Apply allow/review/deny policy. Deny and (by default) review throw.
 * Timeouts and transport errors should be turned into GuardError first,
 * then passed through enforceError.
 */
export async function enforce(
  decision: NormalizedDecision,
  opts: EnforceOptions = {},
): Promise<NormalizedDecision> {
  if (decision.verdict === "allow") return decision;
  if (decision.verdict === "deny") throw new GuardDenied(decision);

  const mode = await resolveReview(opts.onReview ?? "throw", decision);
  if (mode === "allow") return decision;
  if (mode === "deny") throw new GuardDenied(decision, `GrindFree ${decision.service} review treated as deny`);
  throw new GuardReviewRequired(decision);
}

export function enforceError(err: unknown, service: string, opts: EnforceOptions = {}): never {
  const mode = opts.onError ?? "deny";
  if (err instanceof GuardDenied || err instanceof GuardReviewRequired) throw err;
  const wrapped =
    err instanceof GuardError
      ? err
      : new GuardError(err instanceof Error ? err.message : String(err), { service });
  if (mode === "throw") throw wrapped;
  if (mode === "allow") {
    // Caller asked to proceed on transport failure. Still throw so they can
    // distinguish this path if they catch GuardError; use mode "allow" only
    // via tryGuard helpers that swallow this.
    throw wrapped;
  }
  throw new GuardDenied(
    {
      verdict: "deny",
      service: service as ServiceName,
      endpoint: "error",
      reasons: [wrapped.message],
      findings: [],
      raw: { error: wrapped.message, status: wrapped.status },
    },
    `GrindFree ${service} failed closed: ${wrapped.message}`,
  );
}

async function resolveReview(
  onReview: ReviewMode | ((d: NormalizedDecision) => ReviewMode | Promise<ReviewMode>),
  decision: NormalizedDecision,
): Promise<ReviewMode> {
  if (typeof onReview === "function") return onReview(decision);
  return onReview;
}
