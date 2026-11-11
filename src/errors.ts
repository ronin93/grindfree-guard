import type { NormalizedDecision } from "./decisions.js";

export class GuardConfigError extends Error {
  readonly code = "GUARD_CONFIG";
  constructor(message: string) {
    super(message);
    this.name = "GuardConfigError";
  }
}

export class GuardError extends Error {
  readonly code = "GUARD_ERROR";
  readonly status?: number;
  readonly service: string;
  readonly body?: unknown;
  constructor(message: string, opts: { service: string; status?: number; body?: unknown } ) {
    super(message);
    this.name = "GuardError";
    this.service = opts.service;
    this.status = opts.status;
    this.body = opts.body;
  }
}

export class GuardDenied extends Error {
  readonly code = "GUARD_DENIED";
  readonly verdict = "deny" as const;
  readonly service: string;
  readonly decision: NormalizedDecision;
  constructor(decision: NormalizedDecision, message?: string) {
    super(message ?? defaultMessage(decision, "denied"));
    this.name = "GuardDenied";
    this.service = decision.service;
    this.decision = decision;
  }
}

export class GuardReviewRequired extends Error {
  readonly code = "GUARD_REVIEW";
  readonly verdict = "review" as const;
  readonly service: string;
  readonly decision: NormalizedDecision;
  constructor(decision: NormalizedDecision, message?: string) {
    super(message ?? defaultMessage(decision, "needs review"));
    this.name = "GuardReviewRequired";
    this.service = decision.service;
    this.decision = decision;
  }
}

function defaultMessage(d: NormalizedDecision, kind: string): string {
  const reason = d.reasons[0] ?? d.advice ?? d.rawDecision ?? d.risk ?? kind;
  return `GrindFree ${d.service} ${kind}: ${reason}`;
}
