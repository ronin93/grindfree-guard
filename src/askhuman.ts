/** AskHuman: human-in-the-loop approval ($0.03 per request; status polling is free). */
import type { PaidFetch } from "./client.js";
import { postJson } from "./client.js";
import type { NormalizedDecision } from "./decisions.js";
import { GuardDenied, GuardError, GuardReviewRequired } from "./errors.js";
import { SERVICES, serviceUrl } from "./services.js";

export type AskHumanAction = {
  title: string;
  summary?: string;
  details?: string;
  tool?: string;
  args?: unknown;
  risk?: "low" | "medium" | "high" | "critical";
  context_url?: string;
};
export type AskHumanNotify =
  | { ntfy_topic: string }
  | { webhook_url: string }
  | { slack_webhook_url: string }
  | { discord_webhook_url: string }
  | { link_only: true };
export type AskHumanInput = {
  action: AskHumanAction;
  notify: AskHumanNotify;
  timeout_seconds?: number;
  on_timeout?: "deny" | "expire";
  allow_edit?: boolean;
  callback_url?: string;
  guard_decision?: { service?: string; verdict?: string; reasons?: string[] };
};
export type AskHumanTicket = {
  id: string;
  status: "pending";
  expires_at: string;
  approval_url: string;
  poll_url: string;
  wait_url: string;
  poll_token: string;
  callback_secret?: string;
  notify: { channel: string; delivered: boolean };
  action_sha256: string;
};
export type AskHumanStatus = "pending" | "approved" | "denied" | "edited" | "expired";
export type AskHumanDecision = {
  id: string;
  status: AskHumanStatus;
  decision: "approve" | "deny" | "edit" | null;
  note: string | null;
  edited_args: unknown;
  decided_at: string | null;
  expires_at: string;
  /** true only for approved / edited. */
  approved: boolean;
  raw: Record<string, unknown>;
};
export type WaitOptions = { maxWaitMs?: number; pollSeconds?: number };

const ORIGIN = SERVICES.askhuman.origin;

export async function askHuman(paidFetch: PaidFetch, input: AskHumanInput, timeoutMs?: number): Promise<AskHumanTicket> {
  const raw = await postJson(paidFetch, serviceUrl("askhuman", "request"), input, { service: "askhuman", timeoutMs });
  return raw as unknown as AskHumanTicket;
}

export async function getHumanDecision(
  fetchImpl: PaidFetch,
  ticket: Pick<AskHumanTicket, "id" | "poll_token">,
  waitSeconds = 0,
): Promise<AskHumanDecision> {
  const url = `${ORIGIN}/status/${encodeURIComponent(ticket.id)}?token=${encodeURIComponent(ticket.poll_token)}${waitSeconds ? `&wait=${Math.min(25, Math.max(1, Math.floor(waitSeconds)))}` : ""}`;
  const res = await fetchImpl(url, { headers: { accept: "application/json" } });
  const raw = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new GuardError(`askhuman status HTTP ${res.status}`, { service: "askhuman", status: res.status, body: raw });
  const status = raw.status as AskHumanStatus;
  return {
    id: String(raw.id ?? ticket.id),
    status,
    decision: (raw.decision as AskHumanDecision["decision"]) ?? null,
    note: (raw.note as string) ?? null,
    edited_args: raw.edited_args ?? null,
    decided_at: (raw.decided_at as string) ?? null,
    expires_at: String(raw.expires_at ?? ""),
    approved: status === "approved" || status === "edited",
    raw,
  };
}

/** Long-poll until the human decides or the request expires (fails closed). */
export async function waitForHuman(
  fetchImpl: PaidFetch,
  ticket: Pick<AskHumanTicket, "id" | "poll_token">,
  opts: WaitOptions = {},
): Promise<AskHumanDecision> {
  const deadline = Date.now() + (opts.maxWaitMs ?? 24 * 3600 * 1000 + 60_000);
  const poll = opts.pollSeconds ?? 25;
  for (;;) {
    const d = await getHumanDecision(fetchImpl, ticket, poll);
    if (d.status !== "pending") return d;
    if (Date.now() >= deadline) return d;
  }
}

export function humanDecisionAsGuard(d: AskHumanDecision): NormalizedDecision {
  return {
    verdict: d.approved ? "allow" : d.status === "pending" ? "review" : "deny",
    service: "askhuman",
    endpoint: "request",
    rawDecision: d.decision ?? d.status,
    reasons: [d.approved ? `human ${d.status}` : `human ${d.status}${d.note ? `: ${d.note}` : ""}`],
    findings: [],
    raw: d.raw,
  };
}

/** Throw GuardDenied unless the human approved (or approved with edits). */
export function enforceHuman(d: AskHumanDecision): AskHumanDecision {
  if (d.approved) return d;
  throw new GuardDenied(humanDecisionAsGuard(d), `AskHuman: request ${d.status}${d.note ? ` (${d.note})` : ""}`);
}

/** Build an AskHuman guard_decision from a GuardReviewRequired error. */
export function guardDecisionFrom(err: GuardReviewRequired): AskHumanInput["guard_decision"] {
  return { service: err.decision.service, verdict: err.decision.rawDecision ?? err.decision.verdict, reasons: err.decision.reasons.slice(0, 10) };
}
