import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGuard, SERVICES } from "../src/index.js";
import { GuardDenied, GuardReviewRequired } from "../src/errors.js";
import { mockPaidFetch } from "./helpers.js";

const ID = "ah_0123456789abcdef0123456789abcdef";
const ticket = { id: ID, status: "pending", expires_at: "2026-11-12T04:00:00Z", approval_url: "https://askhuman.grindfree.net/r/x", poll_url: "p", wait_url: "w", poll_token: "pt", notify: { channel: "link", delivered: false }, action_sha256: "h" };
const input = { action: { title: "Refund #1234", args: { amount: 82.1 }, risk: "medium" as const }, notify: { link_only: true as const } };

function seqFetch(statuses: Array<Record<string, unknown>>, calls: Array<{ url: string; body: unknown }>) {
  let i = 0;
  const base = mockPaidFetch([{ urlIncludes: "askhuman.grindfree.net/v1/request", body: ticket }], calls);
  return (async (u: any, init?: any) => {
    const url = String(u);
    if (url.includes("/status/")) { calls.push({ url, body: undefined }); const b = statuses[Math.min(i++, statuses.length - 1)]; return new Response(JSON.stringify(b), { status: 200 }); }
    return base(u, init);
  }) as typeof fetch;
}

describe("AskHuman", () => {
  it("service registered at $0.03", () => {
    assert.equal(SERVICES.askhuman.endpoints.request.priceUsdc, "0.03");
  });
  it("askHuman posts the request and returns the ticket", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const g = createGuard({ fetch: seqFetch([], calls) });
    const t = await g.askHuman(input);
    assert.equal(t.id, ID);
    assert.equal(calls[0].url, "https://askhuman.grindfree.net/v1/request");
    assert.deepEqual((calls[0].body as any).notify, { link_only: true });
  });
  it("waitForHuman long-polls until decided", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const g = createGuard({ fetch: seqFetch([{ id: ID, status: "pending" }, { id: ID, status: "edited", decision: "edit", edited_args: { amount: 40 } }], calls) });
    const d = await g.waitForHuman({ id: ID, poll_token: "pt" });
    assert.equal(d.status, "edited"); assert.equal(d.approved, true); assert.deepEqual(d.edited_args, { amount: 40 });
    assert.match(calls[0].url, /\/status\/ah_0123456789abcdef0123456789abcdef\?token=pt&wait=25$/);
    assert.equal(calls.length, 2);
  });
  it("requireHumanApproval throws GuardDenied on deny and on expiry", async () => {
    for (const st of [{ status: "denied", decision: "deny", note: "no" }, { status: "expired", decision: "deny" }]) {
      const g = createGuard({ fetch: seqFetch([{ id: ID, ...st }], []) });
      await assert.rejects(g.requireHumanApproval(input), GuardDenied);
    }
  });
  it("withHumanApproval runs fn only when approved and forwards a guard review", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const g = createGuard({ fetch: seqFetch([{ id: ID, status: "approved", decision: "approve" }], calls) });
    const review = new GuardReviewRequired({ verdict: "review", service: "toolguard", endpoint: "evaluate", rawDecision: "review", reasons: ["unknown host"], findings: [], raw: {} });
    let ran = 0;
    const r = await g.withHumanApproval(input, () => ++ran, review);
    assert.equal(ran, 1); assert.equal(r.human.status, "approved");
    assert.deepEqual((calls[0].body as any).guard_decision, { service: "toolguard", verdict: "review", reasons: ["unknown host"] });
    const g2 = createGuard({ fetch: seqFetch([{ id: ID, status: "denied", decision: "deny" }], []) });
    await assert.rejects(g2.withHumanApproval(input, () => ++ran), GuardDenied);
    assert.equal(ran, 1);
  });
});
