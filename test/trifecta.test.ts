import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createGuard, SERVICES, newSessionId } from "../src/index.js";
import { GuardDenied, GuardReviewRequired, GuardError } from "../src/errors.js";
import { mockPaidFetch } from "./helpers.js";

const block = { verdict: "block", decision: "block", rule: "LETHAL_TRIFECTA", reasons: ["private data + untrusted content + external http_request"] };
const allow = { verdict: "allow", decision: "allow", rule: "NO_TRIFECTA", reasons: ["ok"] };
const review = { verdict: "review", decision: "review", rule: "TRIFECTA_ALLOWLISTED_DESTINATION", reasons: ["confirm"], askhuman: { suggested_request: {} } };

describe("TrifectaGate", () => {
  it("service registered at $0.002 and ids are unguessable", () => {
    assert.equal(SERVICES.trifectagate.endpoints.check.priceUsdc, "0.002");
    const id = newSessionId(); assert.match(id, /^sess_[0-9a-f]{32}$/); assert.notEqual(id, newSessionId());
  });
  it("session batches queued events into the next check", async () => {
    const calls: Array<{ url: string; body: any }> = [];
    const g = createGuard({ fetch: mockPaidFetch([{ urlIncludes: "trifectagate.grindfree.net/v1/check", body: allow }], calls) });
    const s = g.session({ policy: { allow_hosts: ["api.co"] } });
    s.privateData("gmail.read").untrusted("web.fetch", "https://x.example", "block");
    const d = await s.check({ type: "http_request", destination: "https://api.co/x" });
    assert.equal(d.verdict, "allow");
    assert.equal(calls[0].url, "https://trifectagate.grindfree.net/v1/check");
    assert.equal(calls[0].body.session_id, s.sessionId);
    assert.equal(calls[0].body.events.length, 2);
    assert.deepEqual(calls[0].body.policy, { allow_hosts: ["api.co"] });
    await s.check({ type: "dns", destination: "x.example" });
    assert.equal(calls[1].body.events, undefined, "events sent once");
  });
  it("gate blocks on block and reviews on review; fn not run", async () => {
    let ran = 0;
    const g = createGuard({ fetch: mockPaidFetch([{ urlIncludes: "trifectagate", body: block }]) });
    await assert.rejects(g.session().gate({ type: "email", destination: "a@b.example" }, () => ++ran), GuardDenied);
    const g2 = createGuard({ fetch: mockPaidFetch([{ urlIncludes: "trifectagate", body: review }]) });
    await assert.rejects(g2.gateEgress({ action: { type: "http_request", destination: "https://api.co" } }, () => ++ran), GuardReviewRequired);
    const g3 = createGuard({ fetch: mockPaidFetch([{ urlIncludes: "trifectagate", body: allow }]) });
    const r = await g3.gateEgress({ action: { type: "http_request", destination: "https://ok.example" } }, () => ++ran);
    assert.equal(r.value, 1); assert.equal(ran, 1);
  });
  it("transport failure fails closed and re-queues events", async () => {
    const calls: Array<{ url: string; body: any }> = [];
    let fail = true;
    const base = mockPaidFetch([{ urlIncludes: "trifectagate", body: allow }], calls);
    const f = (async (u: any, i?: any) => { if (fail) { fail = false; return new Response("{}", { status: 500 }); } return base(u, i); }) as typeof fetch;
    const s = createGuard({ fetch: f }).session();
    s.privateData("db.query");
    await assert.rejects(s.check({ type: "webhook", destination: "https://h.example" }), (e: any) => e instanceof GuardDenied || e instanceof GuardError);
    await s.check({ type: "webhook", destination: "https://h.example" });
    assert.equal(calls.at(-1)!.body.events.length, 1, "events re-sent after failure");
  });
});
