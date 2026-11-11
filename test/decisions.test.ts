import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { enforce, normalizeDecision } from "../src/decisions.js";
import { GuardDenied, GuardReviewRequired } from "../src/errors.js";

describe("normalizeDecision", () => {
  it("maps ToolGuard allow/review/deny", () => {
    assert.equal(normalizeDecision("toolguard", "evaluate", { decision: "allow" }).verdict, "allow");
    assert.equal(normalizeDecision("toolguard", "evaluate", { decision: "review" }).verdict, "review");
    assert.equal(normalizeDecision("toolguard", "evaluate", { decision: "deny", reasons: ["TOOL_DENIED"] }).verdict, "deny");
  });

  it("maps CommandGuard warn→review and block→deny", () => {
    assert.equal(normalizeDecision("commandguard", "command", { decision: "allow" }).verdict, "allow");
    assert.equal(normalizeDecision("commandguard", "command", { decision: "warn" }).verdict, "review");
    const blocked = normalizeDecision("commandguard", "command", {
      decision: "block",
      findings: [{ rule: "RECURSIVE_DELETE_USER_DATA", reason: "wipes ~/Library" }],
    });
    assert.equal(blocked.verdict, "deny");
    assert.equal(blocked.reasons[0], "RECURSIVE_DELETE_USER_DATA: wipes ~/Library");
  });

  it("maps PromptShield risk and Memory/Wire/Doc decisions", () => {
    assert.equal(normalizeDecision("promptshield", "screen", { risk: "low" }).verdict, "allow");
    assert.equal(normalizeDecision("promptshield", "screen", { risk: "medium" }).verdict, "review");
    assert.equal(normalizeDecision("promptshield", "screen", { risk: "high", sanitized: "Hi" }).verdict, "deny");
    assert.equal(normalizeDecision("memoryguard", "screen", { decision: "block" }).verdict, "deny");
    assert.equal(normalizeDecision("wireshield", "scan", { decision: "review" }).verdict, "review");
    assert.equal(normalizeDecision("docshield", "scan", { decision: "allow", safe_text: "visible" }).safeText, "visible");
  });

  it("maps CrawlSafe crawl_allowed", () => {
    assert.equal(normalizeDecision("crawlsafe", "check", { crawl_allowed: true }).verdict, "allow");
    assert.equal(normalizeDecision("crawlsafe", "check", { crawl_allowed: false }).verdict, "deny");
  });

  it("treats a missing decision as review", () => {
    assert.equal(normalizeDecision("toolguard", "evaluate", {}).verdict, "review");
  });
});

describe("enforce", () => {
  const allow = normalizeDecision("toolguard", "evaluate", { decision: "allow" });
  const review = normalizeDecision("toolguard", "evaluate", { decision: "review", reasons: ["POLICY_MISSING"] });
  const deny = normalizeDecision("toolguard", "evaluate", { decision: "deny", reasons: ["TOOL_DENIED"] });

  it("returns allow and throws on deny", async () => {
    assert.equal((await enforce(allow)).verdict, "allow");
    await assert.rejects(() => enforce(deny), (e: unknown) => e instanceof GuardDenied && e.decision.verdict === "deny");
  });

  it("throws GuardReviewRequired by default, and honors onReview", async () => {
    await assert.rejects(() => enforce(review), (e: unknown) => e instanceof GuardReviewRequired);
    assert.equal((await enforce(review, { onReview: "allow" })).verdict, "review");
    await assert.rejects(() => enforce(review, { onReview: "deny" }), GuardDenied);
  });

  it("supports an async onReview callback", async () => {
    const d = await enforce(review, { onReview: async () => "allow" });
    assert.equal(d.verdict, "review");
  });
});
