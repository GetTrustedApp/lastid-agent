/**
 * Vault-use policy (lib/vault-policy.js). Locks the allow / deny / approval
 * decision: per-use approval forces approval, each constraint gates correctly,
 * a failed constraint honors on_violation, and unknown constraints FAIL CLOSED
 * (never silently bypassed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { evalShareForUse, OUTCOME } from "../lib/vault-policy.js";

const share = (over = {}) => ({
  constraints: [],
  on_violation: "deny",
  require_approval_per_use: false,
  ...over,
});

test("no constraints, no per-use approval → allow", () => {
  assert.equal(evalShareForUse({ content: share() }).outcome, OUTCOME.ALLOW);
});

test("require_approval_per_use → approval", () => {
  const r = evalShareForUse({ content: share({ require_approval_per_use: true }) });
  assert.equal(r.outcome, OUTCOME.APPROVAL);
  assert.equal(r.reason_kind, "approval_per_use");
});

test("one_time_use constraint → approval (every use)", () => {
  const r = evalShareForUse({ content: share({ constraints: [{ kind: "one_time_use" }] }) });
  assert.equal(r.outcome, OUTCOME.APPROVAL);
  assert.equal(r.reason_kind, "one_time_use");
});

test("time_window: inside allows, outside denies (on_violation=deny)", () => {
  const c = share({ constraints: [{ kind: "time_window", start_ms: 100, end_ms: 200 }] });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: 150 } }).outcome, OUTCOME.ALLOW);
  const out = evalShareForUse({ content: c, ctx: { now_ms: 999 } });
  assert.equal(out.outcome, OUTCOME.DENY);
  assert.equal(out.reason_kind, "outside_time_window");
});

test("a failed constraint with on_violation=request_approval → approval (not deny)", () => {
  const c = share({
    constraints: [{ kind: "time_window", start_ms: 100, end_ms: 200 }],
    on_violation: "request_approval",
  });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: 999 } }).outcome, OUTCOME.APPROVAL);
});

test("rate_per_minute: under cap allows, at/over denies", () => {
  const c = share({ constraints: [{ kind: "rate_per_minute", max_uses: 3 }] });
  assert.equal(evalShareForUse({ content: c, ctx: { uses_last_minute: 2 } }).outcome, OUTCOME.ALLOW);
  assert.equal(evalShareForUse({ content: c, ctx: { uses_last_minute: 3 } }).outcome, OUTCOME.DENY);
});

test("scope_required: matching scope allows, mismatch denies", () => {
  const c = share({ constraints: [{ kind: "scope_required", name: "project", value: "embedforge" }] });
  assert.equal(evalShareForUse({ content: c, ctx: { scope: { project: "embedforge" } } }).outcome, OUTCOME.ALLOW);
  assert.equal(evalShareForUse({ content: c, ctx: { scope: { project: "other" } } }).outcome, OUTCOME.DENY);
  assert.equal(evalShareForUse({ content: c, ctx: {} }).outcome, OUTCOME.DENY);
})

test("unknown / malformed constraint FAILS CLOSED", () => {
  assert.equal(evalShareForUse({ content: share({ constraints: [{ kind: "teleport" }] }) }).outcome, OUTCOME.DENY)
  assert.equal(evalShareForUse({ content: share({ constraints: [{}] }) }).outcome, OUTCOME.DENY)
})

test("missing share content → deny", () => {
  assert.equal(evalShareForUse({ content: null }).outcome, OUTCOME.DENY)
})
