/**
 * Vault-use policy (lib/vault-policy.js). Locks the allow / deny / approval
 * decision against the CANONICAL lastid-core Constraint shape (serde
 * `type`-tagged) — the same bytes signed into the VaultShareAcl. Per-use
 * approval forces approval, each constraint gates correctly, a failed
 * constraint honors on_violation, expiry is terminal, and unknown
 * constraints FAIL CLOSED (never silently bypassed).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { evalShareForUse, OUTCOME, recurringScheduleSatisfied } from "../lib/vault-policy.js";

const share = (over = {}) => ({
  constraints: [],
  on_violation: { type: "deny" },
  require_approval_per_use: false,
  ...over,
});

// 2026-01-05 is a Monday; 2026-01-03 a Saturday.
const MON_NOON = Date.parse("2026-01-05T12:00:00Z");
const SAT_NOON = Date.parse("2026-01-03T12:00:00Z");

test("no constraints, no per-use approval → allow", () => {
  assert.equal(evalShareForUse({ content: share() }).outcome, OUTCOME.ALLOW);
});

test("require_approval_per_use → approval (before constraints)", () => {
  const r = evalShareForUse({ content: share({ require_approval_per_use: true }) });
  assert.equal(r.outcome, OUTCOME.APPROVAL);
  assert.equal(r.reason_kind, "one_time_use_required");
});

test("expired share → terminal deny", () => {
  const c = share({ expires_at_ms: 1000 });
  const out = evalShareForUse({ content: c, ctx: { now_ms: 2000 } });
  assert.equal(out.outcome, OUTCOME.DENY);
  assert.equal(out.reason_kind, "share_expired");
});

test("time_window (rfc3339): inside allows, outside denies", () => {
  const c = share({
    constraints: [{ type: "time_window", not_before: "2026-01-01T00:00:00Z", not_after: "2026-01-02T00:00:00Z" }],
  });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: Date.parse("2026-01-01T12:00:00Z") } }).outcome, OUTCOME.ALLOW);
  const out = evalShareForUse({ content: c, ctx: { now_ms: Date.parse("2026-02-01T00:00:00Z") } });
  assert.equal(out.outcome, OUTCOME.DENY);
  assert.equal(out.reason_kind, "outside_time_window");
});

test("failed constraint with on_violation=request_approval → approval (not deny)", () => {
  const c = share({
    constraints: [{ type: "time_window", not_before: "2026-01-01T00:00:00Z", not_after: "2026-01-02T00:00:00Z" }],
    on_violation: { type: "request_approval", approval_request_ttl_secs: 60, handle_ttl_secs: 30 },
  });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: Date.parse("2026-03-01T00:00:00Z") } }).outcome, OUTCOME.APPROVAL);
});

test("rate_per_minute: under cap allows, at/over denies", () => {
  const c = share({ constraints: [{ type: "rate_per_minute", max: 3 }] });
  assert.equal(evalShareForUse({ content: c, ctx: { uses_last_minute: 2 } }).outcome, OUTCOME.ALLOW);
  assert.equal(evalShareForUse({ content: c, ctx: { uses_last_minute: 3 } }).outcome, OUTCOME.DENY);
});

test("amount_cap: under cap allows, over denies, missing amount is malformed", () => {
  const c = share({ constraints: [{ type: "amount_cap", max: 100, unit: "usd" }] });
  assert.equal(evalShareForUse({ content: c, ctx: { declared_amount: 50, declared_amount_unit: "usd" } }).outcome, OUTCOME.ALLOW);
  assert.equal(evalShareForUse({ content: c, ctx: { declared_amount: 150, declared_amount_unit: "usd" } }).outcome, OUTCOME.DENY);
  // Different unit → cap not applicable → allow.
  assert.equal(evalShareForUse({ content: c, ctx: { declared_amount: 150, declared_amount_unit: "eur" } }).outcome, OUTCOME.ALLOW);
  // Missing declared amount → fails (malformed → deny under on_violation=deny).
  assert.equal(evalShareForUse({ content: c, ctx: {} }).outcome, OUTCOME.DENY);
});

test("scope_required: matching scope allows, mismatch/absent denies", () => {
  const c = share({ constraints: [{ type: "scope_required", name: "project", value: "embedforge" }] });
  assert.equal(evalShareForUse({ content: c, ctx: { scope: { project: "embedforge" } } }).outcome, OUTCOME.ALLOW);
  assert.equal(evalShareForUse({ content: c, ctx: { scope: { project: "other" } } }).outcome, OUTCOME.DENY);
  assert.equal(evalShareForUse({ content: c, ctx: {} }).outcome, OUTCOME.DENY);
});

// recurring_schedule — M-F 9-5 GMT.
const MF_9_5_GMT = { type: "recurring_schedule", days: [0, 1, 2, 3, 4], start_minute: 540, end_minute: 1020, utc_offset_minutes: 0 };

test("recurring_schedule: Monday midday allows, after-hours + weekend deny", () => {
  const c = share({ constraints: [MF_9_5_GMT] });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: MON_NOON } }).outcome, OUTCOME.ALLOW);
  const afterHours = evalShareForUse({ content: c, ctx: { now_ms: Date.parse("2026-01-05T18:00:00Z") } });
  assert.equal(afterHours.outcome, OUTCOME.DENY);
  assert.equal(afterHours.reason_kind, "outside_schedule");
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: SAT_NOON } }).outcome, OUTCOME.DENY);
});

test("recurring_schedule: fixed UTC offset shifts the local frame (matches Rust)", () => {
  // 2026-01-05 01:00Z, offset -120 → local 2026-01-04 23:00 = Sunday → deny.
  const c = share({ constraints: [{ ...MF_9_5_GMT, utc_offset_minutes: -120 }] });
  assert.equal(evalShareForUse({ content: c, ctx: { now_ms: Date.parse("2026-01-05T01:00:00Z") } }).outcome, OUTCOME.DENY);
  // 2026-01-05 08:00Z, offset +120 → local 10:00 Monday → allow.
  const c2 = share({ constraints: [{ ...MF_9_5_GMT, utc_offset_minutes: 120 }] });
  assert.equal(evalShareForUse({ content: c2, ctx: { now_ms: Date.parse("2026-01-05T08:00:00Z") } }).outcome, OUTCOME.ALLOW);
});

test("recurringScheduleSatisfied: overnight wrap + empty days fail-closed", () => {
  const overnight = { type: "recurring_schedule", days: [0, 1, 2, 3, 4, 5, 6], start_minute: 1320, end_minute: 360, utc_offset_minutes: 0 };
  assert.equal(recurringScheduleSatisfied(overnight, Date.parse("2026-01-05T23:00:00Z")), true);
  assert.equal(recurringScheduleSatisfied(overnight, Date.parse("2026-01-05T02:00:00Z")), true);
  assert.equal(recurringScheduleSatisfied(overnight, MON_NOON), false);
  // Empty days → never satisfied.
  assert.equal(recurringScheduleSatisfied({ days: [], start_minute: 0, end_minute: 1440, utc_offset_minutes: 0 }, MON_NOON), false);
});

test("unknown / malformed constraint FAILS CLOSED", () => {
  assert.equal(evalShareForUse({ content: share({ constraints: [{ type: "teleport" }] }) }).outcome, OUTCOME.DENY);
  assert.equal(evalShareForUse({ content: share({ constraints: [{}] }) }).outcome, OUTCOME.DENY);
});

test("missing share content → deny", () => {
  assert.equal(evalShareForUse({ content: null }).outcome, OUTCOME.DENY);
});
