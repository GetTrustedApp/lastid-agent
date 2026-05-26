/**
 * Vault-use policy evaluation — a faithful JS mirror of the canonical Rust
 * evaluator (lastid-core::types::policy::evaluate_share_policy / check_constraint).
 * PURE: given a signed share's constraints + a use context, decide allow /
 * deny / approval. No I/O. The listener calls this at vault_use time, BEFORE
 * minting a handle; `approval` routes to the operator's phone, `deny` is
 * terminal.
 *
 * Wire shape is the CANONICAL lastid-core `Constraint` (serde `type`-tagged),
 * NOT a JS twin — the same bytes the operator's device key signs into the
 * VaultShareAcl, so the agent evaluates exactly what was signed:
 *   { type: "time_window", not_before: <rfc3339>, not_after: <rfc3339> }
 *   { type: "rate_per_minute", max: <n> }
 *   { type: "amount_cap", max: <n>, unit: <str> }
 *   { type: "scope_required", name: <str>, value: <str> }
 *   { type: "recurring_schedule", days: [0..6 (0=Mon)], start_minute,
 *     end_minute, utc_offset_minutes }   // M-F 9-5 GMT, etc.
 *
 * `on_violation` is the canonical ViolationPolicy object
 * ({ type: "deny" } | { type: "request_approval", ... }). A failed constraint
 * yields `deny` or `approval` per it. `require_approval_per_use` forces
 * approval regardless of constraints. Composition order matches Rust:
 *   expired → deny ; else per-use approval → approval ; else constraints ;
 *   else allow.
 */

export const OUTCOME = Object.freeze({ ALLOW: "allow", DENY: "deny", APPROVAL: "approval" });

/**
 * @param {object} a
 * @param {object} a.content  signed share (constraints, on_violation,
 *                            require_approval_per_use, expires_at_ms?)
 * @param {object} [a.ctx]    { now_ms, scope?: Record<string,string>,
 *                            uses_last_minute?: number, declared_amount?: number,
 *                            declared_amount_unit?: string }
 * @returns {{ outcome: 'allow'|'deny'|'approval', reason_kind?: string,
 *            reason_detail?: string, constraint_kind?: string }}
 */
export function evalShareForUse({ content, ctx = {} }) {
  if (!content || typeof content !== "object") {
    return { outcome: OUTCOME.DENY, reason_kind: "no_share", reason_detail: "share content missing" };
  }
  const onViolation = violationOutcome(content.on_violation);
  const nowMs = typeof ctx.now_ms === "number" ? ctx.now_ms : Date.now();
  const constraints = Array.isArray(content.constraints) ? content.constraints : [];

  // 1) Share expiry — a present, passed expiry is a hard terminal deny.
  if (typeof content.expires_at_ms === "number" && nowMs > content.expires_at_ms) {
    return {
      outcome: OUTCOME.DENY,
      reason_kind: "share_expired",
      reason_detail: `share expired at ${content.expires_at_ms}ms (now ${nowMs}ms)`,
    };
  }

  // 2) Per-use approval always escalates, before evaluating constraints —
  //    matches Rust's OneTimeUseRequired short-circuit so the "why pending"
  //    reason is accurate.
  if (content.require_approval_per_use === true) {
    return { outcome: OUTCOME.APPROVAL, reason_kind: "one_time_use_required" };
  }

  // 3) Constraints in declared order; first failure short-circuits.
  for (const c of constraints) {
    const v = violation(c, { nowMs, ctx });
    if (v) {
      return {
        outcome: onViolation,
        reason_kind: v.reason_kind,
        reason_detail: v.reason_detail,
        constraint_kind: typeof c?.type === "string" ? c.type : undefined,
      };
    }
  }

  return { outcome: OUTCOME.ALLOW };
}

/** Map the canonical ViolationPolicy ({type:"deny"|"request_approval"}) to an
 *  outcome. Anything other than an explicit request_approval is a deny
 *  (fail closed). */
function violationOutcome(onViolation) {
  if (onViolation && typeof onViolation === "object" && onViolation.type === "request_approval") {
    return OUTCOME.APPROVAL;
  }
  return OUTCOME.DENY;
}

/** Returns a violation {reason_kind, reason_detail} or null if the constraint
 *  is satisfied. Unknown constraint types fail CLOSED (treated as a violation)
 *  — a share carrying a constraint the agent doesn't understand must not be
 *  silently bypassed. */
function violation(c, { nowMs, ctx }) {
  if (!c || typeof c.type !== "string") {
    return { reason_kind: "bad_constraint", reason_detail: "malformed constraint" };
  }
  switch (c.type) {
    case "time_window": {
      const start = Date.parse(c.not_before);
      const end = Date.parse(c.not_after);
      if (Number.isFinite(start) && Number.isFinite(end) && nowMs >= start && nowMs <= end) return null;
      return { reason_kind: "outside_time_window", reason_detail: "use is outside the allowed time window" };
    }
    case "rate_per_minute": {
      const max = Number(c.max);
      const used = Number(ctx.uses_last_minute ?? 0);
      if (Number.isFinite(max) && used < max) return null;
      return { reason_kind: "rate_limited", reason_detail: `over ${c.max}/min` };
    }
    case "amount_cap": {
      const max = Number(c.max);
      const amount = ctx.declared_amount;
      const unit = ctx.declared_amount_unit;
      if (typeof amount !== "number") {
        return { reason_kind: "malformed_request", reason_detail: `amount_cap requires declared_amount (unit=${c.unit})` };
      }
      // Different unit than this cap cares about → not applicable.
      if (unit !== c.unit) return null;
      if (amount <= max) return null;
      return { reason_kind: "amount_exceeded", reason_detail: `amount ${amount} ${c.unit} exceeds cap ${c.max} ${c.unit}` };
    }
    case "scope_required": {
      const got = ctx.scope?.[c.name];
      if (typeof got === "string" && got === c.value) return null;
      return { reason_kind: "scope_mismatch", reason_detail: `requires ${c.name}=${c.value}` };
    }
    case "recurring_schedule": {
      if (recurringScheduleSatisfied(c, nowMs)) return null;
      return { reason_kind: "outside_schedule", reason_detail: "use is outside the allowed weekly schedule" };
    }
    default:
      return { reason_kind: "unknown_constraint", reason_detail: `unknown constraint '${c.type}'` };
  }
}

/** Mirror of the Rust RecurringSchedule check: shift `nowMs` into the fixed
 *  UTC offset, read the local weekday (0=Mon..6=Sun) + minute-of-day, and
 *  require day ∈ days AND minute in [start,end) (with overnight wrap when
 *  start > end). Empty `days` fails closed. */
export function recurringScheduleSatisfied(c, nowMs) {
  const days = Array.isArray(c.days) ? c.days : [];
  const start = Number(c.start_minute);
  const end = Number(c.end_minute);
  const offset = Number(c.utc_offset_minutes);
  if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isFinite(offset)) return false;

  const localMs = nowMs + offset * 60_000;
  const d = new Date(localMs);
  // getUTCDay is 0=Sun..6=Sat; convert to 0=Mon..6=Sun to match Rust's
  // num_days_from_monday (we already shifted by the offset, so the UTC
  // accessors read the operator's local wall clock).
  const weekday = (d.getUTCDay() + 6) % 7;
  const minuteOfDay = d.getUTCHours() * 60 + d.getUTCMinutes();

  const dayOk = days.includes(weekday);
  const timeOk = start <= end
    ? minuteOfDay >= start && minuteOfDay < end
    : minuteOfDay >= start || minuteOfDay < end; // wraps past midnight
  return dayOk && timeOk;
}
