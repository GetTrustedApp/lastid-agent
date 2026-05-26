/**
 * Vault-use policy evaluation — ported from the policy plane
 * (lastid-sdk/docs/design/policy-plane.md, lastid-core policy.rs). PURE: given
 * a decoded share's constraints + a use context, decide allow / deny /
 * approval. No I/O. The listener calls this at vault_use time, BEFORE minting a
 * handle; `approval` routes to the operator's phone (the existing approval
 * loop), `deny` is terminal.
 *
 * Constraint kinds:
 *   time_window     { start_ms, end_ms }  use only within the window
 *   rate_per_minute { max_uses }          cap uses/min (ctx.uses_last_minute)
 *   scope_required  { name, value }        bind to a project/scope value
 *   one_time_use                           every use needs a fresh approval
 *
 * `require_approval_per_use` forces approval regardless of constraints.
 * A FAILED constraint yields `deny` or `approval` per the share's
 * `on_violation`.
 */

export const OUTCOME = Object.freeze({ ALLOW: "allow", DENY: "deny", APPROVAL: "approval" });

/**
 * @param {object} a
 * @param {object} a.content  decoded share bundle (constraints, on_violation,
 *                            require_approval_per_use)
 * @param {object} [a.ctx]    { now_ms, scope?: Record<string,string>,
 *                            uses_last_minute?: number }
 * @returns {{ outcome: 'allow'|'deny'|'approval', reason_kind?: string,
 *            reason_detail?: string, constraint_kind?: string }}
 */
export function evalShareForUse({ content, ctx = {} }) {
  if (!content || typeof content !== "object") {
    return { outcome: OUTCOME.DENY, reason_kind: "no_share", reason_detail: "share content missing" };
  }
  const onViolation = content.on_violation === "request_approval" ? OUTCOME.APPROVAL : OUTCOME.DENY;
  const nowMs = typeof ctx.now_ms === "number" ? ctx.now_ms : Date.now();
  const constraints = Array.isArray(content.constraints) ? content.constraints : [];

  // A one_time_use constraint always needs a fresh approval — surface it first
  // so the reason is specific.
  if (constraints.some((c) => c?.kind === "one_time_use")) {
    return { outcome: OUTCOME.APPROVAL, reason_kind: "one_time_use", constraint_kind: "one_time_use" };
  }

  for (const c of constraints) {
    const v = violation(c, { nowMs, ctx });
    if (v) {
      return {
        outcome: onViolation,
        reason_kind: v.reason_kind,
        reason_detail: v.reason_detail,
        constraint_kind: c.kind,
      };
    }
  }

  // Constraints all passed → approval only if the share demands it per-use.
  if (content.require_approval_per_use === true) {
    return { outcome: OUTCOME.APPROVAL, reason_kind: "approval_per_use" };
  }
  return { outcome: OUTCOME.ALLOW };
}

/** Returns a violation {reason_kind, reason_detail} or null if the constraint
 *  is satisfied. Unknown constraint kinds fail CLOSED (treated as a violation)
 *  — a share carrying a constraint the agent doesn't understand must not be
 *  silently bypassed. */
function violation(c, { nowMs, ctx }) {
  if (!c || typeof c.kind !== "string") {
    return { reason_kind: "bad_constraint", reason_detail: "malformed constraint" };
  }
  switch (c.kind) {
    case "time_window": {
      const start = Number(c.start_ms);
      const end = Number(c.end_ms);
      if (Number.isFinite(start) && Number.isFinite(end) && nowMs >= start && nowMs <= end) return null;
      return { reason_kind: "outside_time_window", reason_detail: "use is outside the allowed time window" };
    }
    case "rate_per_minute": {
      const max = Number(c.max_uses);
      const used = Number(ctx.uses_last_minute ?? 0);
      if (Number.isFinite(max) && used < max) return null;
      return { reason_kind: "rate_limited", reason_detail: `over ${c.max_uses}/min` };
    }
    case "scope_required": {
      const got = ctx.scope?.[c.name];
      if (typeof got === "string" && got === c.value) return null;
      return { reason_kind: "scope_mismatch", reason_detail: `requires ${c.name}=${c.value}` };
    }
    default:
      return { reason_kind: "unknown_constraint", reason_detail: `unknown constraint '${c.kind}'` };
  }
}
