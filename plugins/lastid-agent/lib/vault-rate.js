/**
 * Vault-use rate tracker — a per-item sliding window of recent mint timestamps,
 * so the listener can feed `uses_last_minute` into the policy evaluator and a
 * `rate_per_minute` constraint actually enforces.
 *
 * The constraint was already evaluated (vault-policy.js: rate_per_minute reads
 * ctx.uses_last_minute), but nothing populated the count — it defaulted to 0, so
 * the limit never tripped. The handle store can't supply it: it holds only LIVE
 * handles (deleted on consume/expire), so a consumed use vanishes. This keeps an
 * independent in-memory window of MINT times per item.
 *
 * In-memory + listener-lifetime: the listener daemon is the single point that
 * sees every vault_use, so its process memory is the right home. A daemon
 * restart resets the window (acceptable for a 60s rate gate). The window is
 * pruned lazily on each count, so it never grows without bound.
 */
export class VaultRateTracker {
  #byItem = new Map(); // itemId -> number[] (mint timestamps ms, ascending)

  /** Count mints for `itemId` within the last `windowMs`, pruning older ones. */
  count(itemId, windowMs, now = Date.now()) {
    const arr = this.#byItem.get(itemId);
    if (!arr || arr.length === 0) return 0;
    const cutoff = now - windowMs;
    let drop = 0;
    while (drop < arr.length && arr[drop] <= cutoff) drop += 1;
    if (drop > 0) arr.splice(0, drop);
    if (arr.length === 0) this.#byItem.delete(itemId);
    return arr.length;
  }

  /** Record a successful mint for `itemId` at `now`. */
  record(itemId, now = Date.now()) {
    const arr = this.#byItem.get(itemId);
    if (arr) arr.push(now);
    else this.#byItem.set(itemId, [now]);
  }
}

/** Process-wide default the listener uses (the daemon is one process). */
export const defaultRateTracker = new VaultRateTracker();
