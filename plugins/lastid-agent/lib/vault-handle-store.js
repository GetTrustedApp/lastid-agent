/**
 * Vault handle store — ported from the desktop's vault_handle_store.dart.
 *
 * A handle is an opaque, single-use, short-lived (5 min) token the agent
 * receives from `vault_use` and presents to `http_fetch`. It is BOUND to
 * (agent_did, item_id) at mint and carries NO secret. Lives in memory only, in
 * the LISTENER process (the single trusted env that also unfurls the secret) —
 * never persisted, dropped on listener exit. `http_fetch` revokes it on
 * consume (success or failure), so a handle injects exactly once.
 *
 * In-memory + injectable clock/token-gen so the mint→lookup→revoke + expiry +
 * agent-binding rules are unit-tested without timers or randomness.
 */
import { randomBytes } from "node:crypto";

export const DEFAULT_TTL_MS = 5 * 60 * 1000; // 300s, matches the desktop

export class VaultHandleStore {
  #handles = new Map(); // token -> handle
  #now;
  #genToken;

  constructor({ now = () => Date.now(), genToken = defaultGenToken } = {}) {
    this.#now = now;
    this.#genToken = genToken;
  }

  /**
   * Mint a handle bound to (agentDid, itemId). Returns the full handle; the
   * caller returns ONLY { vault_handle: token, expires_at_ms, item_id,
   * injection } to the agent.
   */
  mint({ agentDid, itemId, ttlMs = DEFAULT_TTL_MS, shareId = null, wasApproved = false, approvalId = null }) {
    if (!agentDid || !itemId) throw new Error("mint needs agentDid + itemId");
    const mintedAtMs = this.#now();
    const token = this.#genToken();
    const handle = {
      token,
      agentDid,
      itemId,
      shareId,
      wasApproved,
      approvalId,
      mintedAtMs,
      expiresAtMs: mintedAtMs + ttlMs,
      ttlMs,
    };
    this.#handles.set(token, handle);
    return handle;
  }

  /**
   * Look up a handle for consumption. Returns the handle only if it exists, is
   * not expired, AND was minted for THIS agent (an agent can't consume another
   * agent's handle). Returns null otherwise. Expired entries are swept on miss.
   */
  lookup(token, { agentDid } = {}) {
    const h = this.#handles.get(token);
    if (!h) return null;
    if (this.#now() >= h.expiresAtMs) {
      this.#handles.delete(token);
      return null;
    }
    if (agentDid && h.agentDid !== agentDid) return null;
    return h;
  }

  /** Revoke a handle (single-use enforcement). Idempotent. */
  revoke(token) {
    return this.#handles.delete(token);
  }

  /** Drop all expired handles (optional periodic sweep). Returns count removed. */
  sweepExpired() {
    const now = this.#now();
    let removed = 0;
    for (const [token, h] of this.#handles) {
      if (now >= h.expiresAtMs) {
        this.#handles.delete(token);
        removed += 1;
      }
    }
    return removed;
  }

  get size() {
    return this.#handles.size;
  }
}

function defaultGenToken() {
  return randomBytes(32).toString("base64url");
}
