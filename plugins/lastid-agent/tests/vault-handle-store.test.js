/**
 * Vault handle store (lib/vault-handle-store.js). Locks the single-use,
 * agent-bound, time-limited handle contract — the gate that lets the agent
 * trigger one credentialed call without ever holding the secret.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { VaultHandleStore } from "../lib/vault-handle-store.js";

function fixedStore(startMs = 1_000) {
  let now = startMs;
  let n = 0;
  const store = new VaultHandleStore({ now: () => now, genToken: () => `tok-${++n}` });
  return { store, advance: (ms) => (now += ms), set: (ms) => (now = ms) };
}

test("mint → lookup returns the handle for the SAME agent", () => {
  const { store } = fixedStore();
  const h = store.mint({ agentDid: "did:agent:zA", itemId: "vault_1" });
  assert.equal(h.token, "tok-1");
  const got = store.lookup(h.token, { agentDid: "did:agent:zA" });
  assert.equal(got.itemId, "vault_1");
});

test("a DIFFERENT agent cannot consume the handle", () => {
  const { store } = fixedStore();
  const h = store.mint({ agentDid: "did:agent:zA", itemId: "v" });
  assert.equal(store.lookup(h.token, { agentDid: "did:agent:zEVE" }), null);
});

test("expired handles return null and are swept", () => {
  const { store, advance } = fixedStore();
  const h = store.mint({ agentDid: "did:agent:zA", itemId: "v", ttlMs: 1000 });
  advance(1001);
  assert.equal(store.lookup(h.token, { agentDid: "did:agent:zA" }), null);
  assert.equal(store.size, 0, "expired entry swept on miss");
});

test("single-use: revoke after consume; a second lookup misses", () => {
  const { store } = fixedStore();
  const h = store.mint({ agentDid: "did:agent:zA", itemId: "v" });
  assert.ok(store.lookup(h.token, { agentDid: "did:agent:zA" }));
  assert.equal(store.revoke(h.token), true);
  assert.equal(store.lookup(h.token, { agentDid: "did:agent:zA" }), null);
  assert.equal(store.revoke(h.token), false, "revoke is idempotent");
});

test("carries approval provenance for timing/audit", () => {
  const { store } = fixedStore();
  const h = store.mint({ agentDid: "did:agent:zA", itemId: "v", shareId: "share::x", wasApproved: true, approvalId: "ap_1" });
  assert.equal(h.wasApproved, true);
  assert.equal(h.approvalId, "ap_1");
  assert.equal(h.shareId, "share::x");
  assert.equal(h.expiresAtMs - h.mintedAtMs, 5 * 60 * 1000);
});

test("sweepExpired drops only the expired", () => {
  const { store, advance } = fixedStore();
  store.mint({ agentDid: "a", itemId: "short", ttlMs: 500 });
  store.mint({ agentDid: "a", itemId: "long", ttlMs: 10_000 });
  advance(600);
  assert.equal(store.sweepExpired(), 1);
  assert.equal(store.size, 1);
});
