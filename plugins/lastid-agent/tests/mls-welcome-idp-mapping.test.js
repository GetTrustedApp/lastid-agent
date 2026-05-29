/**
 * Regression: processWelcome must seed the idp→openmls id mapping so a later
 * reconcile/group_handle can resolve the joined group BY ITS IDP UUID.
 *
 * THE BUG THIS LOCKS (operator's multi-device welcome failure, 2026-05-28):
 * a direct group is created by one party (console/another device) and the
 * joining client receives the welcome. The welcome bytes carry only the
 * openmls-internal group id; the IdP group UUID rides the WS frame. If the
 * join doesn't record the (idp_uuid → openmls_id) mapping, a later
 * reconcileMemberDevices(idp_uuid) → group_handle(idp_uuid) finds no mapping,
 * falls back to treating the UUID as the openmls id, and base64-decoding the
 * UUID panics `InvalidByte(8, 45)` (the '-' at index 8) — so reconcile crashes
 * before it can add the operator's other devices, and they never get welcomed.
 *
 * FIX: processWelcome takes the IdP UUID and seeds the mapping at join (the
 * wasm twin of native MLSGroup::update_idp_group_id). This test drives the
 * REAL vendored wasm:
 *   POSITIVE — A creates a group + welcomes B; B.processWelcome(welcome, idpUuid)
 *     then a reconcile-style group_handle lookup by idpUuid RESOLVES (groupEpoch
 *     by the IdP uuid succeeds) instead of crashing InvalidByte.
 *   NEGATIVE — without the idp id (old behavior), looking the group up by the
 *     UUID throws the base64 InvalidByte — proving the mapping is what fixes it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const wasm = require('../vendor/lastid-mls-wasm/lastid_mls_wasm.js');

try {
  wasm.init();
} catch {
  /* idempotent */
}

const boom = (n) => async () => {
  throw new Error(`unexpected IdP callback ${n}`);
};
function bundles() {
  return {
    directory: {
      peer_active_device_ids: boom('peer_active_device_ids'),
      own_devices: boom('own_devices'),
      peer_device_records: boom('peer_device_records'),
      fetch_peer_key_packages: boom('fetch_peer_key_packages'),
      fetch_own_key_packages: boom('fetch_own_key_packages'),
      fetch_peer_key_packages_per_device: boom('fetch_peer_key_packages_per_device'),
    },
    transport: {
      register_direct_group: boom('register_direct_group'),
      submit_member_add: boom('submit_member_add'),
      submit_member_device_reconcile: boom('submit_member_device_reconcile'),
      submit_member_device_evict: boom('submit_member_device_evict'),
      // reconcile_once calls this per member AFTER group_handle resolves. Return
      // known:false so the loop `continue`s (no add/evict) → reconcile returns
      // { changed:false } cleanly. We only need to prove group_handle resolved
      // the UUID (it ran this far), not exercise a real device diff here.
      fetch_member_device_resolution: async () =>
        JSON.stringify({ known: false, active_device_ids: [], pending_eviction_device_ids: [] }),
      is_group_valid: boom('is_group_valid'),
    },
    host: {
      bearer_credential: async () => 'x',
      emit_setup_event: () => {},
      emit_reconcile_event: () => {},
      schedule_reconcile_retry: async () => {},
      can_defer_reconcile_error: async () => JSON.stringify({ can_defer: false }),
    },
  };
}
function memKv() {
  let b = null;
  return { loadBlob: async () => b, flushBlob: async (x) => { b = x; } };
}
async function handle(did) {
  const { directory, transport, host } = bundles();
  return wasm.createMlsOrchestratorWithCallbacks(did, did, directory, transport, host, memKv());
}
async function drainFree(h) {
  try { await h.flushPending(); } catch {}
  try { h.free(); } catch {}
}
function gid(seed) {
  const b = Buffer.alloc(32, seed & 0xff);
  b[0] = seed & 0xff; b[1] = (seed >> 8) & 0xff;
  return b.toString('base64');
}
function looksLikeBase64InvalidByte(err) {
  const m = err == null ? '' : typeof err === 'string' ? err : err.message || String(err);
  return /InvalidByte|base64/i.test(m);
}

// A realistic IdP group UUID (hyphens → '-' at index 8 is the InvalidByte(8,45) trigger).
const IDP_UUID = '35d34b43-99a5-40e6-95ee-d2b54f118a0e';

test('processWelcome(welcome, idpUuid) seeds the mapping so group_handle resolves by IdP UUID', async () => {
  const a = await handle('did:lastid:zWelcomeA');
  const b = await handle('did:lastid:zWelcomeB');
  try {
    // B publishes a KP; A creates a group and adds B → welcome for B.
    const kpB = await b.generateKeyPackage();
    const g = gid(1);
    await a.createGroup(g);
    const add = JSON.parse(await a.addMember(g, kpB));
    const welcome = add.mls_welcome ?? add.welcome_b64;

    // B joins, PASSING the IdP UUID — this is the fix.
    const joined = JSON.parse(await b.processWelcome(welcome, IDP_UUID));
    assert.ok(joined.group_id_b64, 'B joined the group');

    // The REAL reconcile path: reconcileMemberDevices(idpUuid) → core
    // reconcile_once → group_handle(idpUuid) + member_leaves() as its FIRST
    // step. With the mapping seeded, group_handle resolves the UUID to the
    // real openmls id and member_leaves() succeeds; the only member is B's own
    // leaf (no peer in the group), so the loop's IdP callbacks never fire and
    // reconcile returns { changed:false } cleanly. Pre-fix, group_handle(uuid)
    // treated the UUID as the openmls id and member_leaves base64-decoded it →
    // InvalidByte(8,45) before any of that. So a clean return PROVES the
    // mapping resolved.
    // reconcileMemberDevices resolves to a plain JS object { changed }, not a
    // JSON string (the orchestrator builds it via Reflect.set).
    const res = await b.reconcileMemberDevices(IDP_UUID);
    assert.equal(res.changed, false, 'reconcile resolved the group by IdP UUID and ran to completion');
  } finally {
    await drainFree(a);
    await drainFree(b);
  }
});

test('NEGATIVE: without the idp id, looking the group up by the UUID throws base64 InvalidByte', async () => {
  const a = await handle('did:lastid:zWelcomeA2');
  const b = await handle('did:lastid:zWelcomeB2');
  try {
    const kpB = await b.generateKeyPackage();
    const g = gid(2);
    await a.createGroup(g);
    const add = JSON.parse(await a.addMember(g, kpB));
    const welcome = add.mls_welcome ?? add.welcome_b64;

    // Join WITHOUT the idp id (old behavior — no mapping seeded).
    await b.processWelcome(welcome, null);

    // reconcileMemberDevices(uuid) → group_handle(uuid) with no mapping →
    // treats the UUID as the openmls id → member_leaves base64-decodes it →
    // InvalidByte(8,45). This IS the crash the fix prevents; proving the
    // seeded mapping is what makes the positive case work.
    await assert.rejects(
      () => b.reconcileMemberDevices(IDP_UUID),
      (err) => {
        assert.ok(
          looksLikeBase64InvalidByte(err),
          `expected a base64 InvalidByte (the unmapped-UUID crash); got: ${err}`,
        );
        return true;
      },
    );
  } finally {
    await drainFree(a);
    await drainFree(b);
  }
});
