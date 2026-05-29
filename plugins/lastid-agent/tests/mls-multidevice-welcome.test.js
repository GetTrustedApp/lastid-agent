/**
 * B1 end-to-end regression: multi-device MLS welcome + decrypt across the REAL
 * vendored wasm, AND a guard for the exact instance-split bug B1 fixes.
 *
 * The bug (mem_01KSNXSY4TY7DK7EJTREPNY5RH): the agent ran SEPARATE openmls
 * instances over the same sealed state — keypackage publish minted a KP into
 * instance B, while the orchestrator (instance A) processed the operator's
 * welcome. openmls can only consume a KeyPackage whose PRIVATE parts live in
 * the SAME client that generated it; the welcome therefore failed with
 * NoMatchingKeyPackage and the operator's device never joined → no messages.
 *
 * These tests run two parties (A = group creator, B = joiner) on the real
 * wasm and assert:
 *   POSITIVE — when B uses ONE instance for BOTH generateKeyPackage AND
 *     processWelcome, the welcome succeeds and B decrypts A's message.
 *   NEGATIVE — when B's KeyPackage is generated on a DIFFERENT instance than
 *     the one processing the welcome (the pre-B1 bug), processWelcome FAILS.
 *     This is the regression that locks the convergence: it must stay broken
 *     the "wrong" way so a future split-instance regression trips here.
 *
 * Uses the orchestrator handle's low-level MLS methods directly with in-memory
 * KV (no IdP callbacks needed — the directory/transport bundles throw if
 * touched, proving this path is pure local crypto). Per-instance handle = one
 * openmls client; that's the unit the bug is about.
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

function throwingBundles(label) {
  const boom = (name) => async () => {
    throw new Error(`multidevice test (${label}): unexpected IdP callback ${name}`);
  };
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
      fetch_member_device_resolution: boom('fetch_member_device_resolution'),
      is_group_valid: boom('is_group_valid'),
    },
    host: {
      bearer_credential: async () => 'test-bearer',
      emit_setup_event: () => {},
      emit_reconcile_event: () => {},
      schedule_reconcile_retry: async () => {},
      can_defer_reconcile_error: async () => JSON.stringify({ can_defer: false }),
    },
  };
}

function memoryKv() {
  let blob = null;
  return {
    loadBlob: async () => blob,
    flushBlob: async (b64) => {
      blob = b64;
    },
  };
}

async function makeHandle(did, label) {
  const { directory, transport, host } = throwingBundles(label);
  return await wasm.createMlsOrchestratorWithCallbacks(
    did,
    did,
    directory,
    transport,
    host,
    memoryKv(),
  );
}

async function drainAndFree(h) {
  try {
    await h.flushPending();
  } catch {
    /* nothing pending */
  }
  try {
    h.free();
  } catch {
    /* already freed */
  }
}

function groupId(seed) {
  const b = Buffer.alloc(32, seed & 0xff);
  b[0] = seed & 0xff;
  b[1] = (seed >> 8) & 0xff;
  return b.toString('base64');
}

function b64(text) {
  return Buffer.from(text, 'utf-8').toString('base64');
}

const DID_A = 'did:lastid:agent:zMultiDevA';
const DID_B = 'did:lastid:zMultiDevB';

test('multi-device: ONE instance generates the KP and processes the welcome → joins + decrypts', async () => {
  const a = await makeHandle(DID_A, 'A');
  const b = await makeHandle(DID_B, 'B');
  try {
    // B (the joining device) mints a KeyPackage on the SAME instance that will
    // process the welcome — this is the B1-converged shape.
    const kpB = await b.generateKeyPackage();
    assert.ok(typeof kpB === 'string' && kpB.length > 0, 'B produced a KeyPackage');

    // A creates the group and adds B via B's KP → yields a welcome for B.
    const gid = groupId(1);
    await a.createGroup(gid);
    const addRaw = await a.addMember(gid, kpB);
    const add = JSON.parse(addRaw);
    assert.ok(add.mls_welcome ?? add.welcome_b64, 'addMember produced a welcome');
    const welcome = add.mls_welcome ?? add.welcome_b64;

    // B processes the welcome. Pre-B1, with B's KP minted on a DIFFERENT
    // instance, this threw NoMatchingKeyPackage. One instance → it joins.
    const joinedRaw = await b.processWelcome(welcome);
    const joined = JSON.parse(joinedRaw);
    assert.ok(joined.group_id_b64, 'B joined the group via the welcome');

    // A encrypts an application message; B decrypts it. Proves the channel is
    // live end-to-end across the two devices.
    const ctB64 = await a.encryptApplicationMessage(gid, b64('hello from A'));
    const inboundRaw = await b.processInbound(ctB64);
    const inbound = JSON.parse(inboundRaw);
    assert.equal(inbound.kind, 'application', 'B got an application message');
    const plaintext = Buffer.from(inbound.plaintext_b64, 'base64').toString('utf-8');
    assert.equal(plaintext, 'hello from A', 'B decrypted A’s message');
  } finally {
    await drainAndFree(a);
    await drainAndFree(b);
  }
});

test('multi-device REGRESSION: a KP from a DIFFERENT instance fails the welcome (the pre-B1 bug)', async () => {
  const a = await makeHandle(DID_A, 'A');
  const bGen = await makeHandle(DID_B, 'B-gen'); // mints the KP (the old publish instance)
  const bJoin = await makeHandle(DID_B, 'B-join'); // processes the welcome (the old orchestrator)
  try {
    // B's KP is minted on bGen — a SEPARATE openmls client from bJoin. This is
    // exactly the split B1 eliminated (publish opened its own MlsClient while
    // the orchestrator processed welcomes).
    const kpB = await bGen.generateKeyPackage();

    const gid = groupId(2);
    await a.createGroup(gid);
    const add = JSON.parse(await a.addMember(gid, kpB));
    const welcome = add.mls_welcome ?? add.welcome_b64;

    // bJoin never minted kpB, so it has no matching private parts → the welcome
    // must FAIL. If this ever starts SUCCEEDING, the instance-isolation
    // assumption changed and this test should be revisited — but as long as
    // openmls binds KP privates to the generating client, the split is broken,
    // which is WHY B1 converges to one instance.
    await assert.rejects(
      () => bJoin.processWelcome(welcome),
      (err) => {
        const msg = err == null ? '' : (typeof err === 'string' ? err : err.message || String(err));
        // openmls surfaces this as NoMatchingKeyPackage (or a wrapped variant);
        // any rejection proves the split-instance welcome doesn't silently join.
        assert.ok(msg.length > 0, 'split-instance welcome rejected with a message');
        return true;
      },
    );
  } finally {
    await drainAndFree(a);
    await drainAndFree(bGen);
    await drainAndFree(bJoin);
  }
});
