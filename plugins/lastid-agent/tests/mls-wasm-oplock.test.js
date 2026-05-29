/**
 * B1 regression: the wasm `MlsOrchestrator` op-lock.
 *
 * This is the test that LOCKS the convergence fix. Unlike
 * mls-orchestrator.test.js (which injects a FAKE wasmImpl to test the JS
 * callback wiring), this loads the REAL vendored wasm — the same
 * `--target nodejs` artifact the listener runs in prod — and exercises the
 * actual Rust op-lock through `createMlsOrchestratorWithCallbacks`.
 *
 * What it guards:
 *   1. POSITIVE (burst): firing many state-mutating ops CONCURRENTLY on ONE
 *      orchestrator handle does NOT throw "recursive use of an object detected
 *      which would lead to unsafe aliasing in rust". Before the op-lock
 *      (7a99396) + the one-instance convergence, two wasm-bindgen calls that
 *      hold a &mut self borrow across an await interleaved and the borrow
 *      tracker panicked — the exact prod crash this whole effort fixes.
 *   2. NEGATIVE (no lock poison): a deliberately-failing op rejects, and a
 *      subsequent VALID op still resolves — proving the op-lock guard is
 *      released on the error path and doesn't wedge the orchestrator.
 *
 * Run: node --test plugins/lastid-agent/tests/mls-wasm-oplock.test.js
 *      (or `npm test`)
 *
 * NOTE: this drives the orchestrator's LOCAL crypto methods
 * (generateKeyPackage / createGroup / groupEpoch / processInbound), which never
 * call out to the IdP — so the directory/transport bundles are stubs that
 * THROW if touched (a network call here would be a bug). The KV `callbacks`
 * bundle is in-memory so nothing hits disk.
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

const AGENT_DID = 'did:lastid:zOpLockTestAgent';

/**
 * Stub callback bundles. Local crypto ops must not touch the IdP — if any of
 * these fire, that's a regression (an op reaching for the network when it
 * shouldn't), so they reject loudly rather than returning a benign value.
 */
function throwingBundles() {
  const boom = (name) => async () => {
    throw new Error(`op-lock test: unexpected IdP callback ${name}`);
  };
  const directory = {
    peer_active_device_ids: boom('peer_active_device_ids'),
    own_devices: boom('own_devices'),
    peer_device_records: boom('peer_device_records'),
    fetch_peer_key_packages: boom('fetch_peer_key_packages'),
    fetch_own_key_packages: boom('fetch_own_key_packages'),
    fetch_peer_key_packages_per_device: boom('fetch_peer_key_packages_per_device'),
  };
  const transport = {
    register_direct_group: boom('register_direct_group'),
    submit_member_add: boom('submit_member_add'),
    submit_member_device_reconcile: boom('submit_member_device_reconcile'),
    submit_member_device_evict: boom('submit_member_device_evict'),
    fetch_member_device_resolution: boom('fetch_member_device_resolution'),
    is_group_valid: boom('is_group_valid'),
  };
  const host = {
    bearer_credential: async () => 'test-bearer',
    emit_setup_event: () => {},
    emit_reconcile_event: () => {},
    schedule_reconcile_retry: async () => {},
    can_defer_reconcile_error: async () => JSON.stringify({ can_defer: false }),
  };
  return { directory, transport, host };
}

/** In-memory KV bundle — keeps the test off disk (and off IndexedDB).
 *  flushBlob must NEVER reject: a flush that rejects after the handle is freed
 *  becomes an unhandled rejection that dirties process exit under the parallel
 *  test runner. */
function memoryKvCallbacks() {
  let blob = null;
  return {
    loadBlob: async () => blob,
    flushBlob: async (b64) => {
      try {
        blob = b64;
      } catch {
        /* never reject a flush */
      }
    },
  };
}

/** Drain any pending wasm flush, THEN free — so teardown never races an
 *  in-flight flushBlob (which, freed mid-flight under heavy parallelism, would
 *  reject and dirty the process exit code). */
async function drainAndFree(orch) {
  try {
    await orch.flushPending();
  } catch {
    /* nothing pending / already settled */
  }
  try {
    orch.free();
  } catch {
    /* already freed */
  }
}

async function makeOrchestrator() {
  const { directory, transport, host } = throwingBundles();
  return await wasm.createMlsOrchestratorWithCallbacks(
    AGENT_DID,
    AGENT_DID,
    directory,
    transport,
    host,
    memoryKvCallbacks(),
  );
}

/** Recognize the borrow-tracker panic in any of its thrown shapes. */
function isRecursiveUsePanic(err) {
  const msg =
    err == null
      ? ''
      : typeof err === 'string'
        ? err
        : err.message || String(err);
  return /recursive use of an object|unsafe aliasing/i.test(msg);
}

// A valid openmls group id is 32 bytes base64. The exact bytes don't matter
// for the local create/epoch path — only that it's well-formed + distinct.
function freshGroupIdB64(seed) {
  const b = Buffer.alloc(32, seed & 0xff);
  b[0] = seed & 0xff;
  b[1] = (seed >> 8) & 0xff;
  return b.toString('base64');
}

test('op-lock: concurrent burst on one handle does not trip the borrow tracker', async () => {
  const orch = await makeOrchestrator();
  try {
    // Fire a burst of LOCAL ops concurrently. Pre-fix, two of these
    // overlapping across their internal flush await threw "recursive use of an
    // object". The op-lock must serialize them so all settle cleanly. We don't
    // require every op to SUCCEED — we require that NONE throws the
    // borrow-tracker panic.
    const ops = [];
    for (let i = 0; i < 6; i += 1) {
      ops.push(orch.generateKeyPackage());
      ops.push(orch.createGroup(freshGroupIdB64(i)));
    }
    const results = await Promise.allSettled(ops);
    const panics = results.filter(
      (r) => r.status === 'rejected' && isRecursiveUsePanic(r.reason),
    );
    assert.equal(
      panics.length,
      0,
      `expected no borrow-tracker panic; got ${panics.length}: ` +
        panics.map((p) => String(p.reason)).join(' | '),
    );
    // At least the keypackage generations must have actually succeeded — proves
    // the burst did real work, not "no panic because nothing ran".
    const kpOk = results.filter((r, idx) => idx % 2 === 0 && r.status === 'fulfilled');
    assert.ok(kpOk.length >= 1, 'expected at least one generateKeyPackage to succeed under burst');
  } finally {
    await drainAndFree(orch);
  }
});

test('op-lock: a failed op does not poison the lock for the next op', async () => {
  const orch = await makeOrchestrator();
  try {
    // Deliberately-invalid input: processInbound on garbage must reject (bad
    // MLS bytes), NOT panic, and crucially must RELEASE the op-lock.
    await assert.rejects(
      () => orch.processInbound('!!!not-valid-base64-or-mls!!!'),
      (err) => {
        assert.ok(!isRecursiveUsePanic(err), 'failed op should reject, not borrow-panic');
        return true;
      },
    );

    // The lock must be free now: a valid local op still resolves. If the guard
    // leaked on the error path, this would hang (test timeout) or panic.
    const kp = await orch.generateKeyPackage();
    assert.equal(typeof kp, 'string');
    assert.ok(kp.length > 0, 'generateKeyPackage after a failed op should still work');
  } finally {
    await drainAndFree(orch);
  }
});

test('op-lock: sequential create + groupEpoch round-trips through the single handle', async () => {
  const orch = await makeOrchestrator();
  try {
    const gid = freshGroupIdB64(200);
    await orch.createGroup(gid);
    // groupEpoch is ASYNC on the orchestrator (op-lock-serialized), unlike the
    // persistent client's sync bigint accessor. A freshly-created group is at
    // epoch 0.
    const epoch = await orch.groupEpoch(gid);
    assert.equal(Number(epoch), 0, 'a freshly created group is at epoch 0');
  } finally {
    await drainAndFree(orch);
  }
});
