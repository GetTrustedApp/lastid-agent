/**
 * lib/mls-orchestrator.js — the bridge from the agent listener's JS surface
 * to the shared wasm `MlsOrchestrator`. Locks:
 *   - getOrchestrator caches per-ctx (one wasm handle per listener lifecycle,
 *     concurrent callers coalesce onto the same construction promise),
 *   - disposeOrchestrator frees + clears the cache idempotently,
 *   - buildCallbackBundles produces directory/transport/host objects whose
 *     methods accept a single JSON-string arg and return JSON-string responses,
 *   - directory callbacks fan out to fetchPeerKeyPackages + fetchGroupMemberDevices
 *     with the listener's auth bag,
 *   - transport callbacks split the wasm's `commit` envelope into the
 *     IdP-route helpers' welcome/commit/expected-epoch shape,
 *   - host.bearer_credential returns the agent's VC; can_defer_reconcile_error
 *     classifies transient vs logic errors.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCallbackBundles,
  getOrchestrator,
  disposeOrchestrator,
} from '../lib/mls-orchestrator.js';

function makeCtx(overrides = {}) {
  return {
    scope: 'main',
    agentDid: 'did:lastid:agent:zAgent',
    operatorDid: 'did:lastid:zOperator',
    idpUrl: 'https://idp.test',
    vcCompact: 'vc-compact-jwt',
    signingKey: {},
    // 32-byte seed for the disk backend's at-rest wrap key. The fake
    // wasmImpl factories below never invoke the KV callbacks, so no real
    // disk I/O happens — this just satisfies getOrchestrator's slotSeed guard.
    slotSeed: new Uint8Array(32),
    log: () => {},
    ...overrides,
  };
}

// ─── getOrchestrator caching ───────────────────────────────────────────────

test('getOrchestrator constructs once per ctx and caches the handle', async () => {
  const ctx = makeCtx();
  let constructed = 0;
  const wasmImpl = {
    async createMlsOrchestratorWithCallbacks(botDid, myDid, directory, transport, host) {
      constructed += 1;
      // Stash the bundles so the test can assert they were threaded through.
      return {
        botDid,
        myDid,
        directory,
        transport,
        host,
        free() {},
      };
    },
  };
  const a = await getOrchestrator(ctx, { wasmImpl });
  const b = await getOrchestrator(ctx, { wasmImpl });
  assert.equal(constructed, 1, 'wasm createMlsOrchestrator called exactly once');
  assert.strictEqual(a, b, 'second call returns the cached handle');
  assert.equal(a.botDid, ctx.agentDid);
  assert.equal(a.myDid, ctx.agentDid);
  assert.ok(typeof a.directory.peer_active_device_ids === 'function');
  assert.ok(typeof a.transport.register_direct_group === 'function');
  assert.ok(typeof a.host.bearer_credential === 'function');
});

test('getOrchestrator coalesces concurrent callers onto the same construction', async () => {
  const ctx = makeCtx();
  let constructing = 0;
  let constructed = 0;
  const wasmImpl = {
    async createMlsOrchestratorWithCallbacks() {
      constructing += 1;
      // Yield so the second concurrent call observes us mid-construction.
      await new Promise((r) => setImmediate(r));
      constructed += 1;
      return { free() {} };
    },
  };
  const [a, b] = await Promise.all([
    getOrchestrator(ctx, { wasmImpl }),
    getOrchestrator(ctx, { wasmImpl }),
  ]);
  assert.equal(constructing, 1, 'only one in-flight construction');
  assert.equal(constructed, 1);
  assert.strictEqual(a, b);
});

test('getOrchestrator requires agentDid', async () => {
  await assert.rejects(
    () => getOrchestrator(makeCtx({ agentDid: undefined }), { wasmImpl: {} }),
    /agentDid required/,
  );
});

test('getOrchestrator requires a 32-byte slotSeed for the disk backend', async () => {
  // The default disk backend derives the at-rest wrap key from slotSeed; a
  // missing/short seed must fail loudly rather than silently start an
  // unencrypted or wrong-keyed state. (A test injecting deps.makeKvCallbacks
  // is exempt — that's the in-memory seam the other tests use.)
  await assert.rejects(
    () =>
      getOrchestrator(makeCtx({ slotSeed: undefined }), {
        wasmImpl: { async createMlsOrchestratorWithCallbacks() { return { free() {} }; } },
      }),
    /slotSeed/,
  );
});

test('getOrchestrator surfaces a missing wasm factory loudly', async () => {
  await assert.rejects(
    () => getOrchestrator(makeCtx(), { wasmImpl: {} }),
    /createMlsOrchestratorWithCallbacks not available/,
  );
});

test('disposeOrchestrator frees the handle + clears the cache (idempotent)', async () => {
  const ctx = makeCtx();
  let freed = 0;
  const wasmImpl = {
    async createMlsOrchestratorWithCallbacks() {
      return {
        free() {
          freed += 1;
        },
      };
    },
  };
  await getOrchestrator(ctx, { wasmImpl });
  disposeOrchestrator(ctx);
  assert.equal(freed, 1);
  assert.equal(ctx.__mlsOrchestrator, null);
  // Second dispose is a no-op (no throw, no double-free).
  disposeOrchestrator(ctx);
  assert.equal(freed, 1);
});

// ─── buildCallbackBundles: directory ───────────────────────────────────────

test('directory.peer_active_device_ids returns the live device id list', async () => {
  const ctx = makeCtx();
  const { directory } = buildCallbackBundles({
    ctx,
    deps: {
      async fetchPeerKeyPackages({ targetDid, perDevice, agentDid, vcCompact }) {
        assert.equal(targetDid, ctx.operatorDid);
        assert.equal(perDevice, true);
        assert.equal(agentDid, ctx.agentDid);
        assert.equal(vcCompact, ctx.vcCompact);
        return {
          keyPackages: [
            { keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' },
            { keyPackageB64: 'KP-B', ref: 'r2', deviceId: 'devB' },
            { keyPackageB64: 'KP-Z', ref: 'r3', deviceId: null }, // dropped
          ],
        };
      },
    },
  });
  const json = await directory.peer_active_device_ids(
    JSON.stringify({ peer_did: ctx.operatorDid }),
  );
  assert.deepEqual(JSON.parse(json), ['devA', 'devB']);
});

test('directory.fetch_peer_key_packages filters by requested device_ids', async () => {
  const ctx = makeCtx();
  const { directory } = buildCallbackBundles({
    ctx,
    deps: {
      async fetchPeerKeyPackages() {
        return {
          keyPackages: [
            { keyPackageB64: 'KP-A', ref: 'r1', deviceId: 'devA' },
            { keyPackageB64: 'KP-B', ref: 'r2', deviceId: 'devB' },
            { keyPackageB64: 'KP-C', ref: 'r3', deviceId: 'devC' },
          ],
        };
      },
    },
  });
  const json = await directory.fetch_peer_key_packages(
    JSON.stringify({ peer_did: ctx.operatorDid, device_ids: ['devB', 'devC'] }),
  );
  assert.deepEqual(JSON.parse(json), [
    { device_id: 'devB', key_package: 'KP-B' },
    { device_id: 'devC', key_package: 'KP-C' },
  ]);
});

test('directory.own_devices resolves via listOwnDevices and maps active devices to {device_id, device_identity, did}', async () => {
  // Regression for the multi-device gap: previously this returned a single
  // synthetic `{device_id: agentDid}` entry — a shape openmls's reconcile
  // can't actually match against the IdP's real device_ids. Now the callback
  // hits listOwnDevices (GET /v1/trust/:agentDid/devices — the durable
  // resolver), filters active=false, and returns the REAL device ids so the
  // orchestrator can iterate the agent's own device set.
  const ctx = makeCtx();
  const { directory } = buildCallbackBundles({
    ctx,
    deps: {
      async listOwnDevices(a) {
        // Sanity: the helper closes over auth() — verify it threads through.
        assert.equal(a.agentDid, ctx.agentDid);
        return [
          {
            device_id: 'device-listener-1',
            device_identity: 'device-listener-1',
            last_seen: '2026-05-28T15:00:00.000Z',
            active: true,
          },
          {
            device_id: 'device-inactive',
            device_identity: 'device-inactive',
            last_seen: null,
            active: false,
          },
        ];
      },
    },
  });
  const json = await directory.own_devices(null);
  const out = JSON.parse(json);
  assert.equal(out.length, 1);
  assert.equal(out[0].device_id, 'device-listener-1');
  // lastid-mls-core/reconcile.rs:98 filters live devices by `device_identity`
  // — lock the wire so a regression where we drop it goes loud here.
  assert.equal(out[0].device_identity, 'device-listener-1');
  assert.equal(out[0].did, ctx.agentDid);
});

test('directory.fetch_own_key_packages claims one KP per OTHER own device via fetchPeerKeyPackages(agentDid)', async () => {
  // Regression for the same multi-device gap on the agent side: previously
  // returned [] hardcoded, which forced the agent's reconcile to skip its
  // own-device backfill. Locks the wire: helper called with targetDid ===
  // ctx.agentDid + perDevice: true, output filtered by device_ids when
  // present.
  const ctx = makeCtx();
  let calledArgs;
  const { directory } = buildCallbackBundles({
    ctx,
    deps: {
      async fetchPeerKeyPackages(a) {
        calledArgs = a;
        return {
          keyPackages: [
            { keyPackageB64: 'KP-1', ref: 'r1', deviceId: 'device-listener-1' },
            { keyPackageB64: 'KP-2', ref: 'r2', deviceId: 'device-other' },
          ],
          remainingCount: 0,
        };
      },
    },
  });
  const json = await directory.fetch_own_key_packages(
    JSON.stringify({ device_ids: ['device-listener-1'] }),
  );
  assert.equal(calledArgs.targetDid, ctx.agentDid);
  assert.equal(calledArgs.perDevice, true);
  const out = JSON.parse(json);
  assert.deepEqual(out, [{ device_id: 'device-listener-1', key_package: 'KP-1' }]);
});

// ─── buildCallbackBundles: transport ───────────────────────────────────────

test('transport.register_direct_group POSTs the group + returns {idp_group_id}', async () => {
  const ctx = makeCtx();
  let createArgs;
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async createGroupOnIdp(a) {
        createArgs = a;
        return { id: 'idp-uuid-1', mls_group_id: 'mgid' };
      },
    },
  });
  const json = await transport.register_direct_group(
    JSON.stringify({
      peer_did: ctx.operatorDid,
      mls_group_init_b64: 'GINFO',
      bearer: 'ignored',
    }),
  );
  assert.deepEqual(JSON.parse(json), { idp_group_id: 'idp-uuid-1', existing: false });
  assert.equal(createArgs.mlsGroupInitB64, 'GINFO');
  assert.equal(createArgs.groupType, 'direct');
  assert.equal(createArgs.vcCompact, ctx.vcCompact);
  // The peer is sent so the IdP get-or-creates ONE canonical group per pair;
  // a normal create forwards forceNew:false (rotation would send true).
  assert.equal(createArgs.peerDid, ctx.operatorDid);
  assert.equal(createArgs.forceNew, false);
});

test('transport.register_direct_group surfaces existing:true when the IdP reused the canonical pair group', async () => {
  const ctx = makeCtx();
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async createGroupOnIdp() {
        return { id: 'canonical-1', mls_group_id: 'mgid', existing: true };
      },
    },
  });
  const json = await transport.register_direct_group(
    JSON.stringify({
      peer_did: ctx.operatorDid,
      mls_group_init_b64: 'GINFO',
      bearer: 'ignored',
    }),
  );
  assert.deepEqual(JSON.parse(json), { idp_group_id: 'canonical-1', existing: true });
});

test('transport.register_direct_group throws if the IdP returns no id', async () => {
  const ctx = makeCtx();
  const { transport } = buildCallbackBundles({
    ctx,
    deps: { async createGroupOnIdp() { return {}; } },
  });
  await assert.rejects(
    () =>
      transport.register_direct_group(
        JSON.stringify({ peer_did: ctx.operatorDid, mls_group_init_b64: 'X' }),
      ),
    /no group id/,
  );
});

test('transport.submit_member_add splits the commit envelope into welcome/commit', async () => {
  const ctx = makeCtx();
  let addArgs;
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async addGroupMember(a) {
        addArgs = a;
      },
    },
  });
  await transport.submit_member_add(
    JSON.stringify({
      group_id: 'idp-1',
      member_did: ctx.operatorDid,
      commit: { commit_b64: 'C1', welcome_b64: 'W1', new_epoch: 1 },
    }),
  );
  assert.equal(addArgs.groupId, 'idp-1');
  assert.equal(addArgs.inviteeDid, ctx.operatorDid);
  assert.equal(addArgs.mlsWelcomeB64, 'W1');
  assert.equal(addArgs.mlsCommitB64, 'C1');
});

test('transport.submit_member_device_reconcile sets expected_epoch = new_epoch - 1', async () => {
  const ctx = makeCtx();
  let recArgs;
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async reconcileMemberDevicesAdd(a) {
        recArgs = a;
      },
    },
  });
  await transport.submit_member_device_reconcile(
    JSON.stringify({
      group_id: 'idp-1',
      member_did: ctx.operatorDid,
      target_device_ids: ['devB'],
      commit: { commit_b64: 'AC', welcome_b64: 'AW', new_epoch: 3 },
    }),
  );
  assert.equal(recArgs.groupId, 'idp-1');
  assert.deepEqual(recArgs.targetDeviceIds, ['devB']);
  assert.equal(recArgs.mlsCommitB64, 'AC');
  assert.equal(recArgs.mlsWelcomeB64, 'AW');
  assert.equal(recArgs.expectedEpoch, 2);
});

test('transport.submit_member_device_evict passes reason through', async () => {
  const ctx = makeCtx();
  let eArgs;
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async evictMemberDevices(a) {
        eArgs = a;
      },
    },
  });
  await transport.submit_member_device_evict(
    JSON.stringify({
      group_id: 'idp-1',
      member_did: ctx.operatorDid,
      target_device_ids: ['devB'],
      commit: { commit_b64: 'RC', new_epoch: 5 },
      reason: 'operator_requested',
    }),
  );
  assert.equal(eArgs.groupId, 'idp-1');
  assert.deepEqual(eArgs.targetDeviceIds, ['devB']);
  assert.equal(eArgs.mlsCommitB64, 'RC');
  assert.equal(eArgs.expectedEpoch, 4);
  assert.equal(eArgs.reason, 'operator_requested');
});

test('transport.fetch_member_device_resolution returns the IdP ledger view', async () => {
  const ctx = makeCtx();
  const { transport } = buildCallbackBundles({
    ctx,
    deps: {
      async fetchGroupMemberDevices() {
        return { known: true, activeDeviceIds: ['devA'], pendingDeviceIds: ['devZ'] };
      },
    },
  });
  const json = await transport.fetch_member_device_resolution(
    JSON.stringify({ group_id: 'idp-1', member_did: ctx.operatorDid }),
  );
  assert.deepEqual(JSON.parse(json), {
    known: true,
    active_device_ids: ['devA'],
    pending_eviction_device_ids: ['devZ'],
  });
});

test('transport.is_group_valid returns {valid:true} (no agent-side endpoint today)', async () => {
  const ctx = makeCtx();
  const { transport } = buildCallbackBundles({ ctx });
  const json = await transport.is_group_valid(JSON.stringify({ group_id: 'idp-1' }));
  assert.deepEqual(JSON.parse(json), { valid: true });
});

// ─── buildCallbackBundles: host ────────────────────────────────────────────

test('host.bearer_credential returns the listener-supplied VC compact', async () => {
  const ctx = makeCtx({ vcCompact: 'vc-x' });
  const { host } = buildCallbackBundles({ ctx });
  assert.equal(await host.bearer_credential(null), 'vc-x');
});

test('host.can_defer_reconcile_error classifies transient vs logic errors', async () => {
  const ctx = makeCtx();
  const { host } = buildCallbackBundles({ ctx });
  const transient = JSON.parse(
    await host.can_defer_reconcile_error(JSON.stringify({ error_message: 'fetch failed: ECONNRESET' })),
  );
  assert.equal(transient.can_defer, true);
  const idp5xx = JSON.parse(
    await host.can_defer_reconcile_error(JSON.stringify({ error_message: 'POST failed: HTTP 503 oops' })),
  );
  assert.equal(idp5xx.can_defer, true);
  const logic = JSON.parse(
    await host.can_defer_reconcile_error(JSON.stringify({ error_message: 'invalid commit signature' })),
  );
  assert.equal(logic.can_defer, false);
});

test('host emit_* + schedule_reconcile_retry just log (no throw, no return)', async () => {
  const lines = [];
  const ctx = makeCtx({ log: (l) => lines.push(l) });
  const { host } = buildCallbackBundles({ ctx });
  await host.emit_setup_event(JSON.stringify({ kind: 'started' }));
  await host.emit_reconcile_event(JSON.stringify({ kind: 'changed', group_id: 'g1' }));
  await host.schedule_reconcile_retry(JSON.stringify({ group_id: 'g1', reason: 'idp_busy' }));
  assert.equal(lines.length, 3);
  assert.match(lines[0], /orchestrator setup/);
  assert.match(lines[1], /orchestrator reconcile/);
  assert.match(lines[2], /deferred reconcile retry/);
});
