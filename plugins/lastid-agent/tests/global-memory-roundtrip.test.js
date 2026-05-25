/**
 * Shared-key GLOBAL memories — reissue-proof bedrock (Option-B reuse).
 *
 * Global/bedrock operator memories ride the project Option-B rails: ONE shared
 * record (wire target 'project') under a key derived from project_root_seed,
 * keyed by a RESERVED global routing id (GLOBAL_SHARED_PROJECT_KEY) instead of a
 * repo. Any agent with the seal'd project_root_seed — including a freshly
 * reissued one — reads it from its own store with NO reseal and NO re-provision.
 *
 * This proves the agent side end to end:
 *   - the browser-shaped global-shared record decodes to target 'global' (so it
 *     injects ALWAYS — bedrock/topical via the operator-store), NOT repo-gated;
 *   - it verifies (operator ES256 over the WIRE record, target 'project');
 *   - applied to the operator-store, it surfaces as bedrock;
 *   - a REAL repo routing is NOT retargeted — stays a repo-gated project memory.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  deriveProjectRoutingId,
  encryptProjectContent,
  GLOBAL_SHARED_PROJECT_KEY,
} from '../lib/project-crypto.js';
import { decodeRecord } from '../lib/agent-state-sync.js';
import { verifyRecordSignature } from '../lib/agent-sig-verify.js';
import { OperatorStore } from '../lib/operator-store.js';

const SEED = crypto.createHash('sha256').update('operator-project-root-seed').digest(); // 32B
const sha256Hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

const K = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const opJwk = (() => {
  const j = K.publicKey.export({ format: 'jwk' });
  return { x_b64u: j.x, y_b64u: j.y };
})();
function mintEs256(claims) {
  const h = Buffer.from(JSON.stringify({ typ: 'jwt+lastid-human-auth-v1', alg: 'ES256' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`, 'utf8'), { key: K.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${sig.toString('base64url')}`;
}

/** Build a shared record the way the browser console publishes a memory at the
 *  given routing (global sentinel or a repo). Content carries NO project_key
 *  for global (it's not repo-scoped). */
function sharedRecord(id, routingId, content) {
  const contentBytes = Buffer.from(JSON.stringify(content), 'utf8');
  const enc_b64 = encryptProjectContent(SEED, routingId, contentBytes).toString('base64');
  const claims = {
    kind: 'memory', id, target: 'project', version: 1, status: 'active',
    content_sha256: sha256Hex(contentBytes),
  };
  return {
    id, kind: 'memory', target: 'project', status: 'active', version: 1,
    routing_id: routingId, enc_b64, sig: mintEs256(claims), author: 'operator',
  };
}

const GLOBAL_ROUTING = deriveProjectRoutingId(SEED, GLOBAL_SHARED_PROJECT_KEY);
const REPO_ROUTING = deriveProjectRoutingId(SEED, 'github.com/acme/widgets');

const GLOBAL_MEM = { kind: 'preference', subject: ['workflow'], claim: 'deploys go through staging first', bedrock: true };

test('a global-shared record decodes to target=global (always-inject), with content', () => {
  const rec = sharedRecord('mem_global_1', GLOBAL_ROUTING, GLOBAL_MEM);
  const { storeRecord, contentBytes } = decodeRecord(rec, null, SEED);
  assert.equal(storeRecord.target, 'global', 'global routing must retarget to global, not project');
  assert.deepEqual(storeRecord.content, GLOBAL_MEM);
  assert.ok(contentBytes, 'decrypted content bytes returned for verification');
});

test('it verifies (operator ES256 over the wire record) and lands as bedrock', () => {
  const rec = sharedRecord('mem_global_1', GLOBAL_ROUTING, GLOBAL_MEM);
  const { storeRecord, contentBytes } = decodeRecord(rec, null, SEED);
  // Signature was minted over the WIRE shape (target 'project') — verify uses
  // the wire record, so retargeting to 'global' doesn't break provenance.
  const v = verifyRecordSignature(rec, contentBytes, opJwk, { agentDid: 'did:lastid:agent:zPeer' });
  assert.ok(v.ok, `expected verify ok, got ${JSON.stringify(v)}`);

  const dir = mkdtempSync(join(tmpdir(), 'lastid-globalmem-'));
  after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });
  const store = new OperatorStore('main', join(dir, 'op.json'));
  store.applyRecords([storeRecord], 1);
  // Surfaces as a global memory + as bedrock — the always-inject paths.
  assert.equal(store.listMemories().some((m) => m.id === 'mem_global_1'), true);
  assert.equal(store.bedrockMemories().some((m) => m.id === 'mem_global_1'), true);
});

test('a REAL repo routing is NOT retargeted — stays a repo-gated project memory', () => {
  const rec = sharedRecord('mem_proj_1', REPO_ROUTING, {
    kind: 'fact', subject: ['repo'], claim: 'in this repo we use npm test', bedrock: true,
    project_key: 'github.com/acme/widgets',
  });
  const { storeRecord } = decodeRecord(rec, null, SEED);
  assert.equal(storeRecord.target, 'project', 'repo routing must remain project (repo-gated)');
});

test('without project_root_seed, a global record cannot be decoded (no reseal leak)', () => {
  const rec = sharedRecord('mem_global_1', GLOBAL_ROUTING, GLOBAL_MEM);
  assert.throws(() => decodeRecord(rec, null, null));
});
