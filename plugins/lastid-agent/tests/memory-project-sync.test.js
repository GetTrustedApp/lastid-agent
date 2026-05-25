/**
 * Cross-agent project-memory round-trip (Option B end-to-end, agent side).
 *
 * Agent A writes a project memory → it's encrypted under the project content
 * key (keyed by routing_id) and POSTed as a single shared record. Agent B —
 * a DIFFERENT agent with the SAME operator project_root_seed — syncs that
 * record (it has only the plaintext routing_id), decrypts it, recovers the
 * repo (project_key), and applies it to its local store as a project memory.
 * A peer WITHOUT the seed cannot read it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { publishAgentMemory } from '../lib/agent-memory-publish.js';
import { decodeRecord } from '../lib/agent-state-sync.js';
import { MemoryStore } from '../lib/memory-store.js';
import { deriveProjectRoutingId } from '../lib/project-crypto.js';

const PROJECT_ROOT_SEED = crypto.createHash('sha256').update('operator-project-root').digest(); // 32B
const OTHER_SEED = crypto.createHash('sha256').update('a-different-operator').digest();
const SLOT_A = crypto.createHash('sha256').update('agent-A-slot').digest();
const SLOT_B = crypto.createHash('sha256').update('agent-B-slot').digest();
const IDP = 'github.com/gettrustedapp/gettrusted-idp';

const DIR = mkdtempSync(join(tmpdir(), 'lastid-projsync-'));
import { after } from 'node:test';
after(() => {
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

function projectMemory() {
  return {
    id: 'mem_proj_1',
    version: 1,
    tier: 'project',
    project_key: IDP,
    kind: 'fact',
    subject: ['listener'],
    claim: 'the listener is the single MLS writer per scope',
    bedrock: true,
    sensitivity: 'low',
    source: { kind: 'tool_observation' },
    confidence: 0.7,
    decay: 'none',
    status: 'active',
    created_at: new Date().toISOString(),
  };
}

test('POSITIVE: project memory written by agent A is read+applied by peer agent B (same seed)', async () => {
  // ── Agent A writes: capture the POST body the IdP would store. ──
  let posted = null;
  const fetchImpl = async (_url, init) => {
    posted = JSON.parse(init.body);
    return { ok: true, status: 200 };
  };
  const ok = await publishAgentMemory({
    idpUrl: 'https://human.lastid.co',
    loaded: { agentDid: 'did:lastid:agent:A', slotSeed: SLOT_A, projectRootSeed: PROJECT_ROOT_SEED, vcCompact: 'vc-A' },
    memory: projectMemory(),
    status: 'active',
    version: 1,
    fetchImpl,
  });
  assert.equal(ok, true, 'publish succeeded');
  // It's a single shared record, not a per-agent copy.
  assert.equal(posted.target, 'project');
  assert.equal(posted.routing_id, deriveProjectRoutingId(PROJECT_ROOT_SEED, IDP));
  assert.ok(typeof posted.enc_b64 === 'string' && posted.enc_b64.length > 0);
  assert.equal(posted.copies, undefined, 'no per-agent fan-out for project memories');

  // ── IdP hands the same record to agent B's sync (adds routing context). ──
  const recordFromIdp = {
    id: posted.id,
    kind: 'memory',
    target: 'project',
    routing_id: posted.routing_id,
    version: posted.version,
    status: 'active',
    enc_b64: posted.enc_b64,
    author: 'agent',
    cursor: 7,
    updated_at: new Date().toISOString(),
  };

  // ── Agent B (different slot, SAME project_root_seed) decodes + applies. ──
  const { storeRecord } = decodeRecord(recordFromIdp, SLOT_B, PROJECT_ROOT_SEED);
  assert.equal(storeRecord.content.project_key, IDP, 'B recovered the repo from inside the ciphertext');
  assert.equal(storeRecord.content.claim, 'the listener is the single MLS writer per scope');

  const storeB = new MemoryStore('main', join(DIR, 'b.json'), {
    agentDid: 'did:lastid:agent:B',
    parentHumanDid: 'did:lastid:human:op',
  });
  assert.equal(storeB.applySync(storeRecord, 'agent'), true, 'B applied the project memory');

  // B now injects it ONLY in the idp repo.
  assert.deepEqual(storeB.projectBedrockMemories(IDP).map((m) => m.claim), ['the listener is the single MLS writer per scope']);
  assert.deepEqual(storeB.projectBedrockMemories('github.com/x/other'), []);
  const applied = storeB.get('mem_proj_1');
  assert.equal(applied.tier, 'project');
  assert.equal(applied.project_key, IDP);
  assert.equal(applied.agent_did, null); // shared, not bound to B
});

test('NEGATIVE: a peer WITHOUT the project_root_seed cannot decode the record', () => {
  // Reconstruct a posted record under the real seed.
  const routingId = deriveProjectRoutingId(PROJECT_ROOT_SEED, IDP);
  // Encrypt via the same path publishAgentMemory uses (through a quick publish).
  let posted = null;
  return publishAgentMemory({
    idpUrl: 'https://human.lastid.co',
    loaded: { agentDid: 'did:lastid:agent:A', slotSeed: SLOT_A, projectRootSeed: PROJECT_ROOT_SEED, vcCompact: 'vc' },
    memory: projectMemory(),
    fetchImpl: async (_u, init) => { posted = JSON.parse(init.body); return { ok: true, status: 200 }; },
  }).then(() => {
    const rec = { id: 'x', kind: 'memory', target: 'project', routing_id: routingId, version: 1, status: 'active', enc_b64: posted.enc_b64 };
    // No project_root_seed at all → decode throws (skipped by the sync loop).
    assert.throws(() => decodeRecord(rec, SLOT_B, null), /project_root_seed/);
    // Wrong operator seed → GCM auth failure.
    assert.throws(() => decodeRecord(rec, SLOT_B, OTHER_SEED), /Unsupported state|tag|decrypt/i);
  });
});

test('NEGATIVE: publish refuses a project memory when the agent has no project_root_seed', async () => {
  const ok = await publishAgentMemory({
    idpUrl: 'https://human.lastid.co',
    loaded: { agentDid: 'did:lastid:agent:A', slotSeed: SLOT_A, projectRootSeed: null, vcCompact: 'vc' },
    memory: projectMemory(),
    fetchImpl: async () => ({ ok: true, status: 200 }),
  });
  assert.equal(ok, false, 'no seed → no unreadable project write');
});
