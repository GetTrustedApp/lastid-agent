/**
 * Shared-key GLOBAL rules + per-agent EXEMPTIONS.
 *
 * Global rules ride the SAME reissue-proof shared rails as global memories (one
 * record under the reserved global routing, wire target 'project', retargeted
 * to 'global' locally) — distinguished only by kind='rule'. On top of that, a
 * global rule may opt specific agents OUT via content.exempt_agents: the rule
 * governs every one of the operator's agents EXCEPT those, and a freshly
 * reissued agent (brand-new DID, not yet exempted) is governed by default.
 *
 * This proves the agent side:
 *   - a global-shared rule decodes to target 'global' and FIRES (deny);
 *   - an agent listed in exempt_agents is NOT governed (opt-out);
 *   - a different (e.g. reissued) agent NOT listed IS still governed;
 *   - it verifies as an operator ES256 record over the wire shape.
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

const GLOBAL_ROUTING = deriveProjectRoutingId(SEED, GLOBAL_SHARED_PROJECT_KEY);

/** A shared GLOBAL rule record the way the console publishes one. */
function sharedRule(id, content) {
  const contentBytes = Buffer.from(JSON.stringify(content), 'utf8');
  const enc_b64 = encryptProjectContent(SEED, GLOBAL_ROUTING, contentBytes).toString('base64');
  const claims = {
    kind: 'rule', id, target: 'project', version: 1, status: 'active',
    content_sha256: sha256Hex(contentBytes),
  };
  return {
    id, kind: 'rule', target: 'project', status: 'active', version: 1,
    routing_id: GLOBAL_ROUTING, enc_b64, sig: mintEs256(claims), author: 'operator',
  };
}

const GOVERNED = 'did:lastid:agent:zGovernedReissued';
const EXEMPT = 'did:lastid:agent:zReleaseBot';
const RULE = {
  // tool-agnostic deny so the test doesn't depend on tool-name canonicalization.
  pattern: 'rm -rf /',
  severity: 'deny',
  reason: 'destructive wipe',
  exempt_agents: [EXEMPT],
};

function storeWithRule() {
  const dir = mkdtempSync(join(tmpdir(), 'lastid-globalrule-'));
  after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ } });
  const store = new OperatorStore('main', join(dir, 'op.json'));
  const { storeRecord } = decodeRecord(sharedRule('rule_global_1', RULE), null, SEED);
  assert.equal(storeRecord.target, 'global', 'global routing must retarget a rule to global too');
  assert.equal(storeRecord.kind, 'rule');
  store.applyRecords([storeRecord], 1);
  return store;
}

test('a global-shared rule decodes to global and FIRES for a non-exempt agent', () => {
  const store = storeWithRule();
  const d = store.matchRules('Bash', { command: 'rm -rf /' }, { selfDid: GOVERNED });
  assert.equal(d.allow, false, 'governed agent must be denied');
  assert.equal(d.matched.severity, 'deny');
  assert.equal(d.matched.memory_id, 'rule_global_1');
});

test('an EXEMPT agent is NOT governed by the rule (opt-out)', () => {
  const store = storeWithRule();
  const d = store.matchRules('Bash', { command: 'rm -rf /' }, { selfDid: EXEMPT });
  assert.equal(d.allow, true, 'exempt agent must not be denied');
});

test('policyDecision threads selfDid (authoritative once synced)', () => {
  const store = storeWithRule();
  assert.equal(store.policyDecision('Bash', { command: 'rm -rf /' }, { selfDid: EXEMPT }).allow, true);
  assert.equal(store.policyDecision('Bash', { command: 'rm -rf /' }, { selfDid: GOVERNED }).allow, false);
});

test('no selfDid → governed (safe default: a rule with exemptions still fires)', () => {
  const store = storeWithRule();
  assert.equal(store.matchRules('Bash', { command: 'rm -rf /' }).allow, false);
});

test('the shared rule verifies as an operator ES256 record over the wire shape', () => {
  const rec = sharedRule('rule_global_1', RULE);
  const { contentBytes } = decodeRecord(rec, null, SEED);
  const v = verifyRecordSignature(rec, contentBytes, opJwk, { agentDid: GOVERNED });
  assert.ok(v.ok, `expected verify ok, got ${JSON.stringify(v)}`);
});
