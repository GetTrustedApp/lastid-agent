/**
 * Rule-hit metrics recorder + ship queue (lib/rule-metrics.js).
 *
 * Records a fast local line per rule fire (no sensitive content), and ships
 * unshipped hits best-effort with a cursor that only advances on success.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HOME = mkdtempSync(join(tmpdir(), 'lastid-metrics-'));
process.env.HOME = HOME;
process.env.USERPROFILE = HOME;

const { recordRuleHit, readRuleHits, unshippedHits, shipRuleHits } = await import('../lib/rule-metrics.js');
const { shipRuleMetrics, RULE_HITS_PATH } = await import('../lib/rule-metrics-ship.js');

after(() => {
  try { rmSync(HOME, { recursive: true, force: true }); } catch { /* best-effort */ }
});

test('records a hit with only non-sensitive fields', () => {
  recordRuleHit({ scope: 'a', ruleId: 'rule_1', severity: 'deny', tool: 'shell' });
  const hits = readRuleHits('a');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule_id, 'rule_1');
  assert.equal(hits[0].severity, 'deny');
  assert.equal(hits[0].tool, 'shell');
  assert.equal(hits[0].curated, undefined, 'private rule carries no curated provenance');
  assert.equal(typeof hits[0].at, 'number');
  // No command / pattern / content leaked into the metric.
  assert.equal(JSON.stringify(hits[0]).includes('command'), false);
});

test('curated-pack hit carries pack + rule provenance (for the shared aggregate)', () => {
  recordRuleHit({ scope: 'b', ruleId: 'rule_x', severity: 'warn', tool: 'web_fetch', curated: true, pack: 'network-exfiltration', rule: 'data-drop-sites' });
  const h = readRuleHits('b')[0];
  assert.equal(h.curated, true);
  assert.equal(h.pack, 'network-exfiltration');
  assert.equal(h.rule, 'data-drop-sites');
});

test('record requires ruleId + severity', () => {
  assert.equal(recordRuleHit({ scope: 'c', severity: 'deny' }), false);
  assert.equal(recordRuleHit({ scope: 'c', ruleId: 'r' }), false);
  assert.equal(readRuleHits('c').length, 0);
});

test('ship advances the cursor only on success; retries on failure', async () => {
  recordRuleHit({ scope: 'd', ruleId: 'r1', severity: 'deny', tool: 'shell' });
  recordRuleHit({ scope: 'd', ruleId: 'r2', severity: 'warn', tool: 'mcp' });
  assert.equal(unshippedHits('d').length, 2);

  // A failing send must NOT advance the cursor.
  const failed = await shipRuleHits('d', async () => false);
  assert.equal(failed, 0);
  assert.equal(unshippedHits('d').length, 2, 'still pending after a failed send');

  // A successful send ships all pending + advances.
  let received = null;
  const n = await shipRuleHits('d', async (recs) => { received = recs; return true; });
  assert.equal(n, 2);
  assert.equal(received.length, 2);
  assert.equal(unshippedHits('d').length, 0, 'nothing pending after success');

  // A new hit is the only thing pending next time.
  recordRuleHit({ scope: 'd', ruleId: 'r3', severity: 'rewrite', tool: 'shell' });
  assert.deepEqual(unshippedHits('d').map((h) => h.rule_id), ['r3']);
});

// REGRESSION — broker-native (ES256) agent shipped nothing because the shipper
// bailed on a null signingKey/slotSeed (no seed in node by custody design); the
// broker covers auth/seal/sign. shipRuleMetrics must REACH authedIdpFetch with a
// null signingKey, not bail.
test('shipRuleMetrics: broker-native (null signingKey) reaches authedIdpFetch and ships', async () => {
  recordRuleHit({ scope: 'bn', ruleId: 'r1', severity: 'deny', tool: 'shell' });
  let reached = null;
  const n = await shipRuleMetrics({
    idpUrl: 'https://idp.test',
    scope: 'bn',
    agentDid: 'did:lastid:agent:zDn',
    vcCompact: 'vc.jwt',
    signingKey: null, // broker-native: no key in node
    _authedIdpFetch: async (opts) => { reached = opts; return {}; },
  });
  assert.equal(n, 1, 'shipped the single pending hit via the broker path');
  assert.ok(reached, 'authedIdpFetch WAS called (did not bail on null signingKey)');
  assert.equal(reached.path, RULE_HITS_PATH);
  assert.equal(reached.signingKey, null);
  assert.equal(unshippedHits('bn').length, 0, 'cursor advanced on success');
});

test('shipRuleMetrics: missing vcCompact still bails WITHOUT calling authedIdpFetch (no regression)', async () => {
  recordRuleHit({ scope: 'bn2', ruleId: 'r1', severity: 'deny', tool: 'shell' });
  let called = false;
  const n = await shipRuleMetrics({
    idpUrl: 'https://idp.test',
    scope: 'bn2',
    agentDid: 'did:a',
    vcCompact: '', // missing VC → bail
    signingKey: null,
    _authedIdpFetch: async () => { called = true; return {}; },
  });
  assert.equal(n, 0);
  assert.equal(called, false, 'never reached the IdP call');
  assert.equal(unshippedHits('bn2').length, 1, 'cursor untouched');
});

test('shipRuleMetrics: legacy path unchanged — a real signingKey still ships via authedIdpFetch', async () => {
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('ed25519');
  recordRuleHit({ scope: 'leg', ruleId: 'r1', severity: 'deny', tool: 'shell' });
  let reached = null;
  const n = await shipRuleMetrics({
    idpUrl: 'https://idp.test',
    scope: 'leg',
    agentDid: 'did:a',
    vcCompact: 'vc.jwt',
    signingKey: privateKey,
    _authedIdpFetch: async (opts) => { reached = opts; return {}; },
  });
  assert.equal(n, 1);
  assert.equal(reached.signingKey, privateKey, 'legacy signingKey forwarded unchanged');
});
