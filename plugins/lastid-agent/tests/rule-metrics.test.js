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
