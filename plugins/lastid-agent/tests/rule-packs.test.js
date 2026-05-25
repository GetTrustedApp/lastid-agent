/**
 * Curated rule packs — single source of truth (data/rule-packs.json) validated
 * through the REAL matcher in its PUBLISHED form.
 *
 * The key guarantee: what's tested == what ships == what the operator enables.
 * So each rule is exercised via publishableRuleContent() — the exact content
 * the browser publishes when enabling — not the raw authoring shape. A regex
 * that doesn't fire on its target (the dead-rule class) fails the build, and
 * the published form carries curated provenance + pack version for metrics +
 * rollout.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  RULE_PACKS,
  RULE_PACKS_FORMAT_VERSION,
  allPackRules,
  publishableRuleContent,
} from '../lib/rule-packs.js';
import { OperatorStore, compileRulePattern, applyRewrite } from '../lib/operator-store.js';
import { CANONICAL_TOOLS } from '../lib/tool-taxonomy.js';

const DIR = mkdtempSync(join(tmpdir(), 'lastid-packs-'));
after(() => {
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

const RUNTIME_TOOL = {
  '': 'Bash',
  shell: 'Bash',
  file_read: 'Read',
  file_write: 'Write',
  file_edit: 'Edit',
  search: 'Grep',
  web_fetch: 'WebFetch',
  web_search: 'WebSearch',
  subagent: 'Agent',
  notebook: 'NotebookEdit',
  plan: 'TodoWrite',
  mcp: 'mcp__some_server__some_tool',
  message_out: 'mcp__plugin_lastid-agent_lastid-agent__lastid_send_message',
  message_in: 'message_in',
};

const SEVERITIES = new Set(['deny', 'warn', 'rewrite']);
const VALID_TOOLS = new Set([...CANONICAL_TOOLS, '']);

let n = 0;
/** Build a store holding ONE rule from its published content. */
function storeWithContent(content) {
  const s = new OperatorStore('main', join(DIR, `op-${n++}.json`));
  s.applyRecords(
    [{ id: `rule_${n}`, kind: 'rule', version: 1, updated_at: '2026-01-01T00:00:00Z', content }],
    1,
  );
  return s;
}

// ── structure + versioning ─────────────────────────────────────────

test('packs carry metadata + a version (search, empty-state, rollout)', () => {
  assert.equal(typeof RULE_PACKS_FORMAT_VERSION, 'number');
  assert.ok(RULE_PACKS.length >= 5, 'a real set of packs');
  const packIds = new Set();
  for (const p of RULE_PACKS) {
    assert.ok(typeof p.id === 'string' && p.id.length > 0, 'pack id');
    assert.ok(!packIds.has(p.id), `duplicate pack id ${p.id}`);
    packIds.add(p.id);
    assert.ok(Number.isInteger(p.version) && p.version >= 1, `${p.id} needs an integer version (rollout)`);
    assert.ok(typeof p.name === 'string' && p.name.length > 0, `${p.id} name`);
    assert.ok(typeof p.summary === 'string' && p.summary.length > 0, `${p.id} summary`);
    assert.ok(typeof p.why === 'string' && p.why.length > 20, `${p.id} why`);
    assert.ok(Array.isArray(p.tags) && p.tags.length > 0, `${p.id} tags`);
    assert.ok(Array.isArray(p.rules) && p.rules.length >= 1 && p.rules.length <= 10, `${p.id} 1-10 rules`);
    const ruleIds = new Set();
    for (const r of p.rules) {
      assert.ok(typeof r.id === 'string' && r.id.length > 0, `${p.id} rule id`);
      assert.ok(!ruleIds.has(r.id), `${p.id} duplicate rule id ${r.id}`);
      ruleIds.add(r.id);
      assert.ok(VALID_TOOLS.has(r.tool), `${p.id}/${r.id} tool '${r.tool}'`);
      assert.ok(SEVERITIES.has(r.severity), `${p.id}/${r.id} severity`);
      assert.ok(typeof r.reason === 'string' && r.reason.length > 0, `${p.id}/${r.id} reason`);
      assert.ok(r.examples && r.examples.hit && r.examples.miss, `${p.id}/${r.id} examples`);
      assert.ok(compileRulePattern(r.pattern, r.is_regex) !== null, `${p.id}/${r.id} pattern compiles`);
      if (r.severity === 'rewrite') assert.ok(typeof r.replacement === 'string', `${p.id}/${r.id} replacement`);
    }
  }
});

test('publishableRuleContent stamps curated provenance + pack version', () => {
  const pack = RULE_PACKS[0];
  const c = publishableRuleContent(pack.rules[0], pack);
  assert.equal(c.curated, true);
  assert.equal(c.pack, pack.id);
  assert.equal(c.rule, pack.rules[0].id);
  assert.equal(c.pack_version, pack.version);
  assert.equal(c.examples, undefined, 'display-only metadata is not published');
});

// ── per-rule enforcement IN PUBLISHED FORM (tested == shipped) ──────

for (const pack of RULE_PACKS) {
  for (const rule of pack.rules) {
    test(`[${pack.id}/${rule.id}] published form fires on hit(s) + ignores miss`, () => {
      const toolName = RUNTIME_TOOL[rule.tool];
      assert.ok(toolName, `no runtime tool for '${rule.tool}'`);
      const content = publishableRuleContent(rule, pack);
      const s = storeWithContent(content);

      const hits = [rule.examples.hit, ...(rule.examples.also_hits ?? [])];
      for (const h of hits) {
        const hit = s.matchRules(toolName, h);
        assert.equal(hit.allow, false, `must CATCH ${JSON.stringify(h)}`);
        assert.equal(hit.matched.severity, rule.severity, 'severity carries through');
        // Provenance surfaces so the hook can meter a curated-pack hit.
        assert.equal(hit.matched.curated, true);
        assert.equal(hit.matched.pack, pack.id);
        assert.equal(hit.matched.rule, rule.id);
      }

      const miss = s.matchRules(toolName, rule.examples.miss);
      assert.equal(miss.allow, true, `must IGNORE ${JSON.stringify(rule.examples.miss)}`);

      if (rule.severity === 'rewrite') {
        assert.ok(applyRewrite(rule.examples.hit, rule.pattern, rule.replacement, rule.is_regex) !== null);
      }
    });
  }
}

test('sfw rewrite prepends sfw to a package install', () => {
  const rule = allPackRules().find((r) => r.id === 'sfw-install');
  const out = applyRewrite({ command: 'npm install lodash' }, rule.pattern, rule.replacement, rule.is_regex);
  assert.equal(out.command, 'sfw npm install lodash');
});
