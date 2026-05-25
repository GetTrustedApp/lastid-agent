/**
 * Rule-enforcement coverage for EVERY tool category the authoring UI offers.
 *
 * The browser rule editor's tool selector exposes 14 choices (plus "any").
 * This proves each one is actually wired end-to-end: the Claude runtime tool
 * name normalizes to that category (tool-taxonomy), and a rule authored for the
 * category is ENFORCED by the matcher on the matching tool call — and NOT on a
 * tool in a different category (no over-broad firing, no cross-tool leakage).
 *
 * If a category ever stops mapping or stops enforcing, a row here goes red —
 * so the curated rule pack can't ship a rule that silently no-ops.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { OperatorStore } from '../lib/operator-store.js';
import { canonicalTool, CANONICAL_TOOLS } from '../lib/tool-taxonomy.js';

const DIR = mkdtempSync(join(tmpdir(), 'lastid-rulecov-'));
after(() => {
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

let n = 0;
/** OperatorStore preloaded with one rule (cursor=1 so policyDecision is authoritative). */
function storeWithRule(content) {
  const s = new OperatorStore('main', join(DIR, `op-${n++}.json`));
  s.applyRecords([{ id: 'rule_1', kind: 'rule', version: 1, updated_at: '2026-01-01T00:00:00Z', content }], 1);
  return s;
}

const TOK = 'BADTOKEN';

// The selector contract: category → a representative Claude runtime tool name
// + a matching tool_input that carries the pattern. Mirrors the UI <option>s.
const CASES = {
  shell:       { tool: 'Bash',         input: { command: `run ${TOK} now` } },
  file_read:   { tool: 'Read',         input: { file_path: `/x/${TOK}.txt` } },
  file_write:  { tool: 'Write',        input: { file_path: '/x/y', content: TOK } },
  file_edit:   { tool: 'Edit',         input: { file_path: '/x', old_string: TOK, new_string: 'z' } },
  search:      { tool: 'Grep',         input: { pattern: TOK } },
  web_fetch:   { tool: 'WebFetch',     input: { url: `https://${TOK}.example` } },
  web_search:  { tool: 'WebSearch',    input: { query: TOK } },
  subagent:    { tool: 'Agent',        input: { prompt: `do ${TOK}` } },
  notebook:    { tool: 'NotebookEdit', input: { notebook_path: '/x', new_source: TOK } },
  plan:        { tool: 'TodoWrite',    input: { todos: [{ content: TOK }] } },
  mcp:         { tool: 'mcp__some_server__some_tool', input: { arg: TOK } },
  message_out: { tool: 'mcp__plugin_lastid-agent_lastid-agent__lastid_send_message', input: { text: TOK } },
};

// ── 1. The taxonomy maps every runtime tool name to its category ───────
test('every selector category is produced by canonicalTool from its runtime tool', () => {
  for (const [cat, { tool }] of Object.entries(CASES)) {
    assert.equal(canonicalTool(tool), cat, `${tool} should normalize to ${cat}`);
  }
});

test('the taxonomy enumerates exactly the categories the UI offers (minus message_in, applied off-tool)', () => {
  // message_in is enforced on inbound messages, not tool calls, so it isn't in CASES.
  const enforcedHere = new Set(Object.keys(CASES));
  for (const c of CANONICAL_TOOLS) {
    assert.ok(enforcedHere.has(c) || c === 'message_in', `category ${c} must be covered`);
  }
});

// ── 2. Each category ENFORCES on its tool, and is SCOPED off others ────
for (const [cat, { tool, input }] of Object.entries(CASES)) {
  test(`rule(tool=${cat}) denies ${tool} and does not fire on a different category`, () => {
    const s = storeWithRule({ tool: cat, pattern: TOK, severity: 'deny', reason: `no ${cat}` });
    const hit = s.policyDecision(tool, input);
    assert.equal(hit?.allow, false, `a deny rule for ${cat} must fire on ${tool}`);
    assert.equal(hit.matched.tool, cat);

    // A tool in a DIFFERENT category, with the pattern still present in its
    // input, must NOT trip this rule — proving the scoping is by category,
    // not just by pattern.
    const otherTool = cat === 'shell' ? 'Read' : 'Bash';
    const miss = s.policyDecision(otherTool, { command: TOK, file_path: TOK, text: TOK });
    assert.equal(miss?.allow, true, `${cat} rule must not fire on ${otherTool}`);
  });
}

// ── 3. "any tool" ('') applies across all tools ───────────────────────
test('rule(tool="") applies to ANY tool', () => {
  const s = storeWithRule({ tool: '', pattern: TOK, severity: 'deny' });
  assert.equal(s.policyDecision('Bash', { command: TOK })?.allow, false);
  assert.equal(s.policyDecision('Read', { file_path: TOK })?.allow, false);
  assert.equal(s.policyDecision('WebFetch', { url: TOK })?.allow, false);
  assert.equal(s.policyDecision('NotebookEdit', { new_source: TOK })?.allow, false);
});

// ── 4. message_out vs mcp are distinct surfaces ────────────────────────
test('message_out targets the send tool only — not generic MCP tools, and vice versa', () => {
  const sOut = storeWithRule({ tool: 'message_out', pattern: TOK, severity: 'deny' });
  // fires on the send tool
  assert.equal(sOut.policyDecision(CASES.message_out.tool, { text: TOK })?.allow, false);
  // but NOT on a generic mcp tool
  assert.equal(sOut.policyDecision('mcp__x__y', { arg: TOK })?.allow, true);

  const sMcp = storeWithRule({ tool: 'mcp', pattern: TOK, severity: 'deny' });
  // fires on a generic mcp tool
  assert.equal(sMcp.policyDecision('mcp__x__y', { arg: TOK })?.allow, false);
  // but NOT on the send tool (that's the message_out surface)
  assert.equal(sMcp.policyDecision(CASES.message_out.tool, { text: TOK })?.allow, true);
});

// ── 5. message_in (inbound channel) enforcement + its key invariant ────
test('rule(tool=message_in) fires on inbound messages; tool rules do NOT withhold messages', () => {
  // A message_in rule fires on an inbound operator message.
  const sIn = storeWithRule({ tool: 'message_in', pattern: 'secret', severity: 'deny' });
  assert.equal(
    sIn.matchRules('message_in', 'this mentions a secret', { exactToolOnly: true }).allow,
    false,
    'a message_in rule must apply to inbound messages',
  );
  // A generic "any tool" rule must NOT silently withhold an operator message
  // that merely mentions the pattern (it's about tool execution, not chat).
  const sAny = storeWithRule({ tool: '', pattern: 'secret', severity: 'deny' });
  assert.equal(
    sAny.matchRules('message_in', 'this mentions a secret', { exactToolOnly: true }).allow,
    true,
    'an any-tool rule must NOT fire on the inbound message surface',
  );
  // A shell rule likewise must not fire on inbound messages.
  const sShell = storeWithRule({ tool: 'shell', pattern: 'secret', severity: 'deny' });
  assert.equal(
    sShell.matchRules('message_in', 'this mentions a secret', { exactToolOnly: true }).allow,
    true,
  );
});

// ── 6. permissions apply across ALL MCP tools (any server) ─────────────
test('an mcp-category rule gates EVERY MCP tool, from any server', () => {
  const s = storeWithRule({ tool: 'mcp', pattern: TOK, severity: 'deny' });
  for (const t of [
    'mcp__github__create_issue',
    'mcp__filesystem__delete_file',
    'mcp__slack__post_message',
    'mcp__postgres__run_query',
    'mcp__some-third-party__whatever',
  ]) {
    assert.equal(s.policyDecision(t, { arg: TOK })?.allow, false, `${t} must be gated by an mcp rule`);
  }
  // ...but a built-in (non-MCP) tool is NOT swept up by an mcp-scoped rule.
  assert.equal(s.policyDecision('Bash', { command: TOK })?.allow, true);
});

test('a rule can target ONE specific MCP tool by its literal name', () => {
  // Power-user granularity: the literal-name fallback in ruleAppliesToTool lets
  // a rule gate a single MCP tool without catching its siblings.
  const s = storeWithRule({ tool: 'mcp__github__create_issue', pattern: TOK, severity: 'deny' });
  assert.equal(s.policyDecision('mcp__github__create_issue', { arg: TOK })?.allow, false);
  assert.equal(s.policyDecision('mcp__github__list_issues', { arg: TOK })?.allow, true);
});
