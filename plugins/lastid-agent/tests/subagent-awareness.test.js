/**
 * Subagent awareness shapes whether the model actually DELEGATES. Two surfaces:
 *   - formatSubagentBlock  → the SessionStart block (the three whys + a CREDIBLE
 *     reflex). Locks that the credential-separation security framing is present
 *     and that the discredited absolutism ("REFLEX VIOLATION", "smallness is the
 *     trap", "no exceptions") is GONE — that wording got the whole block
 *     discounted as boilerplate.
 *   - formatSubagentRoster → the per-turn compact roster. Locks the core fix:
 *     it lists EVERY installed helper on EVERY turn (so delegation stays salient
 *     mid-session), not just helpers new since the seen-marker — those just get
 *     a 🆕 flag.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatSubagentBlock,
  formatSubagentRoster,
} from '../lib/subagent-awareness.js';

const A = { slug: 'test-runner', name: 'Test Runner', brief: 'runs a suite, returns a summary' };
const B = { slug: 'deploy-bot', name: 'Deploy Bot', brief: 'ships a release', may_delegate: true };

// ── SessionStart block ───────────────────────────────────────────────

test('formatSubagentBlock: empty when there are no helpers', () => {
  assert.equal(formatSubagentBlock([]), '');
  assert.equal(formatSubagentBlock(undefined), '');
});

test('formatSubagentBlock: leads with the three concrete whys (context, credential separation, attribution)', () => {
  const t = formatSubagentBlock([A]);
  assert.match(t, /KEEP YOUR CONTEXT CLEAN/);
  assert.match(t, /CREDENTIAL SEPARATION/);
  // The security model: parent ingests untrusted input, helper holds the grant.
  assert.match(t, /untrusted input/);
  assert.match(t, /subverting BOTH/i);
  assert.match(t, /CLEAN ATTRIBUTION/);
});

test('formatSubagentBlock: keeps a reflex but makes it CREDIBLE (real triggers, carves out trivial)', () => {
  const t = formatSubagentBlock([A]);
  assert.match(t, /REFLEX/);
  assert.match(t, /make delegating the default/i);
  assert.match(t, /background: true/); // the long/parallel trigger
  // A credible reflex explicitly does NOT demand delegating trivial inline work.
  assert.match(t, /trivial inline edit/i);
});

test('formatSubagentBlock: the discredited absolutism is GONE (it got the block discounted)', () => {
  const t = formatSubagentBlock([A]);
  assert.doesNotMatch(t, /REFLEX VIOLATION/);
  assert.doesNotMatch(t, /Smallness IS the trap/i);
  assert.doesNotMatch(t, /No exceptions/i);
});

test('formatSubagentBlock: renders each helper name, slug, and brief (+ delegate flag)', () => {
  const t = formatSubagentBlock([A, B]);
  assert.match(t, /\*\*Test Runner\*\* \(`test-runner`\) — runs a suite/);
  assert.match(t, /\*\*Deploy Bot\*\* \(`deploy-bot`\) — ships a release/);
  assert.match(t, /can delegate further/); // B.may_delegate
});

// ── Per-turn roster (the persistence fix) ────────────────────────────

test('formatSubagentRoster: empty when there are no helpers', () => {
  assert.equal(formatSubagentRoster([], []), '');
  assert.equal(formatSubagentRoster(undefined, undefined), '');
});

test('formatSubagentRoster: lists an ALREADY-SEEN helper EVERY turn (the core fix), unflagged', () => {
  // Before: a seen helper produced nothing per-turn, so delegation faded from
  // context mid-session. Now it still appears — just without the 🆕 flag on it.
  const t = formatSubagentRoster([A], ['test-runner']);
  assert.notEqual(t, '');
  assert.match(t, /test-runner/);
  assert.match(t, /<lastid-subagents>/);
  // No 🆕 tag ON the seen helper (the legend line may mention 🆕; assert on the
  // helper token specifically, not a global emoji count).
  assert.doesNotMatch(t, /`test-runner`\) 🆕/);
});

test('formatSubagentRoster: flags only the helpers new since the seen-marker', () => {
  const t = formatSubagentRoster([A, B], ['test-runner']); // A seen, B new
  assert.match(t, /`deploy-bot`\) 🆕/); // new helper gets the flag
  assert.doesNotMatch(t, /`test-runner`\) 🆕/); // seen helper does not
});

test('formatSubagentRoster: stays compact + names the two highest-signal triggers', () => {
  const t = formatSubagentRoster([A], []);
  assert.match(t, /lastid_invoke_subagent/);
  assert.match(t, /credentials\/grants/);
  assert.match(t, /flood your context/);
});

test('formatSubagentBlock: tells the parent how to handle a helper that returns NEEDS INPUT', () => {
  // Helpers are one-shot with no back-channel; a blocked helper returns its
  // question. The parent must know to answer + re-invoke (not treat it as done).
  const t = formatSubagentBlock([A]);
  assert.match(t, /NEEDS INPUT:/);
  assert.match(t, /re-invoke/i);
});
