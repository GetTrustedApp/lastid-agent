/**
 * Regression tests for the rewrite path (operator-store.js).
 *
 * THE BUG: a `rewrite` rule authored with the console's "is_regex" checkbox
 * (no `regex:` prefix) MATCHED — patternMatches honoured the flag — but the
 * rewriter only checked the `regex:` prefix, so it ESCAPED the regex into a
 * literal that matched nothing and rewrote nothing. The supply-chain rule
 *   pattern: \b(npm|yarn|pnpm|pip|uv|cargo)(\s|$)  is_regex: true
 *   replacement: sfw $1$2
 * silently no-op'd: `npm install` ran raw, no `sfw`, nothing in the logs.
 *
 * The fix: one shared compileRulePattern() drives BOTH the matcher and the
 * rewriter, so they can never disagree on whether a pattern is a regex.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  OperatorStore,
  compileRulePattern,
  applyRewrite,
  patternMatches,
  stripInlineFlags,
} from '../lib/operator-store.js';

// The exact rule the operator published (read back from the synced store).
const SFW_PATTERN = '\\b(npm|yarn|pnpm|pip|uv|cargo)(\\s|$)';
const SFW_REPLACEMENT = 'sfw $1$2';

function freshStore() {
  return new OperatorStore('test', join(tmpdir(), `opstore-${randomUUID()}.json`));
}

function rule(id, content, over = {}) {
  return {
    id,
    kind: 'rule',
    target: 'global',
    status: 'active',
    version: 1,
    updated_at: '2026-01-01T00:00:00Z',
    content,
    ...over,
  };
}

// ── compileRulePattern: the single source of truth ─────────────────

test('compileRulePattern: literal pattern escapes metacharacters', () => {
  const re = compileRulePattern('a.b', false, 'i');
  assert.ok(re.test('a.b'));
  assert.ok(!re.test('axb'), 'the "." must be literal, not any-char');
});

test('compileRulePattern: is_regex flag is honoured (no prefix needed)', () => {
  const re = compileRulePattern('a.b', true, 'i');
  assert.ok(re.test('axb'), 'with is_regex, "." matches any char');
});

test('compileRulePattern: regex: prefix is honoured', () => {
  const re = compileRulePattern('regex:a.b', false, 'i');
  assert.ok(re.test('axb'));
});

test('compileRulePattern: malformed regex returns null (fail closed)', () => {
  assert.equal(compileRulePattern('regex:(', false, 'i'), null);
  assert.equal(compileRulePattern('(unbalanced', true, 'i'), null);
});

// ── applyRewrite: the sfw regression ───────────────────────────────

test('REGRESSION: checkbox-regex rule rewrites (was a silent no-op)', () => {
  const out = applyRewrite(
    { command: 'npm install lodash' },
    SFW_PATTERN,
    SFW_REPLACEMENT,
    true, // is_regex flag — NO `regex:` prefix, exactly as the console writes it
  );
  assert.ok(out, 'rewrite must produce a changed object, not null');
  assert.equal(out.command, 'sfw npm install lodash');
});

test('applyRewrite: backrefs + alternation across managers', () => {
  for (const [cmd, want] of [
    ['yarn add x', 'sfw yarn add x'],
    ['pnpm i', 'sfw pnpm i'],
    ['pip install requests', 'sfw pip install requests'],
    ['cargo build', 'sfw cargo build'],
  ]) {
    const out = applyRewrite({ command: cmd }, SFW_PATTERN, SFW_REPLACEMENT, true);
    assert.equal(out.command, want, `command: ${cmd}`);
  }
});

test('applyRewrite: a command naming TWO managers double-prefixes (rule quirk, not engine bug)', () => {
  // `uv pip install x` contains both `uv` and `pip`; the operator's
  // alternation + global flag prefixes each one. This documents the real
  // behaviour of the operator's regex — it's a rule-authoring caveat
  // (`sfw uv sfw pip …` is a broken command), NOT an engine fault. The
  // engine faithfully applies the pattern it was given.
  const out = applyRewrite({ command: 'uv pip install x' }, SFW_PATTERN, SFW_REPLACEMENT, true);
  assert.equal(out.command, 'sfw uv sfw pip install x');
});

test('applyRewrite: bare manager name (matches end-of-string group)', () => {
  const out = applyRewrite({ command: 'npm' }, SFW_PATTERN, SFW_REPLACEMENT, true);
  assert.equal(out.command, 'sfw npm');
});

test('applyRewrite: non-matching command is left alone (null)', () => {
  assert.equal(applyRewrite({ command: 'ls -la' }, SFW_PATTERN, SFW_REPLACEMENT, true), null);
});

test('applyRewrite: literal pattern still works (no is_regex)', () => {
  const out = applyRewrite({ command: 'git push --force' }, 'push --force', 'push', false);
  assert.equal(out.command, 'git push');
});

test('applyRewrite: regex: prefix still works', () => {
  const out = applyRewrite({ command: 'npm ci' }, 'regex:^npm', 'sfw npm', false);
  assert.equal(out.command, 'sfw npm ci');
});

test('applyRewrite: rewrites the outbound channel text field too', () => {
  const out = applyRewrite({ text: 'my key is sk-abc123' }, 'sk-\\w+', '[redacted]', true);
  assert.equal(out.text, 'my key is [redacted]');
});

test('applyRewrite: malformed pattern fails closed (null, no throw)', () => {
  assert.equal(applyRewrite({ command: 'npm i' }, 'regex:(', 'x', false), null);
});

// ── the cross-consistency guard: match and rewrite MUST agree ──────

// ── inline-flag handling: (?i) and friends ─────────────────────────
//
// REGRESSION: a pasted PCRE/Python regex like `(?i)…` throws "Invalid
// group" in JS, so it used to compile to null and silently match nothing
// — a dead security rule. compileRulePattern now folds a leading inline-
// flag group into the RegExp flags instead.

test('stripInlineFlags: folds (?i) into flags and removes the group', () => {
  assert.deepEqual(stripInlineFlags('(?i)foo', ''), { source: 'foo', flags: 'i' });
  assert.deepEqual(stripInlineFlags('(?im)foo', 'g'), { source: 'foo', flags: 'gim' });
});

test('stripInlineFlags: leaves unsupported flags (x) in place to fail loudly', () => {
  // `x` (verbose) has no JS equivalent — don't silently strip it.
  assert.deepEqual(stripInlineFlags('(?x)foo', 'i'), { source: '(?x)foo', flags: 'i' });
});

test('stripInlineFlags: no leading group is a no-op', () => {
  assert.deepEqual(stripInlineFlags('foo(?i)bar', 'i'), { source: 'foo(?i)bar', flags: 'i' });
});

test('compileRulePattern: (?i) prefix compiles and is case-insensitive', () => {
  const re = compileRulePattern('(?i)--force', true, 'i');
  assert.ok(re, 'must compile, not return null');
  assert.ok(re.test('--FORCE'));
});

test('compileRulePattern: (?x) prefix still fails closed (null)', () => {
  assert.equal(compileRulePattern('(?x)--force', true, 'i'), null);
});

test("REGRESSION: the operator's (?i) dangerous-flags regex now matches", () => {
  const PAT =
    '(?i)(?:^|\\s)--?(?:danger(?:ous(?:ly)?)?|unsafe|force|bypass|skip(?:-[a-z-]+)?|disable(?:-[a-z-]+)?|ignore(?:-[a-z-]+)?|no-(?:verify|sandbox|auth|security|prompt|confirm))(?:\\s|=|$)';
  for (const cmd of ['rm -rf --force', 'git commit --no-verify', 'DELETE --FORCE', 'tool --skip-checks']) {
    assert.equal(patternMatches(PAT, true, `command=${cmd}`), true, `should match: ${cmd}`);
  }
  for (const cmd of ['ls -la', 'cargo build --release']) {
    assert.equal(patternMatches(PAT, true, `command=${cmd}`), false, `should NOT match: ${cmd}`);
  }
});

test('REGRESSION: matcher and rewriter agree for a checkbox-regex rule', () => {
  const s = freshStore();
  s.upsert(
    rule('r_sfw', {
      tool: 'shell',
      pattern: SFW_PATTERN,
      is_regex: true,
      severity: 'rewrite',
      replacement: SFW_REPLACEMENT,
      reason: 'supply chain firewall',
    }),
  );
  // Match side (what policy-check returns to the hook).
  const decision = s.matchRules('Bash', { command: 'npm install lodash' });
  assert.equal(decision.allow, false);
  assert.equal(decision.matched.severity, 'rewrite');
  assert.equal(decision.matched.is_regex, true, 'matched must carry is_regex for the rewriter');

  // Rewrite side (what the hook then applies) — must actually change it.
  const out = applyRewrite(
    { command: 'npm install lodash' },
    decision.matched.pattern,
    decision.matched.replacement,
    decision.matched.is_regex,
  );
  assert.ok(out, 'a matched rewrite rule must produce an actual rewrite');
  assert.equal(out.command, 'sfw npm install lodash');
});
