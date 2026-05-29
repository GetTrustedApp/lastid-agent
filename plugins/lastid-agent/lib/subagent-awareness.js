/**
 * Subagent awareness — surface WHAT subagents the operator built FOR this
 * agent, so the model recognizes them at session start and reaches for
 * `lastid_invoke_subagent` instead of doing repeatable work inline.
 *
 * Parallel to `credential-awareness`:
 *   - SessionStart: a compact "Subagents your operator built for you"
 *     block + REFLEX directive, rendered from the local subagents index.
 *   - Per-turn (UserPromptSubmit): a one-line "new subagent available"
 *     delta when one shows up mid-session, diffed against a seen marker.
 *
 * Pure formatters. Each entry on the index already includes the brief
 * (extracted from the body at installStubSub time), so this module
 * doesn't re-read the agent.md.
 */
import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

/**
 * SessionStart block listing the operator-published subagents.
 * Returns '' when none so the caller injects nothing.
 *
 * `entries` is what `listSubagents(parentScope)` returns — each entry
 * carries `slug`, `name`, `brief`, `capabilities`, `may_delegate`.
 */
export function formatSubagentBlock(entries) {
  const list = (Array.isArray(entries) ? entries : []).filter((e) => e && e.slug);
  if (list.length === 0) return '';
  const lines = [
    '## Subagents your operator built for you',
    '',
    'The operator authored the helpers below and SIGNED them into existence',
    'specifically so you would delegate to them. Each one has its OWN identity',
    '(its own DID + VC), its OWN listener syncing rules + memories under that',
    'identity, and capabilities the operator picked deliberately. Invoking one',
    'attributes the work to its DID in the audit chain — not yours — and the',
    'output comes back compact instead of flooding your context.',
    '',
  ];
  for (const e of list) {
    const tagline = typeof e.brief === 'string' && e.brief.length > 0 ? e.brief : '(no brief)';
    let line = `- **${e.name ?? e.slug}** (\`${e.slug}\`) — ${tagline}`;
    if (e.may_delegate) line += `\n  - can delegate further (spawn its own sub-helpers)`;
    lines.push(line);
  }
  lines.push('');
  lines.push(
    'REFLEX — read this every turn. The match isn\'t a literal command —',
    'it\'s the SHAPE of the work. BEFORE you do ANY of these inline:',
    '',
    '  RUNNING checks of any kind:',
    '    - `npm test` / `vitest` / `jest` / `pytest`',
    '    - `cargo test` / `cargo check` / `cargo clippy`',
    '    - `tsc` / `eslint` / `ruff` / type-check passes',
    '',
    '  AUTHORING or MODIFYING test code (this matches a test-writing helper',
    '  EVEN when you\'re fixing a single broken test — that fix IS test work):',
    '    - writing a new .test.js / .test.ts / .test.rs / _test.py',
    '    - changing assertions, adding regression cases, updating fixtures',
    '    - extending a mock / fake / fixture to cover a new scenario',
    '',
    '  ANALYZING or SUMMARIZING that produces a structured artifact:',
    '    - log scans, repeated greps for the same pattern',
    '    - PR descriptions / diff summaries / commit-history walks',
    '    - any recurring chore a helper above was clearly built for',
    '',
    'CHECK the helper list above. If a helper matches the SHAPE of the work,',
    'you MUST invoke it via `lastid_invoke_subagent({slug, input})` — even',
    'for "just this one small piece". The most common reflex miss is the',
    'small piece: the broken test in front of you, the one extra assertion,',
    'the quick PR body. Doing it inline IS the violation.',
    '',
    'Running inline when a fit-for-purpose, operator-signed helper exists is',
    'a REFLEX VIOLATION — it flouts the operator\'s setup, leaves no audit',
    'attribution under the helper\'s DID, and floods your context with stdout',
    'the helper would have summarized. The operator built the helper so you',
    'would delegate; not delegating tells them their work was wasted.',
    'No exceptions for "just this one quick edit" / "this is too small".',
  );
  return lines.join('\n');
}

/** Items whose slug is NOT in the seen set — the subagents new since last turn. */
export function diffNewSubagents(seenSlugs, entries) {
  const seen = new Set(Array.isArray(seenSlugs) ? seenSlugs : []);
  return (Array.isArray(entries) ? entries : []).filter((e) => e && e.slug && !seen.has(e.slug));
}

/**
 * Per-turn delta block announcing newly-available subagents. Returns '' when
 * there are none. Wrapped in <lastid-subagents> so it reads as ambient
 * context, not an operator instruction.
 */
export function formatSubagentDelta(newEntries) {
  const list = (Array.isArray(newEntries) ? newEntries : []).filter((e) => e && e.slug);
  if (list.length === 0) return '';
  const names = list
    .map((e) => `**${e.name ?? e.slug}** (\`${e.slug}\`)`)
    .join(', ');
  const plural = list.length === 1 ? '' : 's';
  const itPron = list.length === 1 ? 'it' : 'them';
  return [
    '<lastid-subagents>',
    `🤖 New helper${plural} now available to you: ${names}.`,
    `Invoke via \`lastid_invoke_subagent({slug, input})\` when a task fits ${itPron}.`,
    '</lastid-subagents>',
  ].join('\n');
}

// ── Seen-slug marker (so the per-turn delta only fires on genuinely-new helpers) ──

export function seenSubagentsPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'subagents-seen.json');
}

export function readSeenSubagents(scope = 'main') {
  try {
    const o = JSON.parse(readFileSync(seenSubagentsPath(scope), 'utf8'));
    return Array.isArray(o?.slugs) ? o.slugs.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function writeSeenSubagents(scope = 'main', slugs = []) {
  const p = seenSubagentsPath(scope);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const tmp = `${p}.tmp`;
  const clean = [...new Set((Array.isArray(slugs) ? slugs : []).filter((x) => typeof x === 'string'))];
  writeFileSync(tmp, JSON.stringify({ slugs: clean }), { mode: 0o600 });
  renameSync(tmp, p);
}
