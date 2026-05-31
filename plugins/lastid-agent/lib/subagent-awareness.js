/**
 * Subagent awareness — surface WHAT subagents the operator built FOR this
 * agent and keep delegation salient, so the model reaches for
 * `lastid_invoke_subagent` instead of doing the work inline.
 *
 * The point of delegating to a helper is threefold (this framing drives the
 * copy below):
 *   1. CONTEXT — the helper does the noisy work in its own session and returns
 *      a short summary; raw stdout never enters the parent's window.
 *   2. CREDENTIAL SEPARATION — a helper can hold grants/credentials the
 *      operator deliberately withheld from the parent (which ingests UNTRUSTED
 *      input). Routing credentialed work through the helper means misusing a
 *      secret takes subverting BOTH agents, not one. This is the security win.
 *   3. ATTRIBUTION — the helper's calls log under its own DID in the audit chain.
 *
 * Injection (parallel to `credential-awareness`):
 *   - SessionStart: the full "Subagents your operator built for you" block —
 *     the three whys + a CREDIBLE reflex (delegate by default for the real
 *     triggers; don't bother for trivial inline edits, so the reflex stays
 *     believed rather than discounted as boilerplate).
 *   - Per-turn (UserPromptSubmit): a COMPACT roster of the installed helpers,
 *     re-injected EVERY turn (not just when one is new) so delegation stays
 *     top-of-mind at the decision moment — newly-arrived helpers flagged 🆕.
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
    'The operator authored the helpers below, gave each its OWN signed identity',
    '(DID + VC) and a deliberately-scoped set of capabilities, and signed them',
    'into existence so you would DELEGATE to them. Three concrete reasons to,',
    'all real:',
    '',
    '- KEEP YOUR CONTEXT CLEAN. The helper does the noisy work — runs the suite,',
    '  scans the logs, greps the tree — in ITS OWN session and hands you back a',
    '  short summary. The raw stdout never enters your window.',
    '- CREDENTIAL SEPARATION (the big one). A helper can hold credentials and',
    '  grants the operator deliberately did NOT give you — precisely because YOU',
    '  ingest untrusted input (operator messages, web content, files) and the',
    '  helper, with its narrow prompt, does not. Routing credentialed work',
    '  through the helper means misusing that secret would take subverting BOTH',
    '  you AND the helper, not just you. Trying to do that work yourself defeats',
    '  the protection the operator set up.',
    '- CLEAN ATTRIBUTION. The helper\'s calls log under ITS DID in the audit',
    '  chain, cross-referenced to your invocation.',
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
    'REFLEX — make delegating the default, not an afterthought. Before you',
    'start a unit of work, glance at the briefs above; if a helper fits, invoke',
    'it with `lastid_invoke_subagent({slug, input})` instead of doing it',
    'yourself. Reach for one ESPECIALLY when the work:',
    '  - needs a capability or credential a helper has and you don\'t — do NOT',
    '    try to route around it; that gap is the security model, not an obstacle;',
    '  - would flood your context with output (test runs, log scans, big greps);',
    '  - is long-running or parallelizable — pass `background: true` and keep',
    '    working while it runs; results arrive as a push.',
    '',
    'A trivial inline edit you\'d finish in one step isn\'t worth a round-trip —',
    'so don\'t force it, and the reflex stays believable. But the moment a task',
    'lands in a helper\'s domain — anything credentialed, noisy, or long — the',
    'helper goes first.',
    '',
    'If a helper returns a message starting with `NEEDS INPUT:`, it hit a',
    'decision only you or the operator can make and STOPPED instead of guessing',
    '(helpers are one-shot — they have no mid-task back-channel to ask you).',
    'Answer the question(s) and re-invoke the helper with the answer folded into',
    'a fresh `input`.',
  );
  return lines.join('\n');
}

/**
 * Compact per-turn roster of the installed helpers — re-injected EVERY turn so
 * delegation stays salient at the decision moment (not just at session start,
 * where it recedes up-context as work fills in). Helpers not in `seenSlugs`
 * (arrived since last turn) are flagged 🆕. Returns '' when there are none, so
 * the hook injects nothing. Wrapped in <lastid-subagents> so it reads as
 * ambient context, not an operator instruction.
 *
 * Kept deliberately short: a name list + the two highest-signal triggers
 * (credentialed work, context-flooding work). The full "why + how" lives in the
 * SessionStart block; this is the recurring nudge that keeps it in mind.
 */
export function formatSubagentRoster(entries, seenSlugs) {
  const list = (Array.isArray(entries) ? entries : []).filter((e) => e && e.slug);
  if (list.length === 0) return '';
  const seen = new Set(Array.isArray(seenSlugs) ? seenSlugs : []);
  const names = list
    .map((e) => {
      const flag = seen.has(e.slug) ? '' : ' 🆕';
      return `**${e.name ?? e.slug}** (\`${e.slug}\`)${flag}`;
    })
    .join(', ');
  return [
    '<lastid-subagents>',
    `🤖 Your helpers — delegate via \`lastid_invoke_subagent({slug, input})\`: ${names}.`,
    'Reach for one before work that fits a helper, ESPECIALLY anything that needs its',
    'credentials/grants (you don\'t hold them, by design) or would flood your context',
    '(test runs, log scans). A 🆕 tag marks a helper new since last turn.',
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
