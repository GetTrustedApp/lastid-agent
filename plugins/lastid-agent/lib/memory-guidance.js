/**
 * The injected "## Memory" operating-context guidance.
 *
 * Extracted from the SessionStart hook so it's pure + unit-testable (the hook
 * itself runs side effects at import). This is the text that makes LastID
 * memory the PREFERRED store and steers the agent away from recording durable
 * facts in markdown files (MEMORY.md / CLAUDE.md), which the runtime's own
 * memory prompt would otherwise encourage. Leads with the action (save it
 * here, not in a file); the "why" is a single supporting line.
 */
export function memoryGuidanceLines() {
  return [
    '## Memory (persistent across sessions)',
    '',
    'Save durable facts, preferences, decisions, and project knowledge with',
    '`lastid_memory_write` / `lastid_memory_draft` — NOT to MEMORY.md, CLAUDE.md,',
    'or any markdown/notes file. THIS is your memory and the single source of',
    'truth: it is cryptographically provable, synced to every device and session,',
    'governed by your operator, and auto-injected into your context each turn. A',
    'fact written to a file gets none of that and will not come back to you. If',
    'you catch yourself about to record something durable in a file, write it',
    'here instead.',
    '',
    "Every turn the harness auto-injects the operator's bedrock memories —",
    'ground truth that beats your training data when they conflict. Cite a',
    'memory by id (e.g. `[mem_abc]`) when you act on one.',
    '',
    'Pick a tier with `tier`:',
    '- `agent` (default) — just you, across your sessions.',
    "- `project` — shared with all your operator's agents, injected only when",
    "  you're working in that repo. Use for repo-specific ground truth and",
    '  decisions ("in this repo we …"). Defaults to the repo you are working in.',
    "- `global` — all the operator's agents, in every context. The high bar; an",
    '  agent write here becomes a proposal your operator reviews and promotes.',
    '',
    'Two writing patterns:',
    '',
    '- `lastid_memory_write` — the operator EXPLICITLY asked you to',
    '  remember something ("save this", "from now on", "we decided").',
    '  Commits immediately, surfaces in retrieve, citable next turn.',
    '- `lastid_memory_draft` — YOU inferred something durable from',
    '  conversation but the operator did NOT explicitly ask you to',
    '  save. Queues for review in the wallet UI. Does not influence',
    '  future turns until the operator promotes it. Always include a',
    '  `source_quote` from the conversation so the operator can',
    '  evaluate the proposal.',
    '',
    'Heuristic for when to draft: did the operator just teach you a',
    'preference, decision, named entity, or workflow rule that you',
    'would want to remember next time? If yes and they did not ask',
    'you to save it explicitly, draft it. If no, do not.',
    '',
    'Do NOT draft: ephemeral task state, transient debugging notes,',
    'speculative inferences, or anything you would not want surfaced',
    "back as ground truth. The operator's bandwidth for reviewing",
    'drafts is finite; high signal only.',
  ];
}
