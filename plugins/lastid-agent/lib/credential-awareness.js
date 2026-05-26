/**
 * Credential awareness — surface WHAT the operator has shared with this agent,
 * so it knows its vault access up front instead of discovering it only via a
 * mid-task `vault_list` call (and so it never goes hunting for env vars/files or
 * tells the operator it lacks access to something it already has).
 *
 * Two surfaces:
 *   - SessionStart: a compact "Credentials shared with you right now" block,
 *     rendered from the local synced vault cache (formatCredentialBlock).
 *   - Per-turn (UserPromptSubmit): a one-line "new credential available" delta
 *     when a share lands mid-session, diffed against a seen-id marker.
 *
 * Pure formatters here take the COMPACT view (compactCredential) — never a
 * secret; the secret is dropped upstream by vaultListView. The seen marker
 * stores only share ids (no metadata, no secret).
 */
import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

/**
 * Trim a vaultListView output to the awareness-relevant, secret-free fields.
 * `usage` and `constraints` are the human-readable lines vaultListView already
 * computed (usageContext / summarizeConstraints).
 */
export function compactCredential(v) {
  const view = v && typeof v === 'object' ? v : {};
  return {
    id: view.id ?? view.item_id ?? null,
    title: view.title ?? view.service ?? view.id ?? 'credential',
    service: view.service ?? null,
    host: view.host ?? null,
    injection: view.injection?.type ?? null,
    usage: view.usage ?? null,
    constraints: view.constraints_summary ?? null,
  };
}

/**
 * SessionStart block listing the shared credentials. Returns '' when none so the
 * caller injects nothing (no empty heading).
 */
export function formatCredentialBlock(items) {
  const list = (Array.isArray(items) ? items : []).filter((c) => c && c.id);
  if (list.length === 0) return '';
  const lines = [
    '## Credentials shared with you right now',
    '',
    'The operator has ALREADY shared the vault items below with you. When a task',
    'needs one of these, go straight to `vault_use(item_id)` — do NOT search for',
    'keys, env vars, or files, and do NOT tell the operator you lack access. You',
    'still never see the secret value; the listener injects it at the network',
    'boundary.',
    '',
  ];
  for (const c of list) {
    const detail = [
      c.service && c.service !== c.title ? c.service : null,
      c.host,
      c.injection ? `inject: ${c.injection}` : null,
    ]
      .filter(Boolean)
      .join(' · ');
    let line = `- **${c.title}** (\`${c.id}\`)`;
    if (detail) line += ` — ${detail}`;
    if (c.constraints) line += `\n  - limits: ${c.constraints}`;
    lines.push(line);
  }
  return lines.join('\n');
}

/** Items whose id is NOT in the seen set — the credentials new since last turn. */
export function diffNewCredentials(seenIds, items) {
  const seen = new Set(Array.isArray(seenIds) ? seenIds : []);
  return (Array.isArray(items) ? items : []).filter((c) => c && c.id && !seen.has(c.id));
}

/**
 * Per-turn delta block announcing newly-available credentials. Returns '' when
 * there are none. Wrapped in <lastid-vault> so it reads as ambient context, not
 * an operator instruction.
 */
export function formatCredentialDelta(newItems) {
  const list = (Array.isArray(newItems) ? newItems : []).filter((c) => c && c.id);
  if (list.length === 0) return '';
  const names = list
    .map((c) => `**${c.title}**${c.service && c.service !== c.title ? ` (${c.service})` : ''}`)
    .join(', ');
  const plural = list.length === 1 ? '' : 's';
  const itPron = list.length === 1 ? 'it' : 'them';
  return [
    '<lastid-vault>',
    `🔑 New credential${plural} now available to you via the vault: ${names}.`,
    `Use \`vault_use(item_id)\` to access ${itPron} — no need to ask the operator or hunt for keys.`,
    '</lastid-vault>',
  ].join('\n');
}

// ── Seen-id marker (so the per-turn delta only fires on genuinely-new shares) ──

export function seenCredsPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'vault-seen.json');
}

export function readSeenCreds(scope = 'main') {
  try {
    const o = JSON.parse(readFileSync(seenCredsPath(scope), 'utf8'));
    return Array.isArray(o?.ids) ? o.ids.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function writeSeenCreds(scope = 'main', ids = []) {
  const p = seenCredsPath(scope);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const tmp = `${p}.tmp`;
  const clean = [...new Set((Array.isArray(ids) ? ids : []).filter((x) => typeof x === 'string'))];
  writeFileSync(tmp, JSON.stringify({ ids: clean }), { mode: 0o600 });
  renameSync(tmp, p);
}
