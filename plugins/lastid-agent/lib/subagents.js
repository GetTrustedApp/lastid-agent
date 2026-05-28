/**
 * Subagent registry, invocation, and stub install.
 *
 * A "subagent" is an operator-authored peer-agent that another agent has
 * authority to invoke. v1 phase tonight is STUB mode (no IdP, no signed VC):
 * the operator writes an agent.md to a local scope dir, the parent agent
 * invokes it via `lastid_invoke_subagent`, which spawns a fresh Claude Code
 * headless session with that scope env. Tools the spawned Claude sees:
 * standard Claude tools (Bash/Read/Edit per --allowed-tools), no LastID MCP
 * tools (the scope is unprovisioned → plugin reports "not provisioned" but
 * runs anyway, cleanly degraded). Real IdP-issued mode is post-tonight.
 *
 * Wire shape of subagent's scope dir: `~/.lastid-agent/<parent-slug>/`.
 * Files (stub mode):
 *   - agent.md       — YAML frontmatter + body (system prompt).
 *   - (no vc.sdjwt, no slot_seed — those land in signed mode.)
 *
 * Index: `~/.lastid-agent/<parent-scope>/subagents.json` — JSON map of
 * slug → metadata for everything installed under this parent.
 *
 * Module split:
 *   PURE — testable without spawning:
 *     parseAgentMd, formatAgentMd, buildSpawnArgs, parseStreamJsonResult,
 *     readIndex, addToIndex, removeFromIndex, subagentScopeName, etc.
 *   IO — integration-only:
 *     installStubSub, listSubagents, invokeSubagent (spawns child claude).
 */

import { mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createHash, randomUUID, randomBytes } from 'node:crypto';

// ── Pure layer ───────────────────────────────────────────────────────────

/**
 * Scope name for a subagent installed under `parentScope`.
 * `main` + slug `echobot` → `main-echobot`. Used as `LASTID_AGENT_SCOPE` on
 * the spawned claude process so the subagent's plugin state writes to a
 * sibling scope dir without colliding with the parent's.
 */
export function subagentScopeName(parentScope, slug) {
  if (!parentScope || !slug) throw new Error('subagentScopeName: parentScope + slug required');
  return `${parentScope}-${slug}`;
}

/** ULID-ish opaque id for a subagent record. Crockford-base32, 26 chars. */
export function makeSubagentId() {
  // Simple ULID-ish: time-prefixed random. Good enough for a local id.
  const t = Date.now().toString(36).toUpperCase().padStart(10, '0');
  const r = randomBytes(10).toString('hex').toUpperCase().slice(0, 16);
  return `${t}${r}`.padEnd(26, '0').slice(0, 26);
}

/**
 * Parse an agent.md file: frontmatter (YAML between `---` fences) + body.
 * Minimal YAML — we only need flat scalars + nested objects/lists; not
 * pulling a full YAML lib in for tonight. The frontmatter we write is
 * deterministic JSON-shaped, so this parser is intentionally tight.
 */
export function parseAgentMd(raw) {
  if (typeof raw !== 'string') throw new Error('parseAgentMd: string required');
  const lines = raw.split('\n');
  if (lines[0]?.trim() !== '---') {
    throw new Error('agent.md missing leading `---` frontmatter fence');
  }
  let endIdx = -1;
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '---') {
      endIdx = i;
      break;
    }
  }
  if (endIdx < 0) throw new Error('agent.md missing closing `---` frontmatter fence');
  const fmRaw = lines.slice(1, endIdx).join('\n');
  // We round-trip JSON-shaped frontmatter (see formatAgentMd) — accept a
  // YAML-flavored block by trying JSON first, then a tiny ad-hoc parse for
  // top-level `key: value` scalars when JSON fails.
  let frontmatter;
  try {
    frontmatter = JSON.parse(fmRaw);
  } catch {
    frontmatter = parseMinimalYaml(fmRaw);
  }
  const body = lines.slice(endIdx + 1).join('\n').replace(/^\n+/, '').replace(/\n+$/, '\n');
  return { frontmatter, body };
}

/**
 * Format an agent.md from frontmatter + body. We deliberately serialize the
 * frontmatter as JSON (with the `---` fences) — Claude Code's native loader
 * accepts both YAML and JSON-shaped frontmatter, and JSON gives us
 * deterministic, easy-to-canonicalize bytes for signing later without pulling
 * in a YAML library.
 */
export function formatAgentMd(frontmatter, body) {
  const fmJson = JSON.stringify(frontmatter, null, 2);
  return `---\n${fmJson}\n---\n${body.replace(/\n+$/, '')}\n`;
}

/**
 * Tiny YAML reader: supports `key: scalar` and `key:` followed by `- item`
 * list lines, indented 2 spaces, top-level only. We use this as the fallback
 * when the frontmatter isn't JSON — robust enough to accept hand-edited
 * agent.md files but not a full YAML implementation.
 */
function parseMinimalYaml(text) {
  const out = {};
  let currentList = null;
  for (const lineRaw of text.split('\n')) {
    const line = lineRaw.replace(/\s+$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (line.startsWith('  - ')) {
      if (currentList) currentList.push(parseScalar(line.slice(4)));
      continue;
    }
    const m = line.match(/^([a-zA-Z_][\w]*):\s*(.*)$/);
    if (!m) continue;
    const [, key, rest] = m;
    if (rest === '') {
      currentList = [];
      out[key] = currentList;
    } else {
      currentList = null;
      out[key] = parseScalar(rest);
    }
  }
  return out;
}

function parseScalar(raw) {
  const s = raw.trim();
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  if (s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  if (s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1);
  return s;
}

/**
 * Build the spawn argv + env for invoking a subagent. PURE — given a
 * subagent record + options, produce exactly the command shape we'll exec.
 * Tested without actually spawning anything.
 *
 * SECURITY — input is intentionally NOT in argv: it's piped to stdin by
 * invokeSubagent. The earlier shape (`args.push(input)`) had two problems:
 *   1. ARGV FLAG SMUGGLING — an attacker-controlled input starting with `-`
 *      would have been parsed as a claude CLI flag (e.g. an input of
 *      "--dangerously-skip-permissions" would have flipped that flag on).
 *      Even with an end-of-options `--` sentinel some shells / claude
 *      versions don't honor it strictly enough to rely on.
 *   2. RELIABILITY — claude --print intermittently errors with "Input must
 *      be provided either through stdin or as a prompt argument" on a
 *      positional input depending on argv-parser quirks (caught via smoke
 *      test). Stdin works in every case.
 * Defense-in-depth: handlePluginTool's input validator also rejects strings
 * starting with `-` at the boundary, in case a future refactor reintroduces
 * a positional path before this comment gets read.
 */
export function buildSpawnArgs({ subagent, systemPromptPath, parentEnv }) {
  const args = [
    '--print',
    '--verbose',
    '--system-prompt-file',
    systemPromptPath,
    '--output-format',
    'stream-json',
  ];
  const allowed = subagent.claude_tools?.allowed;
  const disallowed = subagent.claude_tools?.disallowed;
  if (Array.isArray(allowed) && allowed.length > 0) {
    args.push('--allowed-tools', allowed.join(','));
  }
  if (Array.isArray(disallowed) && disallowed.length > 0) {
    args.push('--disallowed-tools', disallowed.join(','));
  }
  return {
    cmd: 'claude',
    args,
    env: { ...(parentEnv ?? {}), LASTID_AGENT_SCOPE: subagent.scope },
  };
}

/**
 * Walk the stream-json stdout, find the terminal `{type:'result', ...}`
 * event, and return a structured result. PURE — given the raw stdout
 * string, return what the parent's MCP tool returns to its caller.
 */
export function parseStreamJsonResult(stdout) {
  const lines = String(stdout ?? '').split('\n').filter((l) => l.trim().length > 0);
  let final = null;
  for (const line of lines) {
    let evt;
    try {
      evt = JSON.parse(line);
    } catch {
      continue;
    }
    if (evt?.type === 'result') {
      final = evt;
      // last 'result' wins (there should be only one but be defensive)
    }
  }
  if (!final) {
    return { ok: false, error: 'no_result_event', text: '' };
  }
  if (final.is_error === true) {
    return { ok: false, error: final.result ?? 'subagent_error', text: String(final.result ?? '') };
  }
  return { ok: true, error: null, text: String(final.result ?? '') };
}

/** sha256 hex of a UTF-8 string. */
export function sha256Hex(s) {
  return createHash('sha256').update(String(s ?? ''), 'utf-8').digest('hex');
}

// ── Index management (pure-ish, fs-backed) ──────────────────────────────

const INDEX_VERSION = 1;

function homeDir() {
  return homedir();
}

function scopeDirFor(scope) {
  return join(homeDir(), '.lastid-agent', scope);
}

function indexPathFor(parentScope) {
  return join(scopeDirFor(parentScope), 'subagents.json');
}

/** Read the parent's subagents index. Empty `{}` map if missing/malformed. */
export async function readIndex(parentScope) {
  try {
    const raw = await readFile(indexPathFor(parentScope), 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && parsed.subagents && typeof parsed.subagents === 'object') {
      return parsed.subagents;
    }
    return {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    return {};
  }
}

/**
 * Add/update a subagent entry in the parent's index. Creates the index file
 * (and parent scope dir) if missing. Returns the new index map.
 */
export async function addToIndex(parentScope, entry) {
  if (!entry || !entry.slug) throw new Error('addToIndex: entry.slug required');
  const map = await readIndex(parentScope);
  map[entry.slug] = entry;
  const path = indexPathFor(parentScope);
  await mkdir(scopeDirFor(parentScope), { recursive: true });
  await writeFile(path, `${JSON.stringify({ version: INDEX_VERSION, subagents: map }, null, 2)}\n`, 'utf-8');
  return map;
}

/** Remove a slug from the parent's index. No-op if missing. */
export async function removeFromIndex(parentScope, slug) {
  const map = await readIndex(parentScope);
  if (!map[slug]) return map;
  delete map[slug];
  const path = indexPathFor(parentScope);
  await writeFile(path, `${JSON.stringify({ version: INDEX_VERSION, subagents: map }, null, 2)}\n`, 'utf-8');
  return map;
}

// ── IO layer ────────────────────────────────────────────────────────────

/**
 * Install a subagent locally in stub mode (no IdP, no signature). Writes the
 * sub-scope dir + agent.md + updates the parent's index. Returns the entry
 * that was written.
 */
export async function installStubSub({
  parentScope,
  slug,
  name,
  body,
  claudeTools,
  mcpAllowed,
  mode,
  id,
}) {
  if (!parentScope) throw new Error('installStubSub: parentScope required');
  if (!slug || !/^[a-z][a-z0-9_-]*$/.test(slug)) {
    throw new Error('installStubSub: slug must be lowercase letters/digits/-/_ starting with a letter');
  }
  if (!name || typeof name !== 'string') throw new Error('installStubSub: name required');
  if (!body || typeof body !== 'string') throw new Error('installStubSub: body required');

  const subScope = subagentScopeName(parentScope, slug);
  const subScopeDir = scopeDirFor(subScope);
  await mkdir(subScopeDir, { recursive: true });

  const frontmatter = {
    lastid_version: 1,
    id: typeof id === 'string' && id.length > 0 ? id : makeSubagentId(),
    name,
    slug,
    parent_scope: parentScope,
    mode: mode === 'published' ? 'published' : 'stub',
    created_at: new Date().toISOString(),
    claude_tools: {
      allowed: Array.isArray(claudeTools?.allowed) ? claudeTools.allowed : [],
      disallowed: Array.isArray(claudeTools?.disallowed) ? claudeTools.disallowed : [],
    },
    mcp_allowed: Array.isArray(mcpAllowed) ? mcpAllowed : [],
  };
  const agentMdPath = join(subScopeDir, 'agent.md');
  await writeFile(agentMdPath, formatAgentMd(frontmatter, body), 'utf-8');

  const entry = {
    slug,
    name,
    scope: subScope,
    mode: frontmatter.mode,
    id: frontmatter.id,
    agent_md_path: agentMdPath,
    body_sha256: sha256Hex(body),
    installed_at: frontmatter.created_at,
    claude_tools: frontmatter.claude_tools,
    mcp_allowed: frontmatter.mcp_allowed,
  };
  await addToIndex(parentScope, entry);
  return entry;
}

/**
 * Apply one decoded `subagent`-kind agent-state record locally. Called by
 * agent-state-sync's dispatch loop when a `subagent.changed` doorbell brings
 * down records sealed by the operator's console — this is the doorbell-driven
 * install rail (operator never touches a CLI).
 *
 * Record content shape (set by lastid.co publishSubagent):
 *   { slug, name, body, claude_tools: { allowed[], disallowed[] }, mcp_allowed[] }
 *
 * Active → write the sub-scope's agent.md + add to the parent's index.
 * Revoked → remove the index entry + delete the scope dir (best-effort).
 *
 * Parent scope = the scope running this sync (the listener owns its own scope,
 * and a subagent published TO this agent slots under it). We do NOT trust a
 * `parent_scope` field in the content — the receiving listener IS the parent
 * by definition, so trust the listener's own scope.
 */
export async function applySubagentRecord({ scope, storeRecord }) {
  if (!scope) throw new Error('applySubagentRecord: scope required');
  if (!storeRecord || typeof storeRecord !== 'object') {
    throw new Error('applySubagentRecord: storeRecord required');
  }
  const status = storeRecord.status ?? 'active';
  const content = storeRecord.content ?? {};
  const slug = typeof content.slug === 'string' ? content.slug : null;
  if (!slug || !/^[a-z][a-z0-9_-]*$/.test(slug)) {
    throw new Error('applySubagentRecord: content.slug missing or malformed');
  }
  if (status === 'revoked') {
    // Idempotent: uninstall returns not_found if it's already gone.
    return uninstallSub({ parentScope: scope, slug });
  }
  // Active — install or refresh.
  const name = typeof content.name === 'string' && content.name.length > 0 ? content.name : slug;
  const body = typeof content.body === 'string' ? content.body : '';
  if (body.length === 0) {
    throw new Error('applySubagentRecord: content.body required for active record');
  }
  const claudeTools = content.claude_tools ?? {};
  const allowed = Array.isArray(claudeTools.allowed) ? claudeTools.allowed : [];
  const disallowed = Array.isArray(claudeTools.disallowed) ? claudeTools.disallowed : [];
  const mcpAllowed = Array.isArray(content.mcp_allowed) ? content.mcp_allowed : [];

  // Reuse the stub-install path so a console-published subagent lands at the
  // same on-disk shape (~/.lastid-agent/<parent>-<slug>/agent.md + the parent's
  // subagents.json) as a dev-installed stub. installStubSub is idempotent
  // (writes over the existing agent.md + updates the index entry in place).
  return installStubSub({
    parentScope: scope,
    slug,
    name,
    body,
    claudeTools: { allowed, disallowed },
    mcpAllowed,
    mode: 'published',
    id: typeof storeRecord.id === 'string' && storeRecord.id.length > 0 ? storeRecord.id : null,
  });
}

/** Uninstall a subagent: remove from index, delete its scope dir. */
export async function uninstallSub({ parentScope, slug }) {
  const map = await readIndex(parentScope);
  const entry = map[slug];
  if (!entry) return { ok: false, error: 'not_found' };
  await removeFromIndex(parentScope, slug);
  try {
    await rm(scopeDirFor(entry.scope), { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
  return { ok: true, removed: entry };
}

/** List subagents installed under a parent scope. */
export async function listSubagents(parentScope) {
  const map = await readIndex(parentScope);
  return Object.values(map).sort((a, b) => a.slug.localeCompare(b.slug));
}

/**
 * Spawn the subagent and capture its result. Streams stdout, writes the
 * final body to memory, returns a structured result. Times out via SIGTERM
 * + falls back to SIGKILL after a grace period.
 */
export async function invokeSubagent({
  parentScope,
  slug,
  input,
  timeoutMs = 5 * 60_000,
  parentEnv = process.env,
  log,
}) {
  if (typeof input !== 'string' || input.length === 0) {
    return { ok: false, error: 'input_required', text: '' };
  }
  const map = await readIndex(parentScope);
  const entry = map[slug];
  if (!entry) {
    return { ok: false, error: 'not_found_or_revoked', text: '' };
  }

  // Read the on-disk agent.md, extract the body to a tempfile so we can pass
  // it via --system-prompt-file (predictable, no shell-quoting hazards).
  let parsed;
  try {
    const raw = await readFile(entry.agent_md_path, 'utf-8');
    parsed = parseAgentMd(raw);
  } catch (err) {
    return { ok: false, error: `agent_md_unreadable: ${err.message ?? err}`, text: '' };
  }
  const sysPromptPath = join(tmpdir(), `lastid-subagent-${randomUUID()}.md`);
  await writeFile(sysPromptPath, parsed.body, 'utf-8');

  const subagent = {
    slug: entry.slug,
    scope: entry.scope,
    claude_tools: entry.claude_tools,
  };
  const { cmd, args, env } = buildSpawnArgs({
    subagent,
    systemPromptPath: sysPromptPath,
    parentEnv,
  });

  const invocationId = randomUUID();
  const startedAt = Date.now();
  if (typeof log === 'function') {
    log(`[lastid-agent] subagent invoke ${slug} → scope=${subagent.scope} input_sha256=${sha256Hex(input).slice(0, 12)}…`);
  }

  const result = await new Promise((resolve) => {
    // stdio: ['pipe', 'pipe', 'pipe'] — input rides stdin (NOT argv: see the
    // SECURITY comment on buildSpawnArgs above for why).
    const child = spawn(cmd, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer = null;

    const settle = (val) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(val);
    };

    child.stdout.on('data', (b) => { stdout += b.toString('utf-8'); });
    child.stderr.on('data', (b) => { stderr += b.toString('utf-8'); });

    // Write the prompt to stdin and close — claude --print reads stdin
    // until EOF, then runs a single turn.
    try {
      child.stdin.end(input, 'utf-8');
    } catch (err) {
      // If stdin write fails for any reason, treat as a spawn error.
      settle({ ok: false, error: `stdin_write_failed: ${err?.message ?? err}`, text: '', exit_code: -1, stderr_tail: '' });
      return;
    }

    child.on('error', (err) => {
      settle({ ok: false, error: `spawn_error: ${err.message ?? err}`, text: '', exit_code: -1, stderr });
    });

    child.on('close', (exitCode) => {
      const parsed = parseStreamJsonResult(stdout);
      settle({
        ok: parsed.ok && exitCode === 0,
        error: parsed.ok ? null : parsed.error,
        text: parsed.text,
        exit_code: exitCode,
        stderr_tail: stderr.slice(-2000),
      });
    });

    timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* */ }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } }, 3_000);
      // Don't settle yet — let close fire with the partial stdout so we
      // can return whatever the subagent emitted before it was killed.
    }, timeoutMs);
  });

  // Cleanup temp system prompt file (best-effort).
  try { await rm(sysPromptPath, { force: true }); } catch { /* */ }

  const durationMs = Date.now() - startedAt;
  return {
    ...result,
    duration_ms: durationMs,
    audit: {
      invocation_id: invocationId,
      subagent_id: entry.id,
      sub_scope: entry.scope,
      parent_scope: parentScope,
      input_sha256: sha256Hex(input),
      output_sha256: sha256Hex(result.text),
      started_at: new Date(startedAt).toISOString(),
      completed_at: new Date(startedAt + durationMs).toISOString(),
    },
  };
}
