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

import { mkdir, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir, tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createHash, randomUUID, randomBytes } from 'node:crypto';

// Absolute path to the plugin's own MCP server entry. Resolved at
// load time from this module's location so it's stable across cwd
// changes. We pass this into the spawned subagent's --mcp-config so
// the child Claude Code session gets the SAME lastid-agent MCP
// server the parent has — capabilities + rules + vault all enforced
// uniformly. See `mcpConfigForSubagent` below.
const PLUGIN_MCP_SERVER_PATH = fileURLToPath(
  new URL('../bin/lastid-agent.js', import.meta.url),
);

// Plugin bin dir. Prepended to the spawned helper's PATH so `lastid-agent`
// resolves to bin/lastid-agent (the bash wrapper that execs node on the .js
// entrypoint). Without this, a helper that explicitly invokes `lastid-agent
// run --item <id> -- aws ...` (rather than letting the PreToolUse rewrite
// transparently wrap a bare `aws ...`) hits exit 127 — the rewrite uses an
// absolute `node /path/lastid-agent.js` form, but an explicit invocation in
// the helper's shell needs the binary on PATH. Belt-and-suspenders.
const PLUGIN_BIN_DIR = fileURLToPath(new URL('../bin/', import.meta.url));

// Plugin root dir — used to substitute `${CLAUDE_PLUGIN_ROOT}` in the hooks
// definitions we inject into the helper's --settings. Without this the
// plugin's hooks (PreToolUse credential-CLI rewrite, SessionStart, etc.)
// don't fire in the helper's headless session: hooks ride settings.json,
// not --mcp-config, and the spawn previously passed an inline settings
// object with permissions/autoMode but NO hooks at all. Result: every
// bare `aws ...` (and `gh ...`, `psql ...`) call from a sub-agent went
// un-rewritten and failed with "Unable to locate credentials", forcing
// the helper to remember the explicit `lastid-agent run --item ...` form.
const PLUGIN_ROOT = fileURLToPath(new URL('..', import.meta.url));
const PLUGIN_HOOKS_JSON_PATH = fileURLToPath(
  new URL('../hooks/hooks.json', import.meta.url),
);

/**
 * Load the plugin's hooks.json and substitute `${CLAUDE_PLUGIN_ROOT}` with
 * the absolute plugin root path. Pure function; the path is exposed for
 * tests to point at a fixture. Returns the `hooks` object (the value at
 * the top-level `.hooks` key) or null if anything goes wrong — a missing
 * or malformed hooks.json must NEVER block subagent spawning, since the
 * cli-rewrite is an optimization and the helper can always fall back to
 * the explicit `lastid-agent run` form.
 */
export function loadPluginHooksForSpawn(hooksJsonPath = PLUGIN_HOOKS_JSON_PATH, pluginRoot = PLUGIN_ROOT) {
  try {
    const raw = readFileSync(hooksJsonPath, 'utf-8');
    const parsed = JSON.parse(raw);
    const hooks = parsed?.hooks;
    if (!hooks || typeof hooks !== 'object') return null;
    // Recursively replace `${CLAUDE_PLUGIN_ROOT}` literal in command strings.
    // Plugin's own hooks reference it because Claude Code expands it at hook-
    // dispatch time; when we hoist them into a spawned helper's settings.json
    // payload, Claude Code WON'T expand it (no plugin context for this child
    // session) — so we expand to the absolute path here.
    const substitute = (value) => {
      if (typeof value === 'string') return value.replaceAll('${CLAUDE_PLUGIN_ROOT}', pluginRoot);
      if (Array.isArray(value)) return value.map(substitute);
      if (value && typeof value === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(value)) out[k] = substitute(v);
        return out;
      }
      return value;
    };
    return substitute(hooks);
  } catch {
    return null;
  }
}

/**
 * Universal runtime-rules suffix appended to EVERY spawned helper's
 * system prompt by invokeSubagent. Owns the rules that are the same for
 * any helper any operator builds — credential handling, audit
 * attribution, and (when background) the lastid_progress directive —
 * so operators don't have to re-state them in every helper.md.
 *
 * Mirrors the credential + audit lines the parent's SessionStart hook
 * (hooks/session-start.js buildOperatingContext) emits, kept slim for
 * the helper case: no identity card (loaded separately via
 * lastid_whoami), no memory guidance (helper-specific), no parent's
 * sub-agent-spawning notes (irrelevant to a leaf helper).
 *
 * PURE. Tested directly in subagents.test.js.
 */
export function formatHelperRuntimeRules({ background = false } = {}) {
  const lines = [
    '---',
    '',
    '## How credentials work here (universal — applies to every operator-shared item)',
    '',
    'The operator may share vault items with you (API keys, OAuth tokens,',
    'basic-auth credentials). You will NEVER see the underlying credential',
    'value. There are two paths the operator may have configured for each',
    'share — `vault_list` tells you which:',
    '',
    '**CLI proxy (preferred for tools that have a CLI)** — the share has',
    '`binaries: [...]` set in its `vault_list` metadata. Run the binary',
    'through the proxy via Bash explicitly:',
    '',
    '    lastid-agent run --item <item_id> -- aws s3 ls',
    '    lastid-agent run --item <item_id> -- gh pr view 123',
    '    lastid-agent run --item <item_id> -- psql -c "select 1"',
    '',
    'The proxy mints a single-use handle, asks the listener to spawn',
    'your command with the credential injected as env vars in the child,',
    'and streams the (scrubbed) stdout back. The secret never enters',
    'your context AND never enters your tool-call inputs. You MUST',
    'invoke `lastid-agent run` explicitly — calling `aws s3 ls` directly',
    'won\'t be auto-rewritten in your session and will fail with',
    'unauthorized credentials. Use this whenever the share lists',
    '`binaries` and the target tool has a CLI.',
    '',
    '**HTTP injection (when there\'s no CLI, or the share lacks `binaries`)**:',
    '1. `vault_list` — discover items the operator has shared with you.',
    '   You see titles, services, hosts, granted actions, and injection',
    '   metadata. You do NOT see the credential value.',
    '2. `vault_use(item_id)` — mint a single-use, short-lived (5 min)',
    '   opaque handle for a specific item. The response includes an',
    '   "injection summary" telling you how the credential will be',
    '   attached (header, bearer, query param, basic auth, oauth_bearer).',
    '3. `http_fetch(url, vault_handle)` — make the outbound request.',
    '   The listener unfurls the handle at the network boundary, attaches',
    '   the credential per the injection summary, and returns the response.',
    '   The credential value never enters your context window.',
    '',
    'Rules you MUST follow:',
    '- Never fabricate, guess, or paste a credential value. You do not have',
    '  one to paste.',
    '- If a task requires a credential not in `vault_list`, tell the parent',
    '  exactly which item you need (service + purpose) and stop. Do NOT',
    '  fall back to environment variables, do NOT read files, do NOT',
    '  improvise.',
    '- Handles are single-use. Mint a fresh handle per request via',
    '  `vault_use` — do not try to reuse one.',
    '- If a credential-related error (401, 403) comes back, report it. Do',
    '  not silently retry with a different credential.',
    '',
    '## What lands in the audit chain',
    '',
    'Every tool call you make appends a record to the operator\'s blake3-',
    'linked, device-key-signed audit chain — attributed to YOUR DID, not',
    'your parent\'s. The chain records the tool name, input shape, result,',
    'and key metadata (item_id, url host, response status, injection',
    'kind). The operator views this in the desktop\'s Agents → Activity',
    'tab. Be precise + intentional — your actions are evidence under your',
    'own identity.',
    '',
    '## You have NO back-channel — return questions, never guess',
    '',
    'You are a ONE-SHOT session: your parent passed you an `input` and will',
    'receive back ONLY your final message. You cannot ask the parent a',
    'question and wait for a reply mid-task — there is no such channel.',
    '',
    '- If the input is clear enough to act on, do the work and return a tight',
    '  result.',
    '- If you genuinely CANNOT proceed without a decision only the parent or',
    '  operator can make — an ambiguous target, missing input, a risky/',
    '  destructive choice, or a credential not in `vault_list` — do NOT guess',
    '  and do NOT do a best-effort-and-hope. STOP and RETURN your question(s)',
    '  as your result: begin the message with `NEEDS INPUT:`, list each',
    '  question, and for each say what you would do under each plausible',
    '  answer. The parent re-invokes you with the answer folded into a new',
    '  `input`.',
    '',
    'A crisp returned question beats a wrong guess: a wrong guess wastes the',
    'round-trip AND may take the wrong action under your own identity.',
  ];
  if (background) {
    lines.push(
      '',
      '## Background-mode progress directive',
      '',
      'You are running as a BACKGROUNDED sub-agent. Your parent gets a',
      'single completion notification when you finish, otherwise silence.',
      'Call `lastid_progress({stage: "..."})` BEFORE each step that might',
      'take more than ~2 seconds — a tool call you\'re about to make, a',
      'chunk of analysis, a network round-trip. Each call becomes a real-',
      'time push to the parent so they know what you\'re doing. Keep stages',
      'to one short verb-led phrase ("reading wallet.ts", "running test',
      'suite", "summarizing diff"). This is liveness, not narration — one',
      'stage per real step, not per thought.',
    );
  }
  return lines.join('\n');
}

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
export function buildSpawnArgs({ subagent, systemPromptPath, parentEnv, mcpConfigPath, invocationContext }) {
  const args = [
    '--print',
    '--verbose',
    '--system-prompt-file',
    systemPromptPath,
    '--output-format',
    'stream-json',
  ];
  // MCP injection: when the caller wrote a one-off .mcp.json (the live
  // invoke path), inject ONLY the lastid-agent server — no operator-
  // machine MCP bleed. `--strict-mcp-config` makes the child ignore
  // any other .mcp.json that might be discovered up the tree. Result:
  // the subagent has the SAME LastID tool surface its parent does
  // (vault_use, http_fetch, lastid_memory_*, lastid_send_message,
  // lastid_invoke_subagent if may_delegate), all capability-gated by
  // its own VC. Without this the subagent sees only Claude built-ins.
  if (typeof mcpConfigPath === 'string' && mcpConfigPath.length > 0) {
    args.push('--mcp-config', mcpConfigPath, '--strict-mcp-config');
  }
  // ALWAYS whitelist the lastid-agent MCP server through BOTH gates that
  // can block our own tool calls in a spawned helper:
  //
  //   1) permissions.allow with `mcp__lastid-agent` — Claude Code's MCP
  //      rule syntax for "all tools from this server" (per the
  //      permissions docs § MCP). Without this, the helper hits a
  //      permission prompt that headless can't answer.
  //
  //   2) autoMode.allow — Claude Code's auto-mode classifier is a SECOND
  //      gate that runs AFTER permissions and natural-language-denies
  //      calls it flags as exfiltration / credential exploration. It's
  //      tuned by prose entries, not regex; we add an explicit "trust
  //      this MCP server" line so vault_list / vault_use / http_fetch /
  //      lastid_progress stop tripping it. Without this, log-diver got
  //      "wrapped in a classifier-bypass narrative" denials even after
  //      we added permissions.allow (2026-05-28).
  //
  // Both ride a single --settings JSON object — Claude Code accepts
  // inline JSON for --settings, so no extra tempfile.
  //
  // CLI flag is --allowedTools (camelCase), NOT --allowed-tools (kebab-
  // case). The kebab form is silently a no-op in current Claude Code,
  // which is why the v0.19.x rounds didn't bypass either gate.
  const allowed = [
    'mcp__lastid-agent',
    ...(Array.isArray(subagent.claude_tools?.allowed) ? subagent.claude_tools.allowed : []),
  ];
  const disallowed = subagent.claude_tools?.disallowed;
  args.push('--allowedTools', allowed.join(','));
  if (Array.isArray(disallowed) && disallowed.length > 0) {
    args.push('--disallowedTools', disallowed.join(','));
  }
  const settingsInline = {
    permissions: {
      allow: allowed.map((t) => t),
    },
    autoMode: {
      allow: [
        '$defaults',
        // Prose-language entry for the auto-mode classifier — describe
        // why the lastid-agent MCP server is trusted infrastructure so
        // the classifier stops treating vault_list / vault_use / http_
        // fetch / lastid_progress as "credential exploration".
        "Trusted MCP server `lastid-agent`: this is the LastID Agent plugin's own MCP server, providing capability-gated vault access (vault_list, vault_use, http_fetch), memory (lastid_memory_*), messaging (lastid_send_message), and progress reporting (lastid_progress). The LastID layer enforces operator-granted VC capabilities at runtime; the agent cannot escalate beyond what its VC permits. Tools from mcp__lastid-agent are routine internal operations, NOT credential exfiltration or third-party calls.",
      ],
    },
  };
  // Inject the plugin's hooks (with `${CLAUDE_PLUGIN_ROOT}` resolved to an
  // absolute path) so the helper's headless session gets the SAME hook
  // surface the parent has — most importantly the PreToolUse CLI rewrite
  // that turns a bare `aws ...` into the credential-injected `lastid-agent
  // run --item ...` form. Without this the helper has to remember the
  // explicit form on every CLI call. Falls back gracefully (no hooks) on a
  // missing/malformed hooks.json — the helper can still proceed using the
  // explicit form.
  const pluginHooks = loadPluginHooksForSpawn();
  if (pluginHooks) {
    settingsInline.hooks = pluginHooks;
  }
  args.push('--settings', JSON.stringify(settingsInline));
  // Invocation context: when this spawn is BACKGROUNDED (the parent passed
  // invocationContext), inject the invocation_id + parent_scope so the child's
  // lastid_progress tool can write progress entries to the parent's per-
  // invocation state file. Foreground invokes don't need this — the parent's
  // own MCP call is awaiting the result anyway. Without this, lastid_progress
  // would have no anchor to write against and would no-op silently.
  const envExtra = { LASTID_AGENT_SCOPE: subagent.scope };
  if (invocationContext) {
    envExtra.LASTID_SUBAGENT_INVOCATION_ID = invocationContext.invocationId;
    envExtra.LASTID_SUBAGENT_PARENT_SCOPE = invocationContext.parentScope;
  }
  // Prepend the plugin's bin dir to PATH so the helper's Bash resolves
  // `lastid-agent` to bin/lastid-agent (the bash wrapper around the .js
  // entrypoint). The PreToolUse hook rewrites a bare `aws ...` to a full
  // `node <abs>/lastid-agent.js run --item ... -- aws ...` form which
  // doesn't need PATH; but a helper that calls `lastid-agent run ...`
  // explicitly does. Prepending (not appending) wins over any stale system
  // entry; we keep the rest of parentEnv.PATH so node, aws, gh, etc. still
  // resolve. PATH-less environments (no `path` from parent) get just our
  // bin so the binary is still reachable.
  const parentPath = parentEnv?.PATH ?? parentEnv?.Path ?? '';
  envExtra.PATH = parentPath ? `${PLUGIN_BIN_DIR}:${parentPath}` : PLUGIN_BIN_DIR;
  return {
    cmd: 'claude',
    args,
    env: { ...(parentEnv ?? {}), ...envExtra },
  };
}

/**
 * Return the in-memory `.mcp.json` content that registers ONLY the
 * lastid-agent MCP server, pointed at this plugin's own server entry.
 * `invokeSubagent` writes this to a tempfile and passes the path to
 * `claude --mcp-config`; with `--strict-mcp-config` the child sees
 * exactly this server + nothing else (no ambient operator config).
 *
 * The plugin's own `.mcp.json` uses `${CLAUDE_PLUGIN_ROOT}` for
 * portability; we resolve it absolutely here (PLUGIN_MCP_SERVER_PATH)
 * so the spawned child doesn't need that env var set.
 */
export function mcpConfigForSubagent({ invocationContext } = {}) {
  // The MCP server process is spawned BY Claude Code (not by us), so the
  // env we set on the `claude` child doesn't propagate into the MCP
  // server's process. To pass invocation context (so lastid_progress
  // knows which state file to append to), bake the values into the
  // mcp.json's per-server `env` field. Without this, lastid_progress
  // sees the env vars unset and silently no-ops with
  // recorded:false — the bug log-diver hit 2026-05-28.
  const env = invocationContext
    ? {
        LASTID_SUBAGENT_INVOCATION_ID: invocationContext.invocationId,
        LASTID_SUBAGENT_PARENT_SCOPE: invocationContext.parentScope,
      }
    : undefined;
  return {
    mcpServers: {
      'lastid-agent': {
        command: 'node',
        args: [PLUGIN_MCP_SERVER_PATH, 'serve'],
        type: 'stdio',
        ...(env ? { env } : {}),
      },
    },
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
  capabilities,
  mayDelegate,
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

  // Capabilities are the OPERATOR-PICKED contract — the IdP issues a VC with
  // exactly these. Persisted on the index so a later listener restart can
  // replay them verbatim via selfHealSubagents (no defaults, no zeroing).
  const normalizedCapabilities = Array.isArray(capabilities) ? capabilities : [];
  const normalizedMayDelegate = mayDelegate === true;

  const frontmatter = {
    lastid_version: 1,
    id: typeof id === 'string' && id.length > 0 ? id : makeSubagentId(),
    name,
    slug,
    parent_scope: parentScope,
    mode: mode === 'published' ? 'published' : 'stub',
    created_at: new Date().toISOString(),
    capabilities: normalizedCapabilities,
    may_delegate: normalizedMayDelegate,
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
    capabilities: normalizedCapabilities,
    may_delegate: normalizedMayDelegate,
    // One-paragraph tagline extracted from the body — used by SessionStart's
    // subagent-awareness block to give the agent a "when to use this helper"
    // signal at a glance (parallel to credential-awareness rendering each
    // vault item's purpose). Capped so the operating context stays compact.
    brief: extractBrief(body),
    claude_tools: frontmatter.claude_tools,
    mcp_allowed: frontmatter.mcp_allowed,
  };
  await addToIndex(parentScope, entry);
  return entry;
}

/**
 * Pull a short, one-paragraph tagline out of the body for SessionStart
 * surfacing. Takes the first non-empty paragraph (up to the first blank
 * line) and caps at 280 chars on a word boundary. Falls back to empty
 * string when the body has no usable opening paragraph.
 */
export function extractBrief(body) {
  if (typeof body !== 'string') return '';
  const para = body.split(/\n\s*\n/, 1)[0]?.trim() ?? '';
  if (!para) return '';
  const single = para.replace(/\s+/g, ' ');
  if (single.length <= 280) return single;
  // Cut at the last word boundary before 280 to avoid mid-word truncation.
  const cut = single.slice(0, 280);
  const lastSp = cut.lastIndexOf(' ');
  return (lastSp > 200 ? cut.slice(0, lastSp) : cut).replace(/[,;:]?\s*$/, '') + '…';
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
  // For revoked records there is NO ciphertext (the IdP's tombstone path on
  // credential revoke carries only metadata + the slug in `tool` as plaintext
  // routing). Fall back to storeRecord.tool when content.slug is missing so
  // the IdP-cascaded revoke resolves to the right install. Active records
  // still require content.slug — they must arrive with ciphertext.
  const slug =
    (typeof content.slug === 'string' ? content.slug : null) ??
    (typeof storeRecord.tool === 'string' ? storeRecord.tool : null);
  if (!slug || !/^[a-z][a-z0-9_-]*$/.test(slug)) {
    throw new Error('applySubagentRecord: slug missing or malformed (content.slug or tool)');
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

  // Capabilities + may_delegate are the OPERATOR-PICKED contract — pass them
  // VERBATIM. Persisted on the index so the listener can replay them on
  // restart (selfHealSubagents) and so any future re-mint uses the exact
  // same set the operator chose. No defaults.
  const capabilities = Array.isArray(content.capabilities) ? content.capabilities : [];
  const mayDelegate = content.may_delegate === true;

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
    capabilities,
    mayDelegate,
    mode: 'published',
    id: typeof storeRecord.id === 'string' && storeRecord.id.length > 0 ? storeRecord.id : null,
  });
}

/** Uninstall a subagent: remove from index, delete its scope dir + wipe
 *  the sub-scope's keychain entries (slot_seed, project_root_seed, VC,
 *  agent_did, idp_url). Revoke means the sub-agent is GONE — no stranded
 *  identity material left behind in keychain or on disk. */
export async function uninstallSub({ parentScope, slug }) {
  const map = await readIndex(parentScope);
  const entry = map[slug];
  if (!entry) return { ok: false, error: 'not_found' };
  // Reap the sub-agent's listener daemon BEFORE deleting any state — a
  // daemon holding an open WS + writing to the scope dir would race the
  // rm and leave half-state behind. Best-effort; the daemon's own
  // parent-watchdog catches a missed reap on the next host event anyway.
  try {
    const { stopSubagentListener } = await import('./subagent-provisioning.js');
    await stopSubagentListener(entry.scope);
  } catch {
    /* best-effort */
  }
  // Wipe ALL keychain entries for the sub-scope (deleteAgentVc deletes
  // slot_seed, project_root_seed, slot_index, agent_did, vc, idp_url
  // under SERVICE_* keys for the given scope). Without this, the VC +
  // slot_seed + seeds linger in keychain after revoke. Best-effort —
  // a keychain miss on revoke is not a correctness failure (the entries
  // become orphan but harmless), but a clean revoke must not leak.
  try {
    const { deleteAgentVc } = await import('./keychain.js');
    await deleteAgentVc(entry.scope);
  } catch {
    /* best-effort */
  }
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

// ── Backgrounded-invocation state files ─────────────────────────────────
//
// Foreground invokes block the MCP call until the child Claude exits —
// fine for sub-second helpers, painful for 5-minute test runs that lock
// up the parent's whole conversation. Background mode writes a state file
// and detaches the child; the parent polls `lastid_subagent_result` or
// scans `lastid_subagent_list_running` to discover when it's done.
//
// Layout: `~/.lastid-agent/<parent-scope>/subagent-invocations/<id>.json`
// One file per invocation, atomically written (tmp+rename). Status field:
//   - 'running'   — child spawned, awaiting close
//   - 'completed' — child exited cleanly with structured result text
//   - 'errored'   — spawn / IO / timeout failure
// State files older than INVOCATION_RETENTION_MS get pruned opportunistically
// on every list call so the directory doesn't grow without bound.

const INVOCATION_RETENTION_MS = 24 * 60 * 60 * 1000; // 24h

function invocationsDirFor(parentScope) {
  return join(scopeDirFor(parentScope), 'subagent-invocations');
}

function invocationFilePath(parentScope, invocationId) {
  return join(invocationsDirFor(parentScope), `${invocationId}.json`);
}

async function writeInvocationState(parentScope, invocationId, state) {
  const file = invocationFilePath(parentScope, invocationId);
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.${randomBytes(4).toString('hex')}.tmp`;
  await writeFile(tmp, JSON.stringify(state, null, 2), 'utf-8');
  // rename is atomic on POSIX so a concurrent reader either sees the old
  // file or the new — never a half-written one. Important: a backgrounded
  // child may be writing the terminal state at the same moment the parent
  // polls for it.
  const { rename } = await import('node:fs/promises');
  await rename(tmp, file);
}

/**
 * Per-sub-scope file the parent writes BEFORE spawning a backgrounded
 * sub-agent, carrying the invocation context (invocationId + parent
 * scope). The child's lastid_progress tool reads this to find its
 * anchor — by sub-scope, NOT env vars, because Claude Code's MCP
 * server launcher filters arbitrary env (LASTID_AGENT_SCOPE survives,
 * arbitrary LASTID_SUBAGENT_* gets stripped — empirically 2026-05-28).
 * Sub-scope IS reachable: it's the spawned helper's working scope and
 * derivable from LASTID_AGENT_SCOPE which does propagate. The parent
 * deletes the file on terminal state so a future foreground invoke of
 * the same helper doesn't accidentally pick up a stale context.
 */
export function activeInvocationContextPath(subScope) {
  return join(scopeDirFor(subScope), 'active-invocation.json');
}

export async function writeActiveInvocationContext({ subScope, invocationId, parentScope }) {
  const p = activeInvocationContextPath(subScope);
  await mkdir(scopeDirFor(subScope), { recursive: true });
  const tmp = `${p}.${randomBytes(4).toString('hex')}.tmp`;
  await writeFile(tmp, JSON.stringify({ invocationId, parentScope }, null, 2), 'utf-8');
  const { rename } = await import('node:fs/promises');
  await rename(tmp, p);
}

export async function readActiveInvocationContext(subScope) {
  try {
    const raw = await readFile(activeInvocationContextPath(subScope), 'utf-8');
    const parsed = JSON.parse(raw);
    if (typeof parsed?.invocationId === 'string' && typeof parsed?.parentScope === 'string') {
      return { invocationId: parsed.invocationId, parentScope: parsed.parentScope };
    }
    return null;
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

export async function clearActiveInvocationContext(subScope) {
  try {
    await rm(activeInvocationContextPath(subScope), { force: true });
  } catch {
    /* best-effort */
  }
}

/**
 * Append a progress entry to a running backgrounded invocation's state
 * file. Called by the child sub-agent's `lastid_progress` MCP tool to
 * stream stage updates back to the parent without waiting on the
 * completion push — operator-facing equivalent of "still alive, here's
 * what I'm doing." Best-effort + IO-failure-tolerant: a write failure
 * just loses that one update; the next one re-reads fresh state. We
 * read-modify-write atomically (tmp + rename) so a parent poll mid-
 * append never observes a torn file.
 *
 * Bounded at MAX_PROGRESS_ENTRIES so a runaway child can't grow the
 * state file unbounded; older entries silently drop off the front when
 * the cap is hit — the operator sees the most recent N stages, which
 * is what matters for "is it stuck?".
 */
const MAX_PROGRESS_ENTRIES = 50;

export async function appendInvocationProgress({ parentScope, invocationId, stage, detail }) {
  if (!parentScope || !invocationId) {
    throw new Error('appendInvocationProgress: parentScope + invocationId required');
  }
  if (typeof stage !== 'string' || stage.length === 0) {
    throw new Error('appendInvocationProgress: stage required (non-empty string)');
  }
  const file = invocationFilePath(parentScope, invocationId);
  let state;
  try {
    state = JSON.parse(await readFile(file, 'utf-8'));
  } catch (err) {
    if (err && err.code === 'ENOENT') return; // unknown invocation — silent no-op
    throw err;
  }
  // Don't append once the invocation is terminal — a late tool call from
  // a still-finishing child shouldn't muddy the completed snapshot.
  if (state.status !== 'running') return;
  const entry = {
    stage,
    at: new Date().toISOString(),
    ...(typeof detail === 'string' && detail.length > 0 ? { detail } : {}),
  };
  const existing = Array.isArray(state.progress) ? state.progress : [];
  const next = existing.length >= MAX_PROGRESS_ENTRIES
    ? [...existing.slice(existing.length - MAX_PROGRESS_ENTRIES + 1), entry]
    : [...existing, entry];
  await writeInvocationState(parentScope, invocationId, { ...state, progress: next });
}

/**
 * Read a single backgrounded invocation's state file. Returns the parsed
 * JSON or null if the file is missing (id not known to this scope, or it
 * was pruned). Callers — the MCP `lastid_subagent_result` tool — use this
 * to surface the status + (when complete) text + audit metadata back to
 * the parent agent.
 */
export async function readSubagentInvocation({ parentScope, invocationId }) {
  if (!parentScope || !invocationId) {
    throw new Error('readSubagentInvocation: parentScope + invocationId required');
  }
  try {
    const raw = await readFile(invocationFilePath(parentScope, invocationId), 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * List backgrounded invocations under this parent. By default returns only
 * those with `status === 'running'` (the actionable "what's still pending"
 * surface). Opportunistically prunes terminal files older than
 * INVOCATION_RETENTION_MS so the directory stays bounded.
 */
export async function listRunningSubagentInvocations({ parentScope, includeAll = false } = {}) {
  if (!parentScope) {
    throw new Error('listRunningSubagentInvocations: parentScope required');
  }
  const dir = invocationsDirFor(parentScope);
  let entries;
  try {
    entries = await readdir(dir);
  } catch (err) {
    if (err && err.code === 'ENOENT') return [];
    throw err;
  }
  const cutoffMs = Date.now() - INVOCATION_RETENTION_MS;
  const out = [];
  for (const entry of entries) {
    if (!entry.endsWith('.json')) continue;
    const file = join(dir, entry);
    let state;
    try {
      state = JSON.parse(await readFile(file, 'utf-8'));
    } catch {
      continue;
    }
    const completedAt = state?.audit?.completed_at
      ? Date.parse(state.audit.completed_at)
      : null;
    const isTerminal = state?.status === 'completed' || state?.status === 'errored';
    // Prune terminal files older than retention. Best-effort — a failed rm
    // just means we try again on the next call.
    if (isTerminal && completedAt !== null && completedAt < cutoffMs) {
      rm(file, { force: true }).catch(() => {});
      continue;
    }
    if (includeAll || state?.status === 'running') {
      out.push(state);
    }
  }
  // Newest first — most-recently-started is usually what the parent wants.
  out.sort((a, b) => String(b.started_at ?? '').localeCompare(String(a.started_at ?? '')));
  return out;
}

/**
 * Spawn the subagent and capture its result. Streams stdout, writes the
 * final body to memory, returns a structured result. Times out via SIGTERM
 * + falls back to SIGKILL after a grace period.
 *
 * When `background: true`, returns immediately with
 * `{ status: 'running', invocation_id, ... }`; the child runs detached and
 * writes its terminal state to disk. The parent polls via
 * `readSubagentInvocation({invocationId})` or `listRunningSubagentInvocations`.
 */
export async function invokeSubagent({
  parentScope,
  slug,
  input,
  timeoutMs = 5 * 60_000,
  parentEnv = process.env,
  log,
  background = false,
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
  // Append a runtime-rules prelude to EVERY spawned helper's system
  // prompt: credential handling, audit attribution, and (when this is a
  // backgrounded invoke) the lastid_progress directive. These rules are
  // UNIVERSAL — the same for any helper any operator builds — so the
  // plugin owns them, not the helper.md. Operators shouldn't have to
  // re-explain vault semantics in every helper they author.
  const promptBody = `${parsed.body}\n\n${formatHelperRuntimeRules({ background })}`;
  await writeFile(sysPromptPath, promptBody, 'utf-8');

  // One-off .mcp.json registering ONLY the lastid-agent server — so
  // the spawned child sees the same MCP tool surface the parent has
  // (and nothing else, via --strict-mcp-config). Written next to the
  // system prompt; cleaned up below in the same finally-shaped path.
  // Allocate invocationId BEFORE writing the mcp.json — the background
  // path bakes the invocation_id + parent_scope INTO the mcp.json's per-
  // server env block so the MCP server child (spawned by Claude Code, not
  // by us) actually sees them. The spawn env on the `claude` process
  // doesn't propagate to MCP server stdio children, so this is the only
  // reliable channel for handing invocation context into lastid_progress.
  const invocationId = randomUUID();
  const startedAt = Date.now();
  const invocationContext = background ? { invocationId, parentScope } : undefined;

  const mcpConfigPath = join(tmpdir(), `lastid-subagent-mcp-${randomUUID()}.json`);
  await writeFile(
    mcpConfigPath,
    JSON.stringify(mcpConfigForSubagent({ invocationContext }), null, 2),
    'utf-8',
  );

  const subagent = {
    slug: entry.slug,
    scope: entry.scope,
    claude_tools: entry.claude_tools,
  };
  const { cmd, args, env } = buildSpawnArgs({
    subagent,
    systemPromptPath: sysPromptPath,
    mcpConfigPath,
    parentEnv,
    invocationContext,
  });
  if (typeof log === 'function') {
    log(`[lastid-agent] subagent invoke ${slug} → scope=${subagent.scope} input_sha256=${sha256Hex(input).slice(0, 12)}…${background ? ' (background)' : ''}`);
  }

  // ── Background path ──────────────────────────────────────────────────
  // Returns immediately with the invocation_id; the child runs detached
  // and writes its terminal state to disk. The parent polls via
  // `readSubagentInvocation` / `listRunningSubagentInvocations`. This is
  // the right shape for long helpers (test runs, builds) so the parent
  // conversation isn't blocked waiting on the MCP call.
  if (background) {
    const initialState = {
      status: 'running',
      invocation_id: invocationId,
      slug,
      subagent_id: entry.id,
      sub_scope: entry.scope,
      parent_scope: parentScope,
      input_sha256: sha256Hex(input),
      started_at: new Date(startedAt).toISOString(),
      timeout_ms: timeoutMs,
    };
    await writeInvocationState(parentScope, invocationId, initialState);
    // Drop a per-sub-scope context file the child's lastid_progress tool
    // reads to find its anchor. Done HERE (not in buildSpawnArgs) so the
    // file exists on disk before the child's MCP server boots + tries
    // to read it. Cleared in recordTerminal below so a future foreground
    // invoke of the same helper doesn't pick up stale context.
    await writeActiveInvocationContext({
      subScope: entry.scope,
      invocationId,
      parentScope,
    });

    const child = spawn(cmd, args, {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      // detached: child gets its own process group so it survives the
      // parent MCP call returning. unref() lets the parent event loop
      // exit independently.
      detached: true,
    });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (b) => { stdout += b.toString('utf-8'); });
    child.stderr.on('data', (b) => { stderr += b.toString('utf-8'); });

    try {
      child.stdin.end(input, 'utf-8');
    } catch (err) {
      // stdin write failure on background path is rare; record terminal
      // state + return so the operator sees the failure on poll.
      await writeInvocationState(parentScope, invocationId, {
        ...initialState,
        status: 'errored',
        ok: false,
        error: `stdin_write_failed: ${err?.message ?? err}`,
        text: '',
        exit_code: -1,
        stderr_tail: '',
        duration_ms: Date.now() - startedAt,
        audit: {
          ...initialState,
          output_sha256: sha256Hex(''),
          completed_at: new Date().toISOString(),
        },
      });
      try { child.kill('SIGKILL'); } catch { /* */ }
      return initialState;
    }

    // Terminal-state recorder shared between close + error + timeout.
    let terminalRecorded = false;
    const recordTerminal = async (val) => {
      if (terminalRecorded) return;
      terminalRecorded = true;
      const durationMs = Date.now() - startedAt;
      const finalState = {
        ...initialState,
        status: val.ok ? 'completed' : 'errored',
        ok: val.ok,
        error: val.error,
        text: val.text,
        exit_code: val.exit_code,
        stderr_tail: val.stderr_tail,
        duration_ms: durationMs,
        audit: {
          invocation_id: invocationId,
          subagent_id: entry.id,
          sub_scope: entry.scope,
          parent_scope: parentScope,
          input_sha256: sha256Hex(input),
          output_sha256: sha256Hex(val.text ?? ''),
          started_at: new Date(startedAt).toISOString(),
          completed_at: new Date(startedAt + durationMs).toISOString(),
        },
      };
      try {
        await writeInvocationState(parentScope, invocationId, finalState);
      } catch {
        /* best-effort — the file is the only place this lives, but the
           parent can still survive a failed write by polling and seeing
           the running state never advance + the child's PID gone. */
      }
      try { await rm(sysPromptPath, { force: true }); } catch { /* */ }
      try { await rm(mcpConfigPath, { force: true }); } catch { /* */ }
      // Clear the per-sub-scope context file so a future foreground invoke
      // of the same helper doesn't pick up this run's stale invocation_id.
      await clearActiveInvocationContext(entry.scope);
    };

    child.on('error', (err) => {
      recordTerminal({
        ok: false,
        error: `spawn_error: ${err.message ?? err}`,
        text: '',
        exit_code: -1,
        stderr_tail: stderr.slice(-2000),
      }).catch(() => {});
    });
    child.on('close', (exitCode) => {
      const parsed = parseStreamJsonResult(stdout);
      recordTerminal({
        ok: parsed.ok && exitCode === 0,
        error: parsed.ok ? null : parsed.error,
        text: parsed.text,
        exit_code: exitCode,
        stderr_tail: stderr.slice(-2000),
      }).catch(() => {});
    });

    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* */ }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } }, 3_000);
    }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();

    // Detach: parent event loop is free to exit even while the child runs.
    child.unref();

    return initialState;
  }

  // ── Foreground path (unchanged) ──────────────────────────────────────
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
  try { await rm(mcpConfigPath, { force: true }); } catch { /* */ }

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
