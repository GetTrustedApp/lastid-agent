/**
 * Local operator-state store — the agent's offline cache of the
 * operator's rules and memories.
 *
 * saas-migration.md §2.2/§2.3: the agent pulls slot_seed-encrypted
 * records from the IdP agent-state store, decrypts them with
 * agent-content-crypto, and applies them here. The hooks then read
 * THIS store first (desktop /policy/check + /memory/retrieve only as a
 * fallback), so the agent keeps enforcing rules and surfacing memory
 * with nothing else online.
 *
 * On disk: ~/.lastid-agent/<scope>/operator-state.json
 *   { version, cursor, records: { <id>: { id, kind, target, status,
 *     version, updated_at, content } } }
 * `content` is the already-decrypted record body (the sync client
 * decrypts before calling applyRecords). `cursor` is the per-operator
 * monotonic high-water mark used for incremental `?since=` pulls.
 *
 * Synchronous fs by design: the hooks run synchronously (spawnSync),
 * and the file is small. Writes are atomic (tmp + rename) with 0600.
 */
import {
  readFileSync,
  writeFileSync,
  renameSync,
  mkdirSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { canonicalTool } from './tool-taxonomy.js';

// Most-restrictive-wins precedence when several rules match one call.
const SEVERITY_RANK = { deny: 3, rewrite: 2, warn: 1 };

export function operatorStatePath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'operator-state.json');
}

export class OperatorStore {
  constructor(scope = 'main', path = operatorStatePath(scope)) {
    this.scope = scope ?? 'main';
    this.path = path;
    this.state = { version: 1, cursor: 0, records: {} };
    this.#load();
  }

  #load() {
    try {
      const parsed = JSON.parse(readFileSync(this.path, 'utf8'));
      if (parsed && typeof parsed === 'object') {
        this.state = {
          version: 1,
          cursor: Number(parsed.cursor) || 0,
          records:
            parsed.records && typeof parsed.records === 'object'
              ? parsed.records
              : {},
          // Trust-on-first-use pin of the operator's delegation_authority key
          // (see pinnedDelegationJwk). Persisted so a later sync can't swap it.
          ...(parsed.delegation_jwk && typeof parsed.delegation_jwk === 'object'
            ? { delegation_jwk: parsed.delegation_jwk }
            : {}),
        };
      }
    } catch {
      // Missing or corrupt file → start empty. A corrupt cache is not
      // fatal; the next sync re-pulls from cursor 0.
    }
  }

  save() {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  get cursor() {
    return this.state.cursor;
  }

  setCursor(c) {
    const n = Number(c);
    if (Number.isFinite(n) && n > this.state.cursor) this.state.cursor = n;
  }

  /**
   * The operator's delegation_authority public key (P-256 {x_b64u,y_b64u}),
   * PINNED on the first sync that supplied one. After that, rule/memory
   * signatures are verified against THIS key — a later sync that hands over a
   * different key (a compromised/forged IdP response) is ignored, so it can't
   * substitute the verification key and forge operator records. Null until the
   * first sync establishes it.
   */
  get pinnedDelegationJwk() {
    return this.state.delegation_jwk ?? null;
  }

  /** Pin the delegation key ONCE (trust-on-first-use). No-op if already pinned
   *  or the candidate is malformed. Returns true if it pinned now. */
  pinDelegationJwk(jwk) {
    if (this.state.delegation_jwk) return false;
    if (!jwk || typeof jwk.x_b64u !== 'string' || typeof jwk.y_b64u !== 'string') return false;
    this.state.delegation_jwk = { x_b64u: jwk.x_b64u, y_b64u: jwk.y_b64u };
    this.save();
    return true;
  }

  /**
   * Apply one decrypted record. Version-guarded (a record older than
   * what we hold is ignored — downgrade defense). A non-active status
   * (revoked / forgotten) removes the record. Returns true if state
   * changed.
   */
  upsert(record) {
    if (!record || !record.id) return false;
    const existing = this.state.records[record.id];
    if (existing && Number(record.version) < Number(existing.version)) {
      return false;
    }
    if (record.status && record.status !== 'active') {
      if (existing) {
        delete this.state.records[record.id];
        return true;
      }
      return false;
    }
    this.state.records[record.id] = {
      id: record.id,
      kind: record.kind,
      target: record.target ?? null,
      status: 'active',
      version: Number(record.version) || 0,
      updated_at: record.updated_at ?? null,
      content: record.content ?? null,
    };
    return true;
  }

  /**
   * Apply a batch of decrypted records and (optionally) advance the
   * cursor, persisting once. Returns the count of records that changed
   * state.
   */
  applyRecords(records = [], cursor = null) {
    let changed = 0;
    for (const r of records) if (this.upsert(r)) changed += 1;
    const cursorMoved = cursor != null && Number(cursor) > this.state.cursor;
    if (cursor != null) this.setCursor(cursor);
    if (changed > 0 || cursorMoved) this.save();
    return changed;
  }

  listRules() {
    return Object.values(this.state.records).filter((r) => r.kind === 'rule');
  }

  listMemories() {
    return Object.values(this.state.records).filter((r) => r.kind === 'memory');
  }

  /** Always-inject memories (saas-migration.md / agent-memory.md bedrock tier). */
  bedrockMemories() {
    return this.listMemories().filter((r) => r.content && r.content.bedrock === true);
  }

  /**
   * Evaluate the local rules against a tool call. Output mirrors the
   * desktop /policy/check shape so the PreToolUse hook can consume it
   * unchanged:
   *   { allow: true }
   *   { allow: false, matched: { severity, memory_id, reason, pattern, tool, replacement } }
   *
   * Most-restrictive-wins: deny > rewrite > warn; ties broken by the
   * more recently updated rule.
   */
  matchRules(toolName, toolInput, opts = {}) {
    // exactToolOnly: skip tool-agnostic ("any tool") rules and require an
    // explicit canonical-category match. The channel-input surface uses
    // this — an inbound message isn't a tool call, so a generic "deny X on
    // any tool" rule (meant for tool execution) must NOT silently withhold
    // an operator message that merely mentions X. Only rules the operator
    // deliberately scoped to `message_in` apply there.
    const exactToolOnly = opts.exactToolOnly === true;
    const flat = flattenInput(toolInput);
    let best = null;
    let bestUpdatedAt = '';
    for (const r of this.listRules()) {
      const c = r.content || {};
      const tool = normalizeTool(c.tool);
      const pattern = c.pattern ?? '';
      // A rule with neither a tool nor a pattern is a no-op (avoid a
      // footgun that would match every call).
      if (!tool && !pattern) continue;
      if (exactToolOnly && !tool) continue;
      if (!ruleAppliesToTool(tool, toolName)) continue;
      if (!patternMatches(pattern, c.is_regex === true, flat)) continue;

      const severity = SEVERITY_RANK[c.severity] ? c.severity : 'warn';
      const cand = {
        severity,
        memory_id: r.id,
        reason: c.reason ?? '',
        pattern,
        is_regex: c.is_regex === true,
        tool: tool || '*',
        replacement: c.replacement,
        // Curated provenance (stamped at publish from a rule pack). Lets the
        // hook meter a curated-pack hit (cumulative, shared) distinctly from a
        // private operator rule, and the console attribute + offer updates.
        ...(c.curated === true
          ? { curated: true, pack: c.pack ?? null, rule: c.rule ?? null, pack_version: c.pack_version ?? null }
          : {}),
      };
      const better =
        !best ||
        SEVERITY_RANK[cand.severity] > SEVERITY_RANK[best.severity] ||
        (SEVERITY_RANK[cand.severity] === SEVERITY_RANK[best.severity] &&
          (r.updated_at || '') > bestUpdatedAt);
      if (better) {
        best = cand;
        bestUpdatedAt = r.updated_at || '';
      }
    }
    return best ? { allow: false, matched: best } : { allow: true };
  }

  /**
   * Local-first policy resolution for the PreToolUse hook.
   *   - a local rule fired        → return its decision (authoritative).
   *   - synced, but no rule fired → return { allow: true } (authoritative;
   *     the local store IS the operator's rule set once we've pulled state).
   *   - never synced (cursor 0)   → return null, signalling the caller to
   *     fall back to the desktop /policy/check (transition / cold start).
   */
  policyDecision(toolName, toolInput) {
    const local = this.matchRules(toolName, toolInput);
    if (local.allow === false) return local;
    if (this.cursor > 0) return { allow: true };
    return null;
  }
}

// ── helpers ──────────────────────────────────────────────────────────

/** Flatten a tool input to a single searchable string (all string leaves). */
export function flattenInput(input) {
  if (input == null) return '';
  if (typeof input === 'string') return input;
  const parts = [];
  const visit = (v) => {
    if (v == null) return;
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) v.forEach(visit);
    else if (typeof v === 'object') Object.values(v).forEach(visit);
    else parts.push(String(v));
  };
  visit(input);
  return parts.join('\n');
}

/** Strip an optional "tool:" prefix and lowercase; '' means "any tool". */
function normalizeTool(tool) {
  if (!tool || typeof tool !== 'string') return '';
  const t = tool.startsWith('tool:') ? tool.slice('tool:'.length) : tool;
  const lower = t.trim().toLowerCase();
  return lower === '*' || lower === 'all' ? '' : lower;
}

function ruleAppliesToTool(normalizedRuleTool, toolName) {
  if (!normalizedRuleTool) return true; // applies to any tool
  // Rules store a CANONICAL tool category (e.g. "shell"); normalize the
  // runtime's literal tool name ("Bash") to canonical before matching so
  // a rule is portable across runtimes (Claude `Bash`, Codex `shell`, …).
  // Also accept a literal-name match for any legacy raw-name rules.
  const raw = String(toolName ?? '').toLowerCase();
  return normalizedRuleTool === canonicalTool(toolName) || normalizedRuleTool === raw;
}

/**
 * Does `pattern` match `text`? Mirrors pre-tool-use.js rewriteToolInput:
 *   - "regex:" prefix → used as a regex source.
 *   - otherwise → literal, with regex metacharacters escaped.
 * Case-insensitive. Empty pattern matches (tool-scoped rule). A
 * malformed regex fails closed (no match) rather than throwing.
 */
export function patternMatches(pattern, isRegexFlag, text) {
  if (pattern == null || pattern === '') return true;
  const re = compileRulePattern(pattern, isRegexFlag, 'i');
  return re ? re.test(text) : false;
}

/**
 * THE single source of truth for how a rule's `pattern` + `is_regex` flag
 * compile to a RegExp. Used by patternMatches (the matcher), redactMatches
 * (inbound channel redaction), and applyRewrite (the PreToolUse rewriter).
 *
 * A pattern is a regex when EITHER the rule's `is_regex` flag is set (the
 * console checkbox) OR the pattern carries a leading `regex:` prefix.
 * Otherwise it's a literal and regex metacharacters are escaped so it
 * matches verbatim. Returns null on a malformed regex so every caller
 * fails closed (no match / no rewrite) rather than throwing.
 *
 * Keeping this in ONE place is the fix for the class of bug where the
 * matcher honoured `is_regex` but the rewriter only checked the `regex:`
 * prefix — so a checkbox-authored regex rule matched but then escaped its
 * own pattern into a literal and rewrote nothing (e.g. the `sfw $1$2`
 * supply-chain rule silently no-op'd).
 */
export function compileRulePattern(pattern, isRegexFlag, flags = 'i') {
  if (pattern == null) return null;
  const str = String(pattern);
  const hasPrefix = str.startsWith('regex:');
  const isRegex = isRegexFlag === true || hasPrefix;
  let rawSrc = hasPrefix ? str.slice('regex:'.length) : str;
  let effFlags = flags;
  if (isRegex) {
    // Fold a leading PCRE/Python-style inline-flag group (e.g. `(?i)`,
    // `(?ims)`) into the RegExp flags — JS throws "Invalid group" on that
    // bare form, so an operator pasting a `(?i)…` regex would otherwise get
    // a silently dead rule (compiles to null → matches nothing). We already
    // apply `i` everywhere, so `(?i)` is usually a no-op once folded.
    const stripped = stripInlineFlags(rawSrc, effFlags);
    rawSrc = stripped.source;
    effFlags = stripped.flags;
  }
  const src = isRegex ? rawSrc : rawSrc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  try {
    return new RegExp(src, effFlags);
  } catch {
    return null;
  }
}

/**
 * Strip a LEADING inline-flag group — `(?i)`, `(?ims)`, etc. — and fold the
 * flags into the RegExp constructor flags, merged with `baseFlags`. Only
 * flags JS supports (i, m, s, u, y) are folded; if the group carries
 * anything else (e.g. `x` verbose mode, which JS can't represent), it is
 * LEFT IN PLACE so the pattern fails to compile and surfaces as invalid —
 * better a loud failure than silently changing the regex's meaning.
 * Returns { source, flags }.
 */
export function stripInlineFlags(source, baseFlags = '') {
  if (typeof source !== 'string') return { source, flags: baseFlags };
  const m = source.match(/^\(\?([a-zA-Z]+)\)/);
  if (!m) return { source, flags: baseFlags };
  if (!/^[imsuy]+$/.test(m[1])) return { source, flags: baseFlags };
  const merged = [...new Set(`${baseFlags}${m[1]}`)].join('');
  return { source: source.slice(m[0].length), flags: merged };
}

/**
 * Globally replace every match of `pattern` in `text` with `replacement`
 * (default "[redacted]"). The inbound twin of applyRewrite: redacts matched
 * spans of a decrypted operator message before the agent sees it. `$1`/`$&`
 * backrefs honoured. Malformed regex fails closed (text unchanged).
 */
export function redactMatches(text, pattern, replacement, isRegexFlag) {
  if (typeof text !== 'string' || !pattern) return text;
  const repl = typeof replacement === 'string' && replacement.length > 0
    ? replacement
    : '[redacted]';
  const re = compileRulePattern(pattern, isRegexFlag, 'gi');
  return re ? text.replace(re, repl) : text;
}

/**
 * Apply a `rewrite`-severity rule to a tool input: substring/regex-replace
 * `pattern` → `replacement` across the command-shaped string fields. Returns
 * a NEW object with the changed fields, or null when nothing changed (caller
 * falls through to a no-op). Shared by the PreToolUse hook so the rewrite
 * uses the exact same pattern grammar as the matcher.
 *
 * `fields` defaults to the command-shaped inputs: `command`/`description`
 * (shell tools) + `text` (the outbound channel tool lastid_send_message).
 */
export function applyRewrite(
  toolInput,
  pattern,
  replacement,
  isRegexFlag,
  fields = ['command', 'description', 'text'],
) {
  if (!pattern || !toolInput || typeof toolInput !== 'object') return null;
  const re = compileRulePattern(pattern, isRegexFlag, 'gi');
  if (!re) return null; // malformed → fail closed (no rewrite)
  const next = { ...toolInput };
  let changed = false;
  for (const field of fields) {
    const v = next[field];
    if (typeof v !== 'string' || v.length === 0) continue;
    re.lastIndex = 0;
    if (!re.test(v)) continue;
    re.lastIndex = 0; // reset after .test() before .replace()
    next[field] = v.replace(re, replacement);
    changed = true;
  }
  return changed ? next : null;
}
