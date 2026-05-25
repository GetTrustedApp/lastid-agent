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
  matchRules(toolName, toolInput) {
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
      if (!ruleAppliesToTool(tool, toolName)) continue;
      if (!patternMatches(pattern, c.is_regex === true, flat)) continue;

      const severity = SEVERITY_RANK[c.severity] ? c.severity : 'warn';
      const cand = {
        severity,
        memory_id: r.id,
        reason: c.reason ?? '',
        pattern,
        tool: tool || '*',
        replacement: c.replacement,
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
  return normalizedRuleTool === String(toolName ?? '').toLowerCase();
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
  const isRegex = isRegexFlag || pattern.startsWith('regex:');
  const rawSrc = pattern.startsWith('regex:')
    ? pattern.slice('regex:'.length)
    : pattern;
  const src = isRegex ? rawSrc : rawSrc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  try {
    return new RegExp(src, 'i').test(text);
  } catch {
    return false;
  }
}
