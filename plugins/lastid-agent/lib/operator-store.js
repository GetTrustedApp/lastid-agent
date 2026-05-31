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
import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import { canonicalTool } from './tool-taxonomy.js';
import { selfProtectionRecords, selfProtectionDisabledByEnv } from './self-protection.js';

// Most-restrictive-wins precedence when several rules match one call.
const SEVERITY_RANK = { deny: 3, rewrite: 2, warn: 1 };

// ── operator-state integrity (anti-tamper) ───────────────────────────
//
// operator-state.json holds the operator's SIGNED settings (rules, audit
// policy, …) after the sync verified each record's delegation signature. But
// the file itself is plaintext on disk — the agent's own Write tool, or an fs
// attacker, could edit it to delete a deny rule, flip exempt_agents, or disable
// audit, silently overriding what the operator signed. So the SINGLE WRITER
// (the listener) stamps a MAC over the state, keyed off a secret the file
// doesn't contain — the agent's slot_seed (in the keychain, which agent
// self-protection guards from being read into context). A reader holding the
// key (the rule-enforcing policy-check) re-verifies on load; a tampered or
// un-MACed file is rejected → SAFE DEFAULTS (no spoofed rules; self-protection
// is built-in, so it stays on regardless). A keyless reader loads best-effort.

/** Deterministic JSON (recursively sorted keys) — mirrors memory-audit.js's
 *  canonicalJson; the MAC must be reproducible across write/read. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

/** The state fields the MAC covers (NOT version, NOT the integrity tag itself). */
function macPayload(state) {
  const p = { cursor: Number(state.cursor) || 0, records: state.records ?? {} };
  if (state.delegation_jwk) p.delegation_jwk = state.delegation_jwk;
  // Per-kind sync cursors (see cursorFor). Covered by the MAC only when
  // NON-EMPTY, so a legacy file that predates per-kind cursors still verifies
  // (its payload carried no `cursors`), while any populated map is tamper-
  // protected — a forged `cursors` to skip records changes the payload and
  // fails the MAC.
  if (state.cursors && Object.keys(state.cursors).length > 0) p.cursors = state.cursors;
  return p;
}

/** Coerce a parsed `cursors` blob to a clean { kind: number } map; drops
 *  non-string keys and non-finite/negative values. Absent/malformed → {}. */
function sanitizeCursors(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    const n = Number(v);
    if (typeof k === 'string' && k && Number.isFinite(n) && n >= 0) out[k] = n;
  }
  return out;
}

function computeStateMac(macKey, state) {
  return createHmac('sha256', macKey).update(canonicalJson(macPayload(state)), 'utf8').digest('hex');
}

function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

/**
 * Derive the operator-state MAC key from the agent's slot_seed (HKDF-SHA256,
 * domain-separated). The slot_seed lives in the keychain — NOT in
 * operator-state.json — so an attacker who can edit the file but not read the
 * keychain (the agent itself, with self-protection on) cannot forge the MAC.
 * Returns null for a missing/empty seed (→ keyless, unverified).
 */
export function deriveOperatorStateMacKey(slotSeed) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length === 0) return null;
  return Buffer.from(
    hkdfSync('sha256', slotSeed, Buffer.alloc(0), Buffer.from('lastid-operator-state-mac-v1'), 32),
  );
}

export function operatorStatePath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'operator-state.json');
}

export class OperatorStore {
  constructor(scope = 'main', path = operatorStatePath(scope), opts = {}) {
    this.scope = scope ?? 'main';
    this.path = path;
    // Anti-tamper MAC key (from the agent's slot_seed). When set, save() stamps
    // a MAC and #load() rejects a tampered/un-MACed file (→ safe defaults). The
    // listener (writer) + the policy-check (rule enforcer) pass it; keyless
    // readers load best-effort. Must be set BEFORE #load().
    this.macKey = opts.macKey ?? null;
    // `cursor` is the global high-water (ever-synced marker + the policyDecision
    // cold-start gate). `cursors` are PER-KIND incremental cursors that actually
    // drive each kind's `?since=` — independent so a fast kind can't strand a
    // slower kind's records (the vault-share stranding bug). Set by setCursorFor.
    this.state = { version: 1, cursor: 0, cursors: {}, records: {} };
    this._cursorsDirty = false;
    this.#load();
  }

  #load() {
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(this.path, 'utf8'));
    } catch {
      // Missing or corrupt file → start empty. A corrupt cache is not
      // fatal; the next sync re-pulls from cursor 0.
      return;
    }
    if (!parsed || typeof parsed !== 'object') return;

    const next = {
      version: 1,
      cursor: Number(parsed.cursor) || 0,
      // Per-kind cursors. Absent on a legacy file → {} → every kind re-pulls
      // from 0 once (self-healing migration: any record stranded by the old
      // single-cursor sync gets re-fetched), then per-kind tracking thereafter.
      cursors: sanitizeCursors(parsed.cursors),
      records:
        parsed.records && typeof parsed.records === 'object' ? parsed.records : {},
      // Trust-on-first-use pin of the operator's delegation_authority key
      // (see pinnedDelegationJwk). Persisted so a later sync can't swap it.
      ...(parsed.delegation_jwk && typeof parsed.delegation_jwk === 'object'
        ? { delegation_jwk: parsed.delegation_jwk }
        : {}),
    };

    // INTEGRITY: when we hold the key, the file MUST carry a valid MAC over its
    // records. A tampered file (the agent's own Write, or an fs attacker editing
    // rules / disabling audit / stripping the MAC) fails here → we keep the
    // EMPTY state (no spoofed rules; the next sync re-pulls the authoritative
    // state + re-MACs; self-protection stays on, it's built-in). A keyless
    // reader loads unverified (best-effort / legacy).
    if (this.macKey) {
      const tag = parsed.integrity && typeof parsed.integrity === 'object' ? parsed.integrity : null;
      const expected = computeStateMac(this.macKey, next);
      if (!tag || !hexEqual(String(tag.mac ?? ''), expected)) {
        process.stderr.write(
          '[lastid-agent] operator-state integrity check FAILED — ignoring on-disk state ' +
            '(tampered or un-MACed); using safe defaults until the next sync re-pulls\n',
        );
        return; // keep the empty default state
      }
    }
    this.state = next;
  }

  save() {
    mkdirSync(dirname(this.path), { recursive: true });
    const out = { ...this.state };
    // Stamp the anti-tamper MAC when keyed (the listener, the single writer).
    if (this.macKey) out.integrity = { v: 1, mac: computeStateMac(this.macKey, this.state) };
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    renameSync(tmp, this.path);
    this._cursorsDirty = false;
  }

  get cursor() {
    return this.state.cursor;
  }

  setCursor(c) {
    const n = Number(c);
    if (Number.isFinite(n) && n > this.state.cursor) this.state.cursor = n;
  }

  /**
   * Per-kind incremental cursor (e.g. 'rule' | 'memory' | 'vault' |
   * 'audit_policy' | 'self_protection'). Each kind advances INDEPENDENTLY so a
   * fast-moving kind (memories) can't push a shared high-water past a slower
   * kind's pending record (a vault share) and strand it from `?since=` forever
   * — the sync bug this replaces. 0 when never synced for that kind, including a
   * legacy store with no per-kind map → re-pull that kind from 0 once.
   */
  cursorFor(kind) {
    if (!this.state.cursors) return 0;
    const n = Number(this.state.cursors[kind]);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  /**
   * Advance ONE kind's cursor (monotonic — never moves backward). Mutates in
   * memory and marks the store dirty; the next save() (applyRecords, or an
   * explicit save) persists it. Returns true if it actually moved.
   */
  setCursorFor(kind, n) {
    if (typeof kind !== 'string' || !kind) return false;
    const v = Number(n);
    if (!Number.isFinite(v)) return false;
    if (!this.state.cursors) this.state.cursors = {};
    if (v > (Number(this.state.cursors[kind]) || 0)) {
      this.state.cursors[kind] = v;
      this._cursorsDirty = true;
      return true;
    }
    return false;
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
    // Revoke-by-id wins WITHIN a batch. If this batch carries a revoke for an
    // id, that id is gone — even if the SAME batch also carries an active row
    // for it (a target-mismatched sibling rail, e.g. a global-shared routing
    // copy alongside a fan-out tombstone). Without this, array order alone
    // decides: a [revoke, active] sequence would delete then re-add, resurrecting
    // a memory the operator forgot — the mem_01KSTB0Q injection-after-delete
    // failure mode. Pairs with the IdP revoke-by-id cascade (#23), which now
    // delivers every rail's revoke under one cursor, i.e. in one batch.
    const revokedIds = new Set();
    for (const r of records) {
      if (r && r.id && r.status && r.status !== 'active') revokedIds.add(r.id);
    }
    let changed = 0;
    for (const r of records) {
      // Drop an active row whose id is revoked elsewhere in this same batch; the
      // revoke record itself still runs through upsert below (deleting any prior).
      if (r && r.id && revokedIds.has(r.id) && (!r.status || r.status === 'active')) {
        continue;
      }
      if (this.upsert(r)) changed += 1;
    }
    const cursorMoved = cursor != null && Number(cursor) > this.state.cursor;
    if (cursor != null) this.setCursor(cursor);
    // Also persist when per-kind cursors advanced (setCursorFor) even if no
    // record changed and the global high-water held — otherwise an
    // independently-advanced vault cursor would be lost on the next load.
    if (changed > 0 || cursorMoved || this._cursorsDirty) this.save();
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
   * Is agent self-protection (deny reading LastID's own keys) active? ON by
   * default — disabled only by a local env override (debugging LastID itself)
   * or a synced operator opt-out (a 'self_protection' record, content.enabled
   * === false, delivered on the same rails as the audit policy).
   */
  selfProtectionEnabled() {
    // Disable comes only from a TRUSTED source — never an unsigned on-disk edit.
    //   (1) a local env override for debugging LastID itself — explicit,
    //       process-level, NOT a file edit (LASTID_SELF_PROTECTION=off);
    //   (2) a delegation-signed operator opt-out (a 'self_protection' record),
    //       honored ONLY when this store is INTEGRITY-VERIFIED (macKey set): the
    //       MAC proves the record arrived via the delegation-verified sync and
    //       wasn't edited on disk. A keyless store can't trust it → stays ON.
    // Default: ON.
    if (selfProtectionDisabledByEnv()) return false;
    if (this.macKey) {
      const rec = Object.values(this.state.records).find((r) => r.kind === 'self_protection');
      if (rec && rec.content && rec.content.enabled === false) return false;
    }
    return true;
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
    // This agent's own DID — used to honor per-agent EXEMPTIONS. A global rule
    // applies to every one of the operator's agents EXCEPT those the operator
    // opted out (content.exempt_agents). Default (no selfDid, or DID not listed)
    // = governed — so a freshly reissued agent with a brand-new DID is governed
    // by every global rule until the operator explicitly exempts it (safe).
    const selfDid = typeof opts.selfDid === 'string' ? opts.selfDid : '';
    const flat = flattenInput(toolInput);
    let best = null;
    let bestUpdatedAt = '';
    // Synced operator rules PLUS the built-in agent self-protection rules (deny
    // reading LastID's own keys) unless disabled — one matcher, one deny/audit/
    // metric path; a self-protection deny wins (most-restrictive). Built-in so a
    // brand-new agent is protected before its first sync.
    const candidates = this.selfProtectionEnabled()
      ? [...this.listRules(), ...selfProtectionRecords()]
      : this.listRules();
    for (const r of candidates) {
      const c = r.content || {};
      // Per-agent opt-out: skip a rule this agent is exempt from.
      if (selfDid && Array.isArray(c.exempt_agents) && c.exempt_agents.includes(selfDid)) continue;
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
        // Mark a self-protection deny so the hook/console can present it
        // distinctly ("agent protecting its own keys") from operator rules.
        ...(c.self_protection === true ? { self_protection: true } : {}),
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
  policyDecision(toolName, toolInput, opts = {}) {
    const local = this.matchRules(toolName, toolInput, opts);
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
