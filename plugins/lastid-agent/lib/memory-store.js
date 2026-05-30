/**
 * Local agent memory store — JS port of the desktop Rust `MemoryStore`
 * (lastid-sdk/lastid-agent-memory) for the SaaS-migrated plugin.
 *
 * The old TCB was a desktop SQLite store (per-human global.db + per-agent
 * agent.db) reached over the desktop MCP. In the new model the agent keeps
 * its own memories in a local JSON store on the agent host (this file),
 * the SAME way operator-store.js caches operator-authored rules/memories
 * synced from the IdP. Operator-authored bedrock memories arrive via the
 * agent-state sync rails (operator-store); memories the AGENT writes/drafts
 * live here. Retrieval composes both.
 *
 * Persistence: ~/.lastid-agent/<scope>/memory.json, mode 0600, atomic
 * (tmp + rename) — identical posture to operator-state.json. Plaintext on
 * the agent's own host (consistent with operator-state.json, which already
 * stores rule patterns/reasons in the clear). The slot_seed at-rest wrap is
 * a later hardening, not a correctness requirement.
 *
 * Faithful to the Rust model: MemoryObject fields, the kind/tier/sensitivity/
 * decay/status enums, source_kind→confidence defaults, kind→decay defaults,
 * the sensitivity auto-escalation heuristic, and the draft→promote/reject
 * lifecycle. Embedding fields (embedding / embedding_model_version) are
 * carried here and populated by the embeddings layer (lib/embeddings.js).
 */
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  renameSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';

// ── enums (mirror lastid-agent-memory/src/types.rs) ──────────────────

export const MEMORY_KINDS = [
  'fact',
  'preference',
  'decision',
  'open_loop',
  'episodic',
  'artifact',
  'rule',
  // Working/RAM layer: a file-anchored, JIT-surfaced working note (see
  // docs/sticky-notes-spec.md). Path-keyed via `anchor`; surfaced ONLY when the
  // agent touches that file (Read hook), EXCLUDED from semantic recall;
  // resolve-or-rip lifecycle (fix / not-relevant), persists across sessions.
  'sticky',
];
// 'project' = shared across all the operator's agents, scoped to one git
// remote (project_key); injected only when an agent is working in that repo.
export const TIERS = ['global', 'agent', 'project'];
export const SENSITIVITIES = ['low', 'medium', 'high', 'restricted'];
const SENSITIVITY_RANK = { low: 0, medium: 1, high: 2, restricted: 3 };
export const DECAYS = ['none', 'slow', 'medium', 'fast'];
export const STATUSES = ['active', 'forgotten', 'deprecated', 'drafted'];
export const SOURCE_KINDS = [
  'user_explicit',
  'inferred',
  'tool_observation',
  'imported',
];

// source_kind → default confidence (store.rs:182-204)
const CONFIDENCE_BY_SOURCE = {
  user_explicit: 0.95,
  inferred: 0.5,
  tool_observation: 0.7,
  imported: 0.6,
};
// kind → default decay
const DECAY_BY_KIND = {
  fact: 'none',
  artifact: 'none',
  rule: 'none',
  preference: 'slow',
  decision: 'slow',
  open_loop: 'medium',
  episodic: 'medium',
  sticky: 'medium',
};

const CLAIM_MAX = 4000;
const SUMMARY_MAX = 600;

/**
 * The `summary` is an OPTIONAL convenience field (the `claim` is the real
 * content). So an over-long summary must NEVER block a write/update — we CLAMP
 * it to SUMMARY_MAX, the same way bug-report slices its fields. Hard-rejecting
 * here was a footgun: callers can't predict the exact length and end up looping
 * on "summary exceeds 600". Trims, then truncates; empty → undefined.
 */
export function clampSummary(raw) {
  if (typeof raw !== 'string') return undefined;
  const t = raw.trim();
  if (t.length === 0) return undefined;
  return t.length > SUMMARY_MAX ? t.slice(0, SUMMARY_MAX) : t;
}

// ── helpers ──────────────────────────────────────────────────────────

export function memoryStatePath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'memory.json');
}

const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32

/** Minimal ULID: 48-bit ms timestamp + 80 bits random, Crockford base32.
 *  Lexicographically sortable by creation time, like the desktop's ids. */
function ulid(nowMs = Date.now()) {
  let ts = nowMs;
  const out = new Array(26);
  for (let i = 9; i >= 0; i--) {
    out[i] = ULID_ALPHABET[ts % 32];
    ts = Math.floor(ts / 32);
  }
  const rnd = randomBytes(16);
  for (let i = 10; i < 26; i++) {
    out[i] = ULID_ALPHABET[rnd[i - 10] % 32];
  }
  return out.join('');
}

function newMemoryId() {
  return `mem_${ulid()}`;
}

function nowIso() {
  return new Date().toISOString();
}

/**
 * Auto-escalate sensitivity when the claim/summary smells like a secret.
 * Mirrors the desktop heuristic intent: never DOWNGRADE the caller's value,
 * only raise it. Returns the higher of caller sensitivity and the detected
 * floor.
 */
export function escalateSensitivity(caller, ...texts) {
  const base = SENSITIVITIES.includes(caller) ? caller : 'low';
  const blob = texts.filter((t) => typeof t === 'string').join('\n').toLowerCase();
  let floor = 'low';
  // high: credential-ish material
  if (
    /\b(password|passphrase|secret|api[\s_-]?key|access[\s_-]?token|private[\s_-]?key|client[\s_-]?secret|bearer\s+[a-z0-9._-]{8,})\b/i.test(
      blob,
    ) ||
    /\b(ssn|social security|credit\s?card|cvv|routing\s?number)\b/i.test(blob)
  ) {
    floor = 'high';
  }
  return SENSITIVITY_RANK[floor] > SENSITIVITY_RANK[base] ? floor : base;
}

function validateWriteInput(input) {
  const errs = [];
  const kind = input.kind;
  if (!MEMORY_KINDS.includes(kind)) errs.push(`kind must be one of ${MEMORY_KINDS.join('|')}`);
  const tier = input.tier ?? 'agent';
  if (!TIERS.includes(tier)) errs.push(`tier must be one of ${TIERS.join('|')}`);
  // project_key identifies the repo a project-tier memory belongs to (a
  // normalized git remote, e.g. github.com/org/repo). Required for tier=project
  // and meaningless otherwise.
  const projectKey =
    typeof input.project_key === 'string' && input.project_key.trim().length > 0
      ? input.project_key.trim()
      : null;
  if (tier === 'project' && !projectKey) {
    errs.push('project_key is required for tier=project');
  }
  const subject = Array.isArray(input.subject)
    ? input.subject.filter((s) => typeof s === 'string' && s.trim().length > 0)
    : [];
  if (subject.length === 0) errs.push('subject must be a non-empty array of strings');
  const claim = typeof input.claim === 'string' ? input.claim.trim() : '';
  if (!claim) errs.push('claim is required');
  if (claim.length > CLAIM_MAX) errs.push(`claim exceeds ${CLAIM_MAX} chars`);
  // Optional summary — clamp (never reject): the claim is the real content.
  const summary = clampSummary(input.summary);
  const sourceKind = input.source_kind;
  if (!SOURCE_KINDS.includes(sourceKind)) {
    errs.push(`source_kind must be one of ${SOURCE_KINDS.join('|')}`);
  }
  return { errs, kind, tier, projectKey, subject, claim, summary, sourceKind };
}

// ── store ────────────────────────────────────────────────────────────

export class MemoryStore {
  constructor(scope = 'main', path = memoryStatePath(scope), { agentDid = null, parentHumanDid = null } = {}) {
    this.scope = scope ?? 'main';
    this.path = path;
    this.agentDid = agentDid;
    this.parentHumanDid = parentHumanDid;
    this.state = { version: 1, records: {} };
    this.#load();
  }

  #load() {
    try {
      const parsed = JSON.parse(readFileSync(this.path, 'utf8'));
      if (parsed && typeof parsed === 'object' && parsed.records && typeof parsed.records === 'object') {
        this.state = { version: 1, records: parsed.records };
      }
    } catch {
      // Missing/corrupt → empty. A corrupt local cache is not fatal.
    }
  }

  save() {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  /** Build a full MemoryObject from caller input + defaults. */
  #materialize(input, status) {
    const { errs, kind, tier, projectKey, subject, claim, summary, sourceKind } = validateWriteInput(input);
    if (errs.length > 0) {
      const e = new Error(`invalid memory: ${errs.join('; ')}`);
      e.code = 'EVALIDATION';
      throw e;
    }
    const ts = nowIso();
    const sensitivity = escalateSensitivity(input.sensitivity ?? 'low', claim, summary);
    return {
      id: newMemoryId(),
      // Monotonic per-id version for the IdP agent-state record (write-through
      // supersede). Bumped on each update.
      version: 1,
      tier,
      // Agent-tier is per-agent; global + project are not bound to one agent.
      agent_did: tier === 'agent' ? this.agentDid : null,
      // Project-tier memories carry the repo key they're scoped to; null else.
      ...(tier === 'project' ? { project_key: projectKey } : {}),
      parent_human_did: this.parentHumanDid,
      kind,
      subject,
      claim,
      ...(summary ? { summary } : {}),
      source: {
        kind: sourceKind,
        ...(typeof input.source_ref === 'string' ? { source_ref: input.source_ref } : {}),
        ...(typeof input.source_quote === 'string' ? { quote: input.source_quote } : {}),
      },
      confidence:
        typeof input.confidence === 'number'
          ? input.confidence
          : (CONFIDENCE_BY_SOURCE[sourceKind] ?? 0.6),
      sensitivity,
      bedrock: input.bedrock === true,
      allowed_uses: Array.isArray(input.allowed_uses) ? input.allowed_uses : ['reasoning', 'style'],
      forbidden_uses: Array.isArray(input.forbidden_uses) ? input.forbidden_uses : [],
      status,
      created_at: ts,
      updated_at: ts,
      last_confirmed_at: ts,
      decay: DECAYS.includes(input.decay) ? input.decay : (DECAY_BY_KIND[kind] ?? 'none'),
      ...(typeof input.expires_at === 'string' ? { expires_at: input.expires_at } : {}),
      related: Array.isArray(input.related) ? input.related : [],
      ...(input.references && typeof input.references === 'object'
        ? { references: input.references }
        : {}),
      // Sticky-note file anchor: { repo_key, rel_path } — repo-RELATIVE so it is
      // portable to console (NOT this machine's absolute path). Surfaced by the
      // Read hook via stickyNotesForAnchor; ignored for non-sticky kinds.
      ...(input.anchor &&
      typeof input.anchor === 'object' &&
      typeof input.anchor.rel_path === 'string' &&
      input.anchor.rel_path.length > 0
        ? {
            anchor: {
              repo_key:
                typeof input.anchor.repo_key === 'string' ? input.anchor.repo_key : null,
              rel_path: input.anchor.rel_path,
            },
          }
        : {}),
      embedding: null,
      embedding_model_version: null,
    };
  }

  /** Save an explicit memory (status=active). */
  write(input) {
    const obj = this.#materialize(input, 'active');
    this.state.records[obj.id] = obj;
    this.save();
    return obj;
  }

  /** Propose a memory for operator review (status=drafted). Does NOT
   *  surface in retrieval until promoted. */
  draft(input) {
    const obj = this.#materialize(input, 'drafted');
    this.state.records[obj.id] = obj;
    this.save();
    return obj;
  }

  get(id) {
    return this.state.records[id] ?? null;
  }

  /** Persist a prebuilt record (used to roll the local cache back to a
   *  snapshot when a live IdP write-through fails). */
  put(obj) {
    if (!obj || !obj.id) return null;
    this.state.records[obj.id] = obj;
    this.save();
    return obj;
  }

  /**
   * Reconcile a synced agent-state record into the local cache — the
   * cross-session/cross-host path. `rec` is the decoded store record
   * ({ id, target, version, status, content }); `author` is the record's
   * author. Version-guarded (only strictly-newer applies, so this host's own
   * just-written records — and their local embeddings — aren't clobbered).
   *
   *   - revoked (any author) → drop the id locally if present.
   *   - active + author='agent' → rebuild the MemoryObject from content + put
   *     (embedding null → re-embedded locally on next search).
   *   - active + operator-authored → ignored (those live in operator-store).
   *
   * Returns true if the local cache changed.
   */
  applySync(rec, author) {
    if (!rec || !rec.id) return false;
    const existing = this.state.records[rec.id];
    const ver = Number(rec.version) || 0;
    if (existing && (Number(existing.version) || 0) >= ver) return false; // downgrade / self-echo guard
    if (rec.status === 'revoked') {
      if (existing) {
        delete this.state.records[rec.id];
        this.save();
        return true;
      }
      return false;
    }
    if (author !== 'agent') return false; // operator-authored actives belong in operator-store
    const c = rec.content || {};
    if (typeof c.claim !== 'string' || c.claim.length === 0) return false;
    // Project records (target='project') are shared across the operator's
    // agents; they carry their repo key inside the decrypted content. A project
    // active with no usable project_key can't be scoped, so skip it.
    const isProject = rec.target === 'project';
    if (isProject && (typeof c.project_key !== 'string' || c.project_key.length === 0)) return false;
    const ts = nowIso();
    this.state.records[rec.id] = {
      id: rec.id,
      version: ver,
      tier: isProject ? 'project' : rec.target === 'global' ? 'global' : 'agent',
      // Project + global memories are not bound to one agent; agent tier is.
      agent_did: isProject || rec.target === 'global' ? null : this.agentDid,
      ...(isProject ? { project_key: c.project_key } : {}),
      parent_human_did: this.parentHumanDid,
      kind: MEMORY_KINDS.includes(c.kind) ? c.kind : 'fact',
      subject: Array.isArray(c.subject) ? c.subject : [],
      claim: c.claim,
      ...(typeof c.summary === 'string' ? { summary: c.summary } : {}),
      // Re-hydrate a sticky note's file anchor from the decrypted content so a
      // synced-down copy surfaces on the right file (kind='sticky').
      ...(c.anchor &&
      typeof c.anchor === 'object' &&
      typeof c.anchor.rel_path === 'string'
        ? {
            anchor: {
              repo_key: typeof c.anchor.repo_key === 'string' ? c.anchor.repo_key : null,
              rel_path: c.anchor.rel_path,
            },
          }
        : {}),
      source: { kind: SOURCE_KINDS.includes(c.source_kind) ? c.source_kind : 'inferred' },
      confidence: typeof c.confidence === 'number' ? c.confidence : 0.6,
      sensitivity: SENSITIVITIES.includes(c.sensitivity) ? c.sensitivity : 'low',
      bedrock: c.bedrock === true,
      allowed_uses: ['reasoning', 'style'],
      forbidden_uses: [],
      status: STATUSES.includes(c.status) ? c.status : 'active',
      created_at: typeof c.created_at === 'string' ? c.created_at : ts,
      updated_at: ts,
      last_confirmed_at: ts,
      decay: DECAYS.includes(c.decay) ? c.decay : 'none',
      related: [],
      embedding: null,
      embedding_model_version: null,
    };
    this.save();
    return true;
  }

  /** Partial update. Only claim/summary/sensitivity/status/bedrock/
   *  expires_at are caller-editable (mirrors the update tool). Editing
   *  claim/summary invalidates the embedding so it gets recomputed. */
  update(id, patch = {}) {
    const m = this.state.records[id];
    if (!m) return null;
    let embeddingDirty = false;
    if (typeof patch.claim === 'string') {
      const c = patch.claim.trim();
      if (!c) throw Object.assign(new Error('claim cannot be empty'), { code: 'EVALIDATION' });
      if (c.length > CLAIM_MAX) throw Object.assign(new Error(`claim exceeds ${CLAIM_MAX}`), { code: 'EVALIDATION' });
      if (c !== m.claim) embeddingDirty = true;
      m.claim = c;
    }
    if (patch.summary !== undefined) {
      // Clamp, don't reject (same as the write path) — an over-long optional
      // summary must never block an update.
      const s = clampSummary(patch.summary) ?? '';
      if (s !== (m.summary ?? '')) embeddingDirty = true;
      if (s) m.summary = s;
      else delete m.summary;
    }
    if (patch.sensitivity !== undefined && SENSITIVITIES.includes(patch.sensitivity)) {
      // re-run the heuristic so an edit can't quietly drop below the floor
      m.sensitivity = escalateSensitivity(patch.sensitivity, m.claim, m.summary);
    }
    if (patch.status !== undefined) {
      // the update tool only allows active|deprecated (not drafted/forgotten)
      if (patch.status === 'active' || patch.status === 'deprecated') m.status = patch.status;
    }
    if (patch.bedrock !== undefined) m.bedrock = patch.bedrock === true;
    if (patch.clear_expires_at === true) delete m.expires_at;
    else if (typeof patch.expires_at === 'string') m.expires_at = patch.expires_at;
    if (embeddingDirty) {
      m.embedding = null;
      m.embedding_model_version = null;
    }
    m.version = (Number(m.version) || 1) + 1;
    m.updated_at = nowIso();
    this.save();
    return m;
  }

  /** Soft-delete (status=forgotten) or hard-delete (row wiped). */
  forget(id, { hard = false } = {}) {
    const m = this.state.records[id];
    if (!m) return false;
    if (hard) {
      delete this.state.records[id];
    } else {
      m.status = 'forgotten';
      m.version = (Number(m.version) || 1) + 1;
      m.updated_at = nowIso();
    }
    this.save();
    return true;
  }

  promoteDraft(id) {
    const m = this.state.records[id];
    if (!m || m.status !== 'drafted') return null;
    m.status = 'active';
    m.updated_at = nowIso();
    this.save();
    return m;
  }

  rejectDraft(id) {
    const m = this.state.records[id];
    if (!m || m.status !== 'drafted') return null;
    m.status = 'forgotten';
    m.updated_at = nowIso();
    this.save();
    return m;
  }

  /** Bump last_confirmed_at (called by the retrieval pipeline when a
   *  memory is injected). No-op for missing ids. Batched save by caller
   *  is preferable; this saves immediately for simplicity. */
  confirm(ids = []) {
    let changed = false;
    const ts = nowIso();
    for (const id of ids) {
      const m = this.state.records[id];
      if (m) {
        m.last_confirmed_at = ts;
        changed = true;
      }
    }
    if (changed) this.save();
  }

  all() {
    return Object.values(this.state.records);
  }

  /** Non-expired, status-active memories. */
  activeMemories(nowMs = Date.now()) {
    return this.all().filter((m) => m.status === 'active' && !isExpired(m, nowMs));
  }

  /**
   * Always-inject memories: active + bedrock + not expired. EXCLUDES project-
   * tier memories — those are scoped to a repo and inject only when the agent
   * is working in it (see projectBedrockMemories), so they never dilute the
   * context of unrelated work.
   */
  bedrockMemories(nowMs = Date.now()) {
    return this.activeMemories(nowMs).filter(
      (m) => m.bedrock === true && m.tier !== 'project',
    );
  }

  /** Active memories scoped to one project_key (a normalized git remote). */
  projectMemories(projectKey, nowMs = Date.now()) {
    if (typeof projectKey !== 'string' || projectKey.length === 0) return [];
    return this.activeMemories(nowMs).filter(
      (m) => m.tier === 'project' && m.project_key === projectKey,
    );
  }

  /**
   * Project-tier always-inject: active + bedrock + matching project_key.
   * Injected every turn the agent operates in that repo.
   */
  projectBedrockMemories(projectKey, nowMs = Date.now()) {
    return this.projectMemories(projectKey, nowMs).filter((m) => m.bedrock === true);
  }

  /**
   * Drafted (unverified) memories that are USABLE as drafts — surfaced in
   * retrieval (the renderer marks them "(draft)" so they're weighted as
   * tentative proposals, never ground truth):
   *   - the agent's own agent-tier drafts (its private working notes), and
   *   - project-tier drafts for the repo it's working in (its own + peers'
   *     synced drafts — shared-by-default, the operator demotes the bad ones).
   * Global-tier drafts stay review-gated (the high bar — they reach every
   * context, so a human promotes before they inject). Excludes expired.
   *
   * This is the opt-OUT draft model: a draft is used immediately (marked),
   * the human demotes it — vs the old opt-in where a draft was invisible until
   * promoted, so an agent couldn't even see its own learning.
   */
  usableDrafts(projectKey, nowMs = Date.now()) {
    return this.all().filter(
      (m) =>
        m.status === 'drafted' &&
        !isExpired(m, nowMs) &&
        (m.tier === 'agent' || (m.tier === 'project' && m.project_key === projectKey)),
    );
  }

  /**
   * Open (active) sticky notes anchored to a file — the JIT lookup the Read
   * hook uses to surface "context when your hands need it". Matches the
   * repo-relative anchor: same `rel_path`, and same `repo_key` when BOTH sides
   * carry one (a null repo_key on either side matches loosely, so a note
   * survives an unresolved repo). Newest first — the v1 stickiness proxy
   * (recency; a surface_count fold-in comes with the hook). Excludes expired +
   * resolved (status !== 'active', e.g. forgotten = "ripped up").
   */
  stickyNotesForAnchor(repoKey, relPath, nowMs = Date.now()) {
    if (typeof relPath !== 'string' || relPath.length === 0) return [];
    const ts = (m) => Date.parse(m.updated_at ?? m.created_at ?? '') || 0;
    return this.activeMemories(nowMs)
      .filter(
        (m) =>
          m.kind === 'sticky' &&
          m.anchor &&
          m.anchor.rel_path === relPath &&
          // repo_key matches when both carry one; missing on either side is permissive.
          !(m.anchor.repo_key && repoKey && m.anchor.repo_key !== repoKey),
      )
      .sort((x, y) => ts(y) - ts(x));
  }

  /**
   * Filtered list (mirrors the list tool). Sorted by confidence DESC then
   * last_confirmed_at DESC.
   */
  list({ kinds, sensitivity_max, subject_includes, status = 'active', bedrock_only, limit } = {}) {
    const maxRank = SENSITIVITY_RANK[sensitivity_max] ?? SENSITIVITY_RANK.restricted;
    const subjWanted = Array.isArray(subject_includes)
      ? subject_includes.map((s) => String(s).toLowerCase())
      : null;
    let rows = this.all().filter((m) => {
      if (status && m.status !== status) return false;
      if (Array.isArray(kinds) && kinds.length > 0 && !kinds.includes(m.kind)) return false;
      if (SENSITIVITY_RANK[m.sensitivity] > maxRank) return false;
      if (bedrock_only === true && m.bedrock !== true) return false;
      if (subjWanted) {
        const ms = (m.subject ?? []).map((s) => String(s).toLowerCase());
        if (!subjWanted.some((w) => ms.includes(w))) return false;
      }
      return true;
    });
    rows.sort(
      (a, b) =>
        (b.confidence ?? 0) - (a.confidence ?? 0) ||
        String(b.last_confirmed_at).localeCompare(String(a.last_confirmed_at)),
    );
    if (Number.isInteger(limit) && limit > 0) rows = rows.slice(0, limit);
    return rows;
  }
}

export function isExpired(m, nowMs = Date.now()) {
  if (!m || typeof m.expires_at !== 'string') return false;
  const t = Date.parse(m.expires_at);
  return Number.isFinite(t) && t < nowMs;
}

/** The text we embed for a memory: claim, then summary, then subject tags —
 *  matching the desktop's memory_embedding_text composition. */
export function memoryEmbeddingText(m) {
  const parts = [m.claim];
  if (m.summary) parts.push(m.summary);
  if (Array.isArray(m.subject) && m.subject.length > 0) parts.push(m.subject.join(', '));
  return parts.filter(Boolean).join('\n');
}
