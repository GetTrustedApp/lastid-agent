/**
 * Memory MCP tools — the agent-facing surface for the local memory store
 * (lib/memory-store.js). Port of the desktop Dart memory tools
 * (lastid-desktop/.../agent_mcp/tools/memory_tools.dart) into PLUGIN tools so
 * they're served locally (no desktop dependency) and operate on the agent's
 * own store.
 *
 * Capability-gated by the central gate in mcp-server.js via each tool's
 * `requiredCapability` (exact match against the agent's VC). The agent's
 * grants are scoped `:global` (memory:read/write/draft:global), matching the
 * "global + global draft" first scope.
 *
 * Semantic `lastid_memory_search` falls back to keyword/subject scoring when
 * no embedder is wired; the embeddings layer (lib/embeddings.js) swaps in
 * cosine similarity via `searchMemories`'s optional embedder.
 */
import { MemoryStore } from './memory-store.js';
import { makeEmbedder, cosine, embedMemory, EMBED_DIM, SEMANTIC_FLOOR } from './embeddings.js';
import { enqueueAuditEvent } from './audit-spool.js';
import { publishAgentMemory } from './agent-memory-publish.js';
import { readLastProject } from './project-sticky.js';
import { projectKeyForPath } from './project-key.js';

const DEFAULT_IDP_URL = 'https://human.lastid.co';

const CAP_WRITE = { resource: 'memory:write:global', action: 'Write' };
const CAP_DRAFT = { resource: 'memory:draft:global', action: 'Draft' };
const CAP_READ = { resource: 'memory:read:global', action: 'Read' };

const KIND_ENUM = ['fact', 'preference', 'decision', 'open_loop', 'episodic', 'artifact', 'rule'];
const SENS_ENUM = ['low', 'medium', 'high', 'restricted'];
const SOURCE_ENUM = ['user_explicit', 'inferred', 'tool_observation', 'imported'];

// Shared write/draft input schema (mirrors the desktop tool shape).
const writeInputSchema = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: KIND_ENUM, description: 'Memory kind.' },
    tier: {
      type: 'string',
      enum: ['agent', 'global', 'project'],
      description:
        "Storage tier. 'project' (the default when you're working in a repo) = shared with your operator's agents on that repo. 'agent' = private to you. 'global' = all your operator's agents everywhere (a proposal the operator reviews). The repo for project-tier is detected AUTOMATICALLY from where you're working — you do NOT name it.",
    },
    subject: {
      type: 'array',
      items: { type: 'string' },
      minItems: 1,
      description: 'Topical tags (≥1) — what the memory is about.',
    },
    claim: { type: 'string', description: 'The memory itself (≤4000 chars).' },
    summary: { type: 'string', description: 'Optional short summary. Kept to 600 chars — longer is truncated, never rejected, so a memory write is never blocked by summary length.' },
    source_kind: { type: 'string', enum: SOURCE_ENUM, description: 'Where this came from.' },
    source_quote: { type: 'string', description: 'Verbatim user text (for user_explicit).' },
    source_ref: { type: 'string', description: 'Session/file/conversation reference.' },
    sensitivity: { type: 'string', enum: SENS_ENUM, description: 'Auto-escalated if content looks secret.' },
    bedrock: { type: 'boolean', description: 'Always-inject on every turn if true.' },
    expires_at: { type: 'string', description: 'RFC3339 hard expiry (optional).' },
  },
  required: ['kind', 'subject', 'claim', 'source_kind'],
  additionalProperties: false,
};

export const MEMORY_TOOLS = [
  {
    name: 'lastid_memory_write',
    description:
      'Save a memory the agent should retain across sessions. Use when the operator says "remember", "save this", "from now on", "we decided", or states a stable preference/fact/decision. Commits immediately (status=active) and surfaces in future retrieval. Cite it later by its id.',
    requiredCapability: CAP_WRITE,
    inputSchema: writeInputSchema,
  },
  {
    name: 'lastid_memory_draft',
    description:
      "Save a durable memory you INFERRED (the operator didn't explicitly say \"remember\"). It's USED IMMEDIATELY as a draft — marked unverified, lower-trust than a confirmed memory, never ground truth — and, when you're working in a repo, shared with your operator's agents on that repo (project tier) so the whole fleet benefits. Your operator can demote it. Prefer lastid_memory_write when the operator explicitly asked. Always include source_quote.",
    requiredCapability: CAP_DRAFT,
    inputSchema: writeInputSchema,
  },
  {
    name: 'lastid_memory_get',
    description: 'Fetch a single memory by its id.',
    requiredCapability: CAP_READ,
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_memory_list',
    description:
      'List stored memories, filtered. Sorted by confidence then recency. Use to review what you remember about a subject.',
    requiredCapability: CAP_READ,
    inputSchema: {
      type: 'object',
      properties: {
        kinds: { type: 'array', items: { type: 'string', enum: KIND_ENUM } },
        sensitivity_max: { type: 'string', enum: SENS_ENUM },
        subject_includes: { type: 'array', items: { type: 'string' } },
        status: { type: 'string', enum: ['active', 'forgotten', 'deprecated', 'drafted'] },
        bedrock_only: { type: 'boolean' },
        limit: { type: 'integer', minimum: 1, maximum: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_memory_search',
    description:
      'Semantic search across stored memories. Returns top-K ranked by relevance to the query. Use when you know what kind of guidance you need but not the exact subject tags.',
    requiredCapability: CAP_READ,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'integer', minimum: 1, maximum: 32 },
        exclude_bedrock: { type: 'boolean' },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_memory_update',
    description:
      'Modify an existing memory (claim/summary/sensitivity/status/bedrock/expiry). Requires a reason for the audit trail. Editing the claim recomputes its embedding.',
    requiredCapability: CAP_WRITE,
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        claim: { type: 'string', description: 'Replacement memory text (≤4000 chars).' },
        summary: { type: 'string', description: 'Replacement short summary. Kept to 600 chars — longer is truncated, never rejected.' },
        sensitivity: { type: 'string', enum: SENS_ENUM },
        status: { type: 'string', enum: ['active', 'deprecated'] },
        bedrock: { type: 'boolean' },
        clear_expires_at: { type: 'boolean' },
        expires_at: { type: 'string' },
        reason: { type: 'string', description: 'Why (for audit).' },
      },
      required: ['id', 'reason'],
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_memory_forget',
    description:
      'Forget a memory. Soft-delete (status=forgotten, default) keeps provenance; hard_delete wipes the row. Requires a reason.',
    requiredCapability: CAP_WRITE,
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        reason: { type: 'string' },
        hard_delete: { type: 'boolean' },
      },
      required: ['id', 'reason'],
      additionalProperties: false,
    },
  },
];

export const MEMORY_TOOL_NAMES = new Set(MEMORY_TOOLS.map((t) => t.name));

// A trimmed view for tool output — the agent doesn't need raw embedding
// vectors or internal bookkeeping echoed back.
function publicView(m) {
  if (!m) return null;
  // Strip internal/local-only fields (raw embedding vector, sync bookkeeping).
  const { embedding, embedding_model_version, _unsynced, ...rest } = m;
  return rest;
}

/**
 * Keyword/subject relevance score in [0,1]: fraction of query terms that
 * appear in the memory's claim/summary/subject. The fallback when no
 * embedder is wired. The embeddings layer replaces this with cosine.
 */
export function keywordScore(query, m) {
  const terms = String(query)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2);
  if (terms.length === 0) return 0;
  const hay = [m.claim, m.summary, ...(m.subject ?? [])].filter(Boolean).join(' ').toLowerCase();
  let hits = 0;
  for (const t of terms) if (hay.includes(t)) hits += 1;
  return hits / terms.length;
}

/**
 * Search active memories for `query`. When `embedder` is provided AND yields
 * a query vector (embeddings installed), ranks by cosine similarity with a
 * semantic floor, lazily backfilling any candidate that lacks a vector (so
 * memories written before embeddings were set up still match). Otherwise
 * falls back to keyword/subject scoring. Returns
 * [{ memory_id, claim, summary, subject, score }] sorted desc, top `limit`.
 */
// Relevance lift for a memory that belongs to the repo the agent is working in
// right now (tier=project AND project_key === the active projectKey). Applied to
// the SORT rank only — keeps cross-repo (global/agent) memories eligible and
// ranked on raw relevance, but lets this boundary's ground truth lead instead
// of a global memory that merely mentions another repo.
const PROJECT_RANK_BOOST = 0.25;

export async function searchMemories(store, query, { limit = 8, excludeBedrock = false, embedder = null, projectKey = null, includeDrafts = false } = {}) {
  const select = () => {
    let c = store.activeMemories();
    // Drafts (unverified) are eligible too when asked: the agent's own + this
    // repo's project drafts (usableDrafts scopes them). The hit carries
    // `draft: true` so the renderer marks it — usable, but lower-trust.
    if (includeDrafts) c = c.concat(store.usableDrafts(projectKey));
    if (excludeBedrock) c = c.filter((m) => m.bedrock !== true);
    // Project-tier memories are eligible for topical ranking ONLY when the
    // agent is working in their repo (project_key === the active projectKey);
    // non-project memories are always eligible. Keeps a repo's memories out of
    // unrelated work and never leaks them across repos.
    c = c.filter((m) => m.tier !== 'project' || m.project_key === projectKey);
    return c;
  };
  let candidates = select();
  if (candidates.length === 0 || !query || String(query).trim().length === 0) return [];

  let scored = null;
  if (typeof embedder === 'function') {
    const qvec = await embedder(query);
    if (Array.isArray(qvec)) {
      // Lazy backfill: embed candidates missing a vector, then re-read.
      let needBackfill = false;
      for (const m of candidates) {
        if (!Array.isArray(m.embedding) || m.embedding.length !== EMBED_DIM) {
          await embedMemory(store, m.id, embedder);
          needBackfill = true;
        }
      }
      if (needBackfill) candidates = select();
      scored = candidates
        .map((m) => ({ m, score: Array.isArray(m.embedding) ? cosine(qvec, m.embedding) : 0 }))
        .filter((x) => x.score >= SEMANTIC_FLOOR);
    }
  }
  if (!scored) {
    scored = candidates.map((m) => ({ m, score: keywordScore(query, m) })).filter((x) => x.score > 0);
  }
  // Sort by a boundary-weighted `rank` (this repo's project memories lifted),
  // but keep the raw `score` for display so the shown [match] stays honest.
  for (const s of scored) {
    const onBoundary = s.m.tier === 'project' && !!projectKey && s.m.project_key === projectKey;
    s.rank = onBoundary ? s.score * (1 + PROJECT_RANK_BOOST) : s.score;
  }
  scored.sort((a, b) => b.rank - a.rank);
  return scored.slice(0, limit).map(({ m, score }) => ({
    memory_id: m.id,
    claim: m.claim,
    ...(m.summary ? { summary: m.summary } : {}),
    subject: m.subject,
    score: Number(score.toFixed(4)),
    // Tier lets the renderer label collective ground truth (global/project,
    // shared across the operator's agents) vs private (agent, just me);
    // project_key pins which repo a project hit belongs to.
    tier: m.tier,
    ...(m.tier === 'project' && m.project_key ? { project_key: m.project_key } : {}),
    // Unverified draft — the renderer marks it so it's weighted as a tentative
    // proposal, not ground truth.
    ...(m.status === 'drafted' ? { draft: true } : {}),
  }));
}

function ok(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}
function err(message) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

/**
 * Dispatch a memory tool. Assumes the central capability gate already ran.
 * Builds the store from the agent's identity (agent_did + parent_human_did).
 */
export async function handleMemoryTool({ name, args = {}, scope = 'main', loadedAgent, claims, fetchImpl, resolveRepo }) {
  if (!loadedAgent) return err('not provisioned — run `lastid-agent provision` first');
  const agentDid = claims?.sub ?? loadedAgent.agentDid ?? null;
  const store = new MemoryStore(scope, undefined, {
    agentDid,
    parentHumanDid: claims?.parent_human_did ?? null,
  });
  // Agent-side audit chain: ENQUEUE every memory CUD to the spool. We must NOT
  // append the signed chain here — this MCP tool server is one of several
  // processes that emit audit events (the PreToolUse/PostToolUse hooks too), and
  // Claude runs tools in parallel, so concurrent appends would fork the hash
  // chain. The listener is the single chain writer: it drains the spool in
  // order, signs + hash-links each event, and ships. (See audit-spool.js.)
  const audit = (eventType, memoryId, metadata) => {
    enqueueAuditEvent({ scope, eventType, memoryId, metadata });
  };
  // LIVE write-through (saas-migration §slot_seed): the IdP server store is
  // authoritative. The tool encrypts under the agent's slot_seed and POSTs as
  // the operation — only on a confirmed write does the local cache keep it.
  // If the IdP write fails the local cache is rolled back and the tool reports
  // the failure; we do NOT silently keep a local-only copy.
  const idpUrl = loadedAgent.idpUrl ?? DEFAULT_IDP_URL;
  const live = (memory, status) =>
    publishAgentMemory({ idpUrl, loaded: loadedAgent, memory, status, version: memory.version, fetchImpl }).catch(() => false);
  const notSaved = (detail) =>
    err(`memory NOT saved — the server write failed${detail ? `: ${detail}` : ''}. Tell your operator; nothing was stored.`);
  // ── THE REPO IS TOOL-DERIVED FROM THE FILESYSTEM, never from the agent ──
  // The agent does NOT supply the repo: it hallucinated keys (e.g.
  // github.com/LastID/lastid.co) when the real git remote is
  // github.com/GetTrustedApp/lastid.co, and the old "pass project_key" error
  // invited it to invent one on retry. We resolve the repo from where the work
  // is happening — the sticky last-project (PreToolUse records it from the
  // operative path's git remote), falling back to this process's cwd — and run
  // it through normalizeRemoteUrl, so the key is always the REAL, lowercased
  // host/owner/repo. Any agent-supplied project_key is dropped.
  if (name === 'lastid_memory_write' || name === 'lastid_memory_draft') {
    if ('project_key' in args) delete args.project_key;
    // Filesystem-derived (injectable for tests). Sticky = the operative path's
    // git remote PreToolUse recorded; cwd is the fallback. Never the agent.
    const repo =
      (typeof resolveRepo === 'function' ? resolveRepo() : readLastProject(scope) || projectKeyForPath(process.cwd())) || null;
    const canProject = Buffer.isBuffer(loadedAgent.projectRootSeed);
    // Repo work defaults to the PROJECT tier (shared, opt-out) when we can both
    // detect a real repo AND publish it. A genuinely personal note can still
    // pass tier:'agent' explicitly.
    if (!args.tier && repo && canProject) {
      args = { ...args, tier: 'project' };
    }
    if (args.tier === 'project') {
      if (!repo) {
        return err(
          "can't scope a project memory — no repo is in context. Read or edit a file in the repo first (the repo is detected automatically from its git remote; you never supply it), then save. Or use tier:'agent' for a private note.",
        );
      }
      args = { ...args, project_key: repo };
    }
  }
  // A project-tier write needs the operator's project_root_seed (sealed at
  // provisioning). If this session's bundle lacks it — the agent predates
  // project memories, OR a long-lived server cached a pre-reprovision bundle —
  // the write fails at publishAgentMemory's seed guard with a misleading
  // "server write failed". Surface the REAL reason so it isn't mistaken for an
  // IdP problem (that misread cost an hour-long IdP hunt once).
  if (
    (name === 'lastid_memory_write' || name === 'lastid_memory_draft') &&
    args.tier === 'project' &&
    !Buffer.isBuffer(loadedAgent.projectRootSeed)
  ) {
    return err(
      "can't write a project-tier memory: no project_root_seed is loaded for this agent in this session. " +
        'If you just (re)provisioned, restart the session to pick it up; otherwise this agent predates project memories and needs reprovisioning.',
    );
  }
  try {
    switch (name) {
      case 'lastid_memory_write': {
        const m = store.write(args); // local cache
        if (!(await live(m, 'active'))) {
          store.forget(m.id, { hard: true }); // roll back — IdP is authoritative
          return notSaved();
        }
        audit('AgentMemoryWritten', m.id, {
          kind: m.kind,
          tier: m.tier,
          bedrock: String(m.bedrock === true),
          source_kind: m.source?.kind,
          sensitivity: m.sensitivity,
        });
        return ok({ ok: true, memory: publicView(store.get(m.id) ?? m) });
      }
      case 'lastid_memory_draft': {
        // Drafts ride to the IdP (content.status='drafted', record status
        // 'active' so peers sync it) — used immediately as a marked draft, not
        // audit-chained until confirmed (the chain logs decisions, not proposals).
        const m = store.draft(args);
        if (!(await live(m, 'active'))) {
          store.forget(m.id, { hard: true });
          return notSaved();
        }
        const shared = m.tier === 'project' && m.project_key;
        return ok({
          ok: true,
          status: 'drafted',
          note: shared
            ? `Saved as a draft (marked unverified) and shared with your operator's agents on ${m.project_key} — usable now; your operator can demote it.`
            : 'Saved as a draft (marked unverified) — usable by you now; your operator can demote or confirm it.',
          memory: publicView(store.get(m.id) ?? m),
        });
      }
      case 'lastid_memory_get': {
        const m = store.get(args.id);
        return m ? ok({ memory: publicView(m) }) : err(`no memory with id ${args.id}`);
      }
      case 'lastid_memory_list':
        return ok({ memories: store.list(args).map(publicView) });
      case 'lastid_memory_search': {
        const hits = await searchMemories(store, args.query, {
          limit: Number.isInteger(args.limit) ? args.limit : 8,
          excludeBedrock: args.exclude_bedrock === true,
          embedder: makeEmbedder({ scope }),
        });
        return ok({ query: args.query, hits });
      }
      case 'lastid_memory_update': {
        const before = store.get(args.id);
        if (!before) return err(`no memory with id ${args.id}`);
        const snapshot = structuredClone(before);
        const m = store.update(args.id, args);
        if (!(await live(m, 'active'))) {
          store.put(snapshot); // roll back to pre-update
          return notSaved();
        }
        const fields = ['claim', 'summary', 'sensitivity', 'status', 'bedrock', 'expires_at', 'clear_expires_at']
          .filter((k) => args[k] !== undefined);
        audit('AgentMemoryUpdated', m.id, {
          fields_changed: fields.join(','),
          ...(typeof args.reason === 'string' ? { reason: args.reason } : {}),
        });
        return ok({ ok: true, memory: publicView(store.get(m.id) ?? m) });
      }
      case 'lastid_memory_forget': {
        const before = store.get(args.id);
        if (!before) return err(`no memory with id ${args.id}`);
        const tombVersion = (Number(before.version) || 1) + 1;
        // Revoke at the IdP first; only drop locally once the server confirms.
        if (!(await live({ id: args.id, tier: before.tier ?? 'agent', version: tombVersion }, 'revoked'))) {
          return notSaved('the forget did not reach the server');
        }
        store.forget(args.id, { hard: args.hard_delete === true });
        audit('AgentMemoryForgotten', args.id, {
          hard_delete: String(args.hard_delete === true),
          ...(typeof args.reason === 'string' ? { reason: args.reason } : {}),
        });
        return ok({ ok: true, id: args.id, hard_delete: args.hard_delete === true });
      }
      default:
        return err(`unknown memory tool: ${name}`);
    }
  } catch (e) {
    return err(e?.message ?? String(e));
  }
}
