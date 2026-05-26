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
        "Storage tier. Default agent. 'project' = shared with all your operator's agents and injected only when working in that repo (use for repo-specific ground truth/decisions).",
    },
    project_key: {
      type: 'string',
      description:
        "For tier='project': the repo (normalized git remote, e.g. github.com/org/repo). Omit to use the repo you're currently working in.",
    },
    subject: {
      type: 'array',
      items: { type: 'string' },
      minItems: 1,
      description: 'Topical tags (≥1) — what the memory is about.',
    },
    claim: { type: 'string', description: 'The memory itself (≤4000 chars).' },
    summary: { type: 'string', description: 'Optional short summary (≤600 chars).' },
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
      'Propose a memory for operator review. Use when YOU inferred something durable (preference, decision, named entity, workflow rule) but the operator did NOT explicitly ask you to save it. Queues for review; does NOT influence future turns until the operator promotes it. Always include source_quote.',
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
        claim: { type: 'string' },
        summary: { type: 'string' },
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
export async function searchMemories(store, query, { limit = 8, excludeBedrock = false, embedder = null, projectKey = null } = {}) {
  const select = () => {
    let c = store.activeMemories();
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
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map(({ m, score }) => ({
    memory_id: m.id,
    claim: m.claim,
    ...(m.summary ? { summary: m.summary } : {}),
    subject: m.subject,
    score: Number(score.toFixed(4)),
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
export async function handleMemoryTool({ name, args = {}, scope = 'main', loadedAgent, claims, fetchImpl }) {
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
  // Project-tier authoring: default project_key to the repo the agent is
  // currently working in (the sticky last-project the PreToolUse hook records)
  // when the model didn't name one. Without any repo context we can't scope it.
  if ((name === 'lastid_memory_write' || name === 'lastid_memory_draft') && args.tier === 'project' && !args.project_key) {
    const sticky = readLastProject(scope);
    if (!sticky) {
      return err(
        "tier='project' needs a repo and none is in context yet — pass project_key (the repo's normalized git remote, e.g. github.com/org/repo), or act in the repo first.",
      );
    }
    args = { ...args, project_key: sticky };
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
        // Drafts ride to the IdP too (content.status='drafted') so the operator
        // sees them for review; not audit-chained until promoted (the chain
        // logs decisions, not proposals).
        const m = store.draft(args);
        if (!(await live(m, 'active'))) {
          store.forget(m.id, { hard: true });
          return notSaved();
        }
        return ok({
          ok: true,
          status: 'drafted',
          note: 'Saved to your operator for review. Will not influence future turns until promoted.',
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
