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
    tier: { type: 'string', enum: ['agent', 'global'], description: 'Storage tier. Default agent.' },
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
  const { embedding, embedding_model_version, ...rest } = m;
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
export async function searchMemories(store, query, { limit = 8, excludeBedrock = false, embedder = null } = {}) {
  const select = () => {
    const c = store.activeMemories();
    return excludeBedrock ? c.filter((m) => m.bedrock !== true) : c;
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
export async function handleMemoryTool({ name, args = {}, scope = 'main', loadedAgent, claims }) {
  if (!loadedAgent) return err('not provisioned — run `lastid-agent provision` first');
  const store = new MemoryStore(scope, undefined, {
    agentDid: claims?.sub ?? loadedAgent.agentDid ?? null,
    parentHumanDid: claims?.parent_human_did ?? null,
  });
  try {
    switch (name) {
      case 'lastid_memory_write':
        return ok({ ok: true, memory: publicView(store.write(args)) });
      case 'lastid_memory_draft':
        return ok({
          ok: true,
          status: 'drafted',
          note: 'Queued for operator review. Will not influence future turns until promoted.',
          memory: publicView(store.draft(args)),
        });
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
          embedder: makeEmbedder(),
        });
        return ok({ query: args.query, hits });
      }
      case 'lastid_memory_update': {
        const m = store.update(args.id, args);
        return m ? ok({ ok: true, memory: publicView(m) }) : err(`no memory with id ${args.id}`);
      }
      case 'lastid_memory_forget': {
        const done = store.forget(args.id, { hard: args.hard_delete === true });
        return done
          ? ok({ ok: true, id: args.id, hard_delete: args.hard_delete === true })
          : err(`no memory with id ${args.id}`);
      }
      default:
        return err(`unknown memory tool: ${name}`);
    }
  } catch (e) {
    return err(e?.message ?? String(e));
  }
}
