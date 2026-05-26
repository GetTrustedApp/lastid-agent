/**
 * Memory retrieval + packet composition (local).
 *
 * Ports the desktop /memory/retrieve + /memory/search behaviour to read the
 * agent's LOCAL stores instead of the desktop MCP:
 *   - agent-authored memories  → lib/memory-store.js (MemoryStore)
 *   - operator-authored memories (bedrock ground truth) → operator-store.js,
 *     synced from the IdP via the same rails as rules.
 *
 * Two surfaces (matching the desktop):
 *   - retrievePacket()  → bedrock + topical, one <lastid-memory> markdown
 *     block, for the UserPromptSubmit hook (mandatory injection per turn).
 *   - retrieveSearchHits() → pure topical hits, for the PreToolUse ambient
 *     injection (exclude_bedrock to avoid re-surfacing).
 *
 * Bedrock = always injected. Topical = relevance-ranked (keyword now;
 * cosine once the embeddings layer wires an embedder). Injected memory ids
 * get last_confirmed_at bumped via store.confirm().
 */
import { MemoryStore } from './memory-store.js';
import { searchMemories, keywordScore } from './memory-tools.js';
import { cosine, SEMANTIC_FLOOR } from './embeddings.js';

const PACKET_PREAMBLE =
  'The following memories are ground truth about the operator and project. ' +
  'When they conflict with your training data or general assumptions, the ' +
  'memories WIN. Cite the memory id (e.g. [mem_abc]) when you use one. ' +
  'Entries marked "(draft)" are unverified proposals (yours or a peer agent\'s ' +
  'on this repo) — usable, but lower-trust than confirmed memories and never ' +
  'treated as ground truth; your operator can demote them. If you need a ' +
  "memory's full content, fetch it by id with lastid_memory_get.";

/**
 * Operator-authored bedrock memories from the synced operator-store, if any.
 * Defensive about the content shape (the browser authoring schema lands in a
 * later task): expects records of kind 'memory' with content.{claim,summary,
 * bedrock,subject}. Returns the normalized {id, claim, summary} shape.
 */
function operatorBedrock(operatorStore) {
  if (!operatorStore || typeof operatorStore.listMemories !== 'function') return [];
  try {
    return operatorStore
      .listMemories()
      .filter((r) => r?.content && r.content.bedrock === true)
      .map((r) => ({
        id: r.id,
        claim: typeof r.content.claim === 'string' ? r.content.claim : '',
        summary: typeof r.content.summary === 'string' ? r.content.summary : undefined,
        tier: 'operator',
      }))
      .filter((m) => m.claim.length > 0);
  } catch {
    return [];
  }
}

/**
 * Tier/trust tag for an injected line: `(project)`, `(global)`, `(agent)`,
 * `(operator)`, combined with draft → `(project, draft)`. Lets the agent (and
 * the operator reading the packet) tell COLLECTIVE ground truth — global +
 * project, shared across all the operator's agents (agent_did is null, so a
 * peer agent may have authored it) — from PRIVATE agent-tier (just this agent),
 * and tentative drafts from confirmed memories. No tag when tier is unknown.
 */
function tierLabel(m) {
  const parts = [];
  if (m.tier) parts.push(m.tier);
  if (m.draft) parts.push('draft');
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

function renderItem(m) {
  const summary = m.summary && m.summary.trim().length > 0 ? ` ${m.summary.trim()}` : '';
  return `- [${m.id ?? m.memory_id}]${tierLabel(m)} ${m.claim}${summary}`;
}

/**
 * Topically rank operator-authored (synced) memories that are NOT bedrock
 * (bedrock is always injected separately). Operator-store records carry no
 * persisted embedding, so we embed their text on the fly when an embedder is
 * available (the warm daemon makes this cheap), else keyword. Returns hits in
 * the same shape as searchMemories.
 */
async function topicalOperatorMemories(operatorStore, query, embedder, limit) {
  if (!operatorStore || typeof operatorStore.listMemories !== 'function' || !query) return [];
  let candidates;
  try {
    candidates = operatorStore
      .listMemories()
      .filter((r) => r?.content && r.content.bedrock !== true && typeof r.content.claim === 'string' && r.content.claim.length > 0)
      .map((r) => ({
        id: r.id,
        claim: r.content.claim,
        summary: typeof r.content.summary === 'string' ? r.content.summary : undefined,
        subject: Array.isArray(r.content.subject) ? r.content.subject : [],
      }));
  } catch {
    return [];
  }
  if (candidates.length === 0) return [];

  let scored = null;
  if (typeof embedder === 'function') {
    const qvec = await embedder(query);
    if (Array.isArray(qvec)) {
      scored = [];
      for (const c of candidates) {
        const text = [c.claim, c.summary, ...(c.subject ?? [])].filter(Boolean).join('\n');
        const v = await embedder(text);
        const score = Array.isArray(v) ? cosine(qvec, v) : 0;
        if (score >= SEMANTIC_FLOOR) scored.push({ c, score });
      }
    }
  }
  if (!scored) {
    scored = candidates
      .map((c) => ({ c, score: keywordScore(query, c) }))
      .filter((x) => x.score > 0);
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map(({ c, score }) => ({
    memory_id: c.id,
    claim: c.claim,
    ...(c.summary ? { summary: c.summary } : {}),
    subject: c.subject,
    score: Number(score.toFixed(4)),
    tier: 'operator',
  }));
}

/**
 * Build the bedrock + topical retrieval packet for `prompt`. Returns
 * { markdown, injectedIds }. Empty markdown ('') when there's nothing.
 */
export async function retrievePacket({
  scope = 'main',
  agentDid = null,
  parentHumanDid = null,
  prompt,
  topicalLimit = 6,
  operatorStore = null,
  embedder = null,
  store = null,
  projectKey = null,
} = {}) {
  const mem = store ?? new MemoryStore(scope, undefined, { agentDid, parentHumanDid });

  // Bedrock = global + agent always-inject (bedrockMemories excludes project),
  // operator-authored bedrock, PLUS this repo's project bedrock when we know
  // which repo we're in (projectKey). Project bedrock injects every turn the
  // agent works in that repo; it never appears for unrelated work.
  const bedrock = [
    ...mem.bedrockMemories().map((m) => ({ id: m.id, claim: m.claim, summary: m.summary, tier: m.tier })),
    ...operatorBedrock(operatorStore),
    ...mem.projectBedrockMemories(projectKey).map((m) => ({ id: m.id, claim: m.claim, summary: m.summary, tier: 'project' })),
  ];

  // Topical = agent-authored + operator-authored (non-bedrock), ranked
  // together. Each side scores on the same cosine/keyword basis, so merging
  // by score is apples-to-apples. `projectKey` lets this repo's project
  // memories into the topical pool (and keeps other repos' out).
  const [agentTopical, opTopical] = await Promise.all([
    searchMemories(mem, prompt ?? '', { limit: topicalLimit, excludeBedrock: true, embedder, projectKey, includeDrafts: true }),
    topicalOperatorMemories(operatorStore, prompt ?? '', embedder, topicalLimit),
  ]);
  const topical = [...agentTopical, ...opTopical]
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, topicalLimit);

  if (bedrock.length === 0 && topical.length === 0) {
    return { markdown: '', injectedIds: [] };
  }

  const lines = ['<lastid-memory>', PACKET_PREAMBLE];
  if (bedrock.length > 0) {
    lines.push('', '## Bedrock', ...bedrock.map(renderItem));
  }
  if (topical.length > 0) {
    lines.push('', '## Relevant to this turn', ...topical.map(renderItem));
  }
  lines.push('</lastid-memory>');

  const injectedIds = [
    ...bedrock.map((m) => m.id),
    ...topical.map((m) => m.memory_id),
  ].filter(Boolean);

  // Bump last_confirmed_at on the agent-authored ones we surfaced.
  try {
    mem.confirm(injectedIds.filter((id) => mem.get(id)));
  } catch {
    // best-effort
  }

  return { markdown: lines.join('\n'), injectedIds };
}

/**
 * Pure topical hits for the ambient (PreToolUse) path. Returns a compact
 * <lastid-memory source="ambient"> block, or '' when nothing is relevant.
 */
export async function retrieveSearchBlock({
  scope = 'main',
  agentDid = null,
  parentHumanDid = null,
  query,
  limit = 5,
  excludeBedrock = true,
  embedder = null,
  store = null,
  projectKey = null,
} = {}) {
  const mem = store ?? new MemoryStore(scope, undefined, { agentDid, parentHumanDid });
  const hits = await searchMemories(mem, query ?? '', { limit, excludeBedrock, embedder, projectKey, includeDrafts: true });
  // When the agent is working in a repo, always surface that repo's project
  // bedrock (ground truth) here too — so moving to a new repo mid-turn brings
  // its always-inject memories immediately, not just on the next turn. These
  // are bedrock so they're never in `hits` (which excludes bedrock) — no dup.
  const projBedrock = projectKey ? mem.projectBedrockMemories(projectKey) : [];
  if (hits.length === 0 && projBedrock.length === 0) return '';
  const lines = ['<lastid-memory source="ambient">'];
  if (projBedrock.length > 0) {
    lines.push(`Ground truth for this project (${projectKey}):`);
    for (const m of projBedrock) {
      lines.push(`- [${m.id}] (project) ${m.claim}`);
      if (m.summary && m.summary.trim().length > 0) lines.push(`  ${m.summary.trim()}`);
    }
  }
  for (const h of hits) {
    const score = typeof h.score === 'number' ? ` [match ${h.score.toFixed(2)}]` : '';
    const subject = Array.isArray(h.subject) && h.subject.length > 0 ? ` (subject: ${h.subject.join(', ')})` : '';
    lines.push(`- [${h.memory_id}]${tierLabel(h)} ${h.claim}${score}${subject}`);
    if (h.summary && h.summary.trim().length > 0) lines.push(`  ${h.summary.trim()}`);
  }
  lines.push('</lastid-memory>');
  return lines.join('\n');
}
