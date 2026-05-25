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
import { searchMemories } from './memory-tools.js';

const PACKET_PREAMBLE =
  'The following memories are ground truth about the operator and project. ' +
  'When they conflict with your training data or general assumptions, the ' +
  'memories WIN. Cite the memory id (e.g. [mem_abc]) when you use one.';

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
      }))
      .filter((m) => m.claim.length > 0);
  } catch {
    return [];
  }
}

function renderItem(m) {
  const summary = m.summary && m.summary.trim().length > 0 ? ` ${m.summary.trim()}` : '';
  return `- [${m.id ?? m.memory_id}] ${m.claim}${summary}`;
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
} = {}) {
  const mem = store ?? new MemoryStore(scope, undefined, { agentDid, parentHumanDid });

  const bedrock = [...mem.bedrockMemories().map((m) => ({ id: m.id, claim: m.claim, summary: m.summary })), ...operatorBedrock(operatorStore)];

  const topical = await searchMemories(mem, prompt ?? '', {
    limit: topicalLimit,
    excludeBedrock: true,
    embedder,
  });

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
} = {}) {
  const mem = store ?? new MemoryStore(scope, undefined, { agentDid, parentHumanDid });
  const hits = await searchMemories(mem, query ?? '', { limit, excludeBedrock, embedder });
  if (hits.length === 0) return '';
  const lines = ['<lastid-memory source="ambient">'];
  for (const h of hits) {
    const score = typeof h.score === 'number' ? ` [match ${h.score.toFixed(2)}]` : '';
    const subject = Array.isArray(h.subject) && h.subject.length > 0 ? ` (subject: ${h.subject.join(', ')})` : '';
    lines.push(`- [${h.memory_id}] ${h.claim}${score}${subject}`);
    if (h.summary && h.summary.trim().length > 0) lines.push(`  ${h.summary.trim()}`);
  }
  lines.push('</lastid-memory>');
  return lines.join('\n');
}
