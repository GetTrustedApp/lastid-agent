/**
 * Local embeddings for topical memory search.
 *
 * Port of the desktop's fastembed/all-MiniLM-L6-v2 path to Node via
 * @xenova/transformers. Same model + 384 dims, so the embedding space
 * matches. The dependency is HEAVY (~137MB incl. onnxruntime native
 * binaries) so it is NOT part of the plugin's fast first-run bootstrap —
 * installing it there would stall the MCP server past the runtime's connect
 * timeout. It is opt-in via `lastid-agent memory-setup`; until then memory
 * search degrades gracefully to keyword scoring (see memory-tools.js).
 *
 * Everything here is lazy + best-effort: if @xenova/transformers isn't
 * installed (or the model can't load), the embedder fn returns null and the
 * caller falls back to keyword. The model caches under ~/.lastid-agent/models.
 */
import { join } from 'node:path';
import { homedir } from 'node:os';
import { memoryEmbeddingText } from './memory-store.js';

export const EMBED_MODEL = 'Xenova/all-MiniLM-L6-v2';
export const EMBED_MODEL_VERSION = 'all-MiniLM-L6-v2';
export const EMBED_DIM = 384;
/** Cosine floor for semantic topical hits. The desktop used 0.72 but that was
 *  calibrated for a different setup; quantized MiniLM scores ~0.3 for related
 *  text, so a low floor + top-K is the right shape here. */
export const SEMANTIC_FLOOR = 0.2;

export function modelCacheDir() {
  return join(homedir(), '.lastid-agent', 'models');
}

let _pipelinePromise = null; // shared across makeEmbedder() callers
let _unavailable = false; // sticky: once the dep/model fails, stop retrying this process

async function loadPipeline() {
  if (_unavailable) return null;
  if (_pipelinePromise) return _pipelinePromise;
  _pipelinePromise = (async () => {
    let transformers;
    try {
      transformers = await import('@xenova/transformers');
    } catch {
      _unavailable = true;
      return null; // dep not installed → keyword fallback
    }
    try {
      const { pipeline, env } = transformers;
      env.cacheDir = modelCacheDir();
      env.allowRemoteModels = true; // download on first use, then cache
      return await pipeline('feature-extraction', EMBED_MODEL, { quantized: true });
    } catch (err) {
      _unavailable = true;
      process.stderr.write(`[lastid-agent] embeddings unavailable: ${err?.message ?? err}\n`);
      return null;
    }
  })();
  return _pipelinePromise;
}

/** Is the embeddings dependency importable (installed)? Cheap check for
 *  memory-setup + status, doesn't load the model. */
export async function embeddingsInstalled() {
  try {
    await import('@xenova/transformers');
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns an async embedder fn (text → number[384]) or, when embeddings are
 * unavailable, a fn that resolves null. Always returns a function so callers
 * can `await embedder(text)` and branch on null. Mean-pooled + L2-normalized,
 * matching the desktop's embedding text composition.
 */
export function makeEmbedder() {
  return async function embed(text) {
    if (!text || typeof text !== 'string') return null;
    const extractor = await loadPipeline();
    if (!extractor) return null;
    try {
      const out = await extractor(text, { pooling: 'mean', normalize: true });
      return Array.from(out.data);
    } catch (err) {
      process.stderr.write(`[lastid-agent] embed failed: ${err?.message ?? err}\n`);
      return null;
    }
  };
}

/** Cosine similarity. Inputs are L2-normalized by the embedder, so this is a
 *  dot product, but we normalize defensively in case of mixed sources. */
export function cosine(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * Best-effort: compute + persist the embedding for one memory. No-op if the
 * embedder is unavailable or the memory is gone. Returns true if stored.
 */
export async function embedMemory(store, memoryId, embedder = makeEmbedder()) {
  const m = store.get(memoryId);
  if (!m) return false;
  const vec = await embedder(memoryEmbeddingText(m));
  if (!vec || vec.length !== EMBED_DIM) return false;
  // re-read in case it changed; set on the live record + persist
  const live = store.get(memoryId);
  if (!live) return false;
  live.embedding = vec;
  live.embedding_model_version = EMBED_MODEL_VERSION;
  store.save();
  return true;
}

/**
 * Embed every active memory missing (or stale) an embedding. Returns the
 * count embedded. Used on search (lazy backfill so memories written before
 * embeddings were installed get vectors) and by memory-setup.
 */
export async function backfillEmbeddings(store, embedder = makeEmbedder()) {
  let n = 0;
  for (const m of store.activeMemories()) {
    if (Array.isArray(m.embedding) && m.embedding.length === EMBED_DIM) continue;
    if (await embedMemory(store, m.id, embedder)) n += 1;
  }
  return n;
}
