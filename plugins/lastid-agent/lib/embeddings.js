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
import { connect } from 'node:net';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { memoryEmbeddingText } from './memory-store.js';

const require = createRequire(import.meta.url);

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

/**
 * Stable, version-independent home for the embeddings runtime dependency
 * (@xenova/transformers). It used to install into the plugin's PER-VERSION
 * node_modules, so every `/plugin update` orphaned it — the model cache
 * (modelCacheDir, global) survived, but the code to run it didn't, silently
 * dropping semantic search to keyword until memory-setup re-ran. Installing
 * here (via `npm --prefix`) survives updates. memory-setup installs into this
 * dir; resolveTransformers() loads from it.
 */
export function embeddingsRuntimeDir() {
  return join(homedir(), '.lastid-agent', 'embeddings-runtime');
}

/**
 * Resolve @xenova/transformers's entry file — the stable runtime dir FIRST (so
 * it survives plugin updates), then default resolution (dev checkout, or a
 * legacy install in the plugin's own node_modules). Returns the path, or null
 * if not installed anywhere. @xenova/transformers is a plain ESM package
 * (type:module, `main`, no `exports` map), so require.resolve gives the ESM
 * main and a dynamic import of that path loads the same module as a bare
 * import. `runtimeDir` overrides the stable dir (tests only).
 */
function resolveTransformers({ runtimeDir } = {}) {
  const stable = join(runtimeDir ?? embeddingsRuntimeDir(), 'node_modules');
  try {
    return require.resolve('@xenova/transformers', { paths: [stable] });
  } catch {
    /* not in the stable dir — fall through to default resolution */
  }
  try {
    return require.resolve('@xenova/transformers');
  } catch {
    return null;
  }
}

/** Unix socket the listener's embedding daemon listens on. */
export function embedSocketPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'embed.sock');
}

/**
 * Ask the warm embedding daemon (running in the listener) to embed `text`.
 * Newline-delimited JSON over a unix socket: send {text}, read {vector} or
 * {error}. Returns the vector, or null if the daemon isn't running / errors
 * / times out (caller falls back to in-process or keyword). Fast path — the
 * model is already loaded in the listener, so this avoids per-spawn init.
 */
export function embedViaListener(scope, text, timeoutMs = 2500) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(v);
    };
    let sock;
    try {
      sock = connect(embedSocketPath(scope));
    } catch {
      return resolve(null);
    }
    const timer = setTimeout(() => done(null), timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    let buf = '';
    sock.on('error', () => done(null)); // ENOENT/ECONNREFUSED → no daemon
    sock.on('connect', () => {
      sock.write(`${JSON.stringify({ text })}\n`);
    });
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      clearTimeout(timer);
      try {
        const msg = JSON.parse(buf.slice(0, nl));
        done(Array.isArray(msg?.vector) && msg.vector.length === EMBED_DIM ? msg.vector : null);
      } catch {
        done(null);
      }
    });
  });
}

let _pipelinePromise = null; // shared across makeEmbedder() callers
let _unavailable = false; // sticky: once the dep/model fails, stop retrying this process

async function loadPipeline() {
  if (_unavailable) return null;
  if (_pipelinePromise) return _pipelinePromise;
  _pipelinePromise = (async () => {
    let transformers;
    try {
      const entry = resolveTransformers();
      if (!entry) throw new Error('@xenova/transformers not installed');
      transformers = await import(pathToFileURL(entry).href);
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

/** Is the embeddings dependency installed? Cheap resolve (no heavy import / no
 *  model load) — checks the stable runtime dir first, then default resolution.
 *  `opts.runtimeDir` overrides the stable dir (tests only). */
export async function embeddingsInstalled(opts = {}) {
  return resolveTransformers(opts) !== null;
}

/**
 * Is the embedding MODEL cached on this host? This is the durable OPT-IN
 * signal: the operator ran memory-setup at some point and downloaded the
 * ~137MB model. The model cache (modelCacheDir, global, version-independent)
 * survives plugin updates even when the runtime dep gets orphaned — so a
 * cached model means "they opted in" and we must keep semantic memory working
 * for them across updates rather than silently dropping to keyword.
 * `opts.cacheDir` overrides the cache dir (tests only).
 */
export function modelInstalled({ cacheDir } = {}) {
  const onnx = join(
    cacheDir ?? modelCacheDir(),
    'Xenova',
    'all-MiniLM-L6-v2',
    'onnx',
    'model_quantized.onnx',
  );
  return existsSync(onnx);
}

/**
 * Install the embeddings runtime dep (@xenova/transformers) into the STABLE,
 * version-independent dir (survives `/plugin update`). The single source of
 * truth for the install command + target, shared by `memory-setup` and the
 * listener self-heal. A mkdir-based lock serializes concurrent installs (two
 * scopes' listeners can start at once and would otherwise corrupt the prefix).
 * Returns `{ status, locked }` — status is the npm exit code (0 = ok); locked
 * is true when another process holds the install lock (caller should no-op).
 */
export function installEmbeddingsRuntime({ log, stdio = ['ignore', 'pipe', 'pipe'] } = {}) {
  const runtimeDir = embeddingsRuntimeDir();
  mkdirSync(runtimeDir, { recursive: true });
  const lockDir = join(runtimeDir, '.install.lock');
  try {
    mkdirSync(lockDir); // atomic: throws EEXIST if another process holds it
  } catch {
    return { status: 1, locked: true };
  }
  try {
    log?.(
      `[lastid-agent] installing local embeddings runtime (@xenova/transformers) into ${runtimeDir}…`,
    );
    const r = spawnSync(
      'npm',
      [
        'install',
        '@xenova/transformers',
        '--prefix',
        runtimeDir,
        '--omit=dev',
        '--no-audit',
        '--no-fund',
      ],
      { stdio },
    );
    return { status: r.status ?? 1, locked: false };
  } finally {
    try {
      rmSync(lockDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

/**
 * Keep an opted-in host's semantic memory working across plugin updates.
 * Idempotent + best-effort:
 *   - dep already resolvable        → { ok: true,  action: 'present' }
 *   - dep missing, model cached     → reinstall the dep into the stable dir
 *     (NO model re-download)        → { ok, action: 'installed' | 'install-failed' | 'install-in-progress' }
 *   - dep missing, model NOT cached → { ok: false, action: 'not-opted-in' }
 *
 * The decision inputs are injected (`_embeddingsInstalled` / `_modelInstalled`
 * / `_install`) so the logic is unit-testable without touching the filesystem
 * or running npm.
 */
export async function ensureEmbeddingsRuntime({
  log,
  _embeddingsInstalled = embeddingsInstalled,
  _modelInstalled = modelInstalled,
  _install = installEmbeddingsRuntime,
} = {}) {
  if (await _embeddingsInstalled()) return { ok: true, action: 'present' };
  if (!_modelInstalled()) return { ok: false, action: 'not-opted-in' };
  const { status, locked } = _install({ log });
  if (locked) return { ok: false, action: 'install-in-progress' };
  if (status !== 0) return { ok: false, action: 'install-failed' };
  return { ok: await _embeddingsInstalled(), action: 'installed' };
}

/** In-process embed: load the model in THIS process and embed. ~0.2s on a
 *  warm disk cache. Used as the fallback when the listener daemon isn't up,
 *  and BY the daemon itself. */
export async function embedInProcess(text) {
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
}

/**
 * Returns an async embedder fn (text → number[384] | null). Always a function
 * so callers can `await embedder(text)` and branch on null.
 *
 * Resolution order:
 *   1. the warm embedding daemon in the listener (fast, one shared model) —
 *      tried when `scope` is given;
 *   2. in-process load (~0.2s warm cache) — unless `daemonOnly`;
 *   3. null → caller falls back to keyword.
 *
 * The MCP server / CLI spawns get warm embeddings for free when the listener
 * is running; otherwise they pay the one-time in-process load.
 */
export function makeEmbedder({ scope = null, daemonOnly = false } = {}) {
  return async function embed(text) {
    if (!text || typeof text !== 'string') return null;
    if (scope) {
      const viaDaemon = await embedViaListener(scope, text);
      if (Array.isArray(viaDaemon)) return viaDaemon;
    }
    if (daemonOnly) return null;
    return embedInProcess(text);
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
