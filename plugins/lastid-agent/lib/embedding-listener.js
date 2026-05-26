/**
 * Embedding daemon — runs inside the long-lived listener so the embedding
 * model is loaded ONCE and stays warm, instead of every per-prompt CLI spawn
 * paying init. Serves newline-delimited JSON over a unix socket at
 * ~/.lastid-agent/<scope>/embed.sock:  {"text":"..."} → {"vector":[...384]}
 * (or {"error":"..."}). Clients: embeddings.js::embedViaListener.
 *
 * Only starts when the opt-in embeddings dependency is installed; otherwise
 * clients fall back to in-process / keyword. Best-effort: a socket error
 * never disrupts the listener's MLS/channel work.
 */
import { createServer } from 'node:net';
import { unlink, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  embedSocketPath,
  embedInProcess,
  embeddingsInstalled,
  modelInstalled,
  ensureEmbeddingsRuntime,
} from './embeddings.js';

export async function startEmbeddingServer({ scope = 'main' } = {}) {
  if (!(await embeddingsInstalled())) {
    // Opted in (the ~137MB model is cached) but the runtime dep is gone? That's
    // almost always a `/plugin update` orphaning the dep. Keep them in: reinstall
    // it into the stable dir (NO model re-download) in the BACKGROUND so we never
    // block the listener's MLS/vault startup, then bind the socket once ready.
    // Never opted in (no model) → stay disabled until `memory-setup`.
    if (!modelInstalled()) {
      return { status: 'disabled', reason: 'embeddings not installed (run `lastid-agent memory-setup`)' };
    }
    void (async () => {
      const res = await ensureEmbeddingsRuntime({
        log: (l) => process.stderr.write(`${l}\n`),
      });
      if (res.ok && res.action === 'installed') {
        process.stderr.write(
          '[lastid-agent] embeddings runtime reinstalled after update — starting daemon\n',
        );
        await startEmbeddingServer({ scope }).catch(() => {});
      } else if (res.action !== 'present') {
        process.stderr.write(`[lastid-agent] embeddings auto-setup: ${res.action}\n`);
      }
    })();
    return {
      status: 'installing',
      reason: 'reinstalling embeddings runtime after update (model already cached)',
    };
  }
  const sockPath = embedSocketPath(scope);
  await mkdir(dirname(sockPath), { recursive: true });
  // Clear a stale socket left by a crashed/previous listener.
  if (existsSync(sockPath)) {
    try {
      await unlink(sockPath);
    } catch {
      /* ignore */
    }
  }

  const server = createServer((conn) => {
    let buf = '';
    conn.on('error', () => {
      /* client vanished mid-request — ignore */
    });
    conn.on('data', (chunk) => {
      buf += chunk.toString('utf-8');
      let nl;
      // Process each complete line; a connection may pipeline requests.
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let req;
        try {
          req = JSON.parse(line);
        } catch {
          conn.write(`${JSON.stringify({ error: 'bad_json' })}\n`);
          continue;
        }
        const text = typeof req?.text === 'string' ? req.text : '';
        void embedInProcess(text)
          .then((vec) => {
            if (!conn.destroyed) {
              conn.write(`${JSON.stringify(vec ? { vector: vec } : { error: 'embed_failed' })}\n`);
            }
          })
          .catch(() => {
            if (!conn.destroyed) conn.write(`${JSON.stringify({ error: 'embed_failed' })}\n`);
          });
      }
    });
  });
  server.on('error', (err) =>
    process.stderr.write(`[lastid-agent] embed server error: ${err.message}\n`),
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(sockPath, resolve);
  });
  // Warm the model so the first real request is instant.
  void embedInProcess('warm up the embedding model').catch(() => {});
  return { status: 'listening', socket: sockPath, server };
}
