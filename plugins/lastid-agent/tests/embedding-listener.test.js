/**
 * Tests for the warm embedding daemon (lib/embedding-listener.js) + client
 * (embeddings.js::embedViaListener / makeEmbedder daemon-first). Skips when
 * the opt-in embeddings dep is absent. Also verifies the graceful fallback
 * when no daemon is running.
 */
import { test } from 'node:test';
import assert from 'node:assert';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';

import { startEmbeddingServer } from '../lib/embedding-listener.js';
import {
  embedViaListener,
  makeEmbedder,
  embeddingsInstalled,
  EMBED_DIM,
} from '../lib/embeddings.js';

const HAS_EMB = await embeddingsInstalled();

test('embedViaListener: no daemon running → resolves null (fast)', async () => {
  const v = await embedViaListener(`test-${randomUUID()}`, 'hello', 500);
  assert.equal(v, null);
});

test('embedding daemon: serves a warm vector over the socket', { skip: !HAS_EMB }, async () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  let server;
  try {
    const r = await startEmbeddingServer({ scope });
    assert.equal(r.status, 'listening');
    server = r.server;

    const direct = await embedViaListener(scope, 'how do I install packages safely', 8000);
    assert.ok(Array.isArray(direct) && direct.length === EMBED_DIM, 'daemon returns a 384-vec');

    // makeEmbedder with scope should resolve via the daemon.
    const viaMaker = await makeEmbedder({ scope, daemonOnly: true })('another query');
    assert.ok(Array.isArray(viaMaker) && viaMaker.length === EMBED_DIM, 'daemon-only embedder works');
  } finally {
    if (server) await new Promise((res) => server.close(res));
    rmSync(dir, { recursive: true, force: true });
  }
});
