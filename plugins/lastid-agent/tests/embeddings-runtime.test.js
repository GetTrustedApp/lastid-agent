/**
 * Embeddings runtime location — the dep (@xenova/transformers) MUST live in a
 * stable, version-independent dir so `/plugin update` doesn't orphan it and
 * silently drop semantic memory to keyword (the bug: it used to install into
 * the per-version plugin node_modules). These lock that.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';

import { embeddingsRuntimeDir, embeddingsInstalled } from '../lib/embeddings.js';

test('runtime dir is version-independent (survives plugin updates)', () => {
  const dir = embeddingsRuntimeDir();
  // Under ~/.lastid-agent, NOT inside the per-version plugin install.
  assert.equal(dir, join(homedir(), '.lastid-agent', 'embeddings-runtime'));
  assert.doesNotMatch(dir, /plugins[/\\]lastid-agent/, 'must not be under the plugin dir');
  assert.doesNotMatch(dir, /\d+\.\d+\.\d+/, 'must not contain a version number');
  // Stable across calls.
  assert.equal(embeddingsRuntimeDir(), dir);
});

test('embeddingsInstalled resolves the dep from the stable runtime dir', async () => {
  const root = mkdtempSync(join(tmpdir(), 'lastid-embruntime-'));
  after(() => {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best-effort */ }
  });
  // Plant a minimal resolvable @xenova/transformers under <root>/node_modules.
  const pkgDir = join(root, 'node_modules', '@xenova', 'transformers');
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(
    join(pkgDir, 'package.json'),
    JSON.stringify({ name: '@xenova/transformers', version: '0.0.0-test', type: 'module', main: './index.js' }),
  );
  writeFileSync(join(pkgDir, 'index.js'), 'export const pipeline = () => {}; export const env = {};\n');

  assert.equal(await embeddingsInstalled({ runtimeDir: root }), true);
});
