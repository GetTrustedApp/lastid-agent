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

import {
  embeddingsRuntimeDir,
  embeddingsInstalled,
  modelInstalled,
  ensureEmbeddingsRuntime,
} from '../lib/embeddings.js';

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

test('modelInstalled reflects whether the quantized model is cached (the opt-in signal)', () => {
  const cacheDir = mkdtempSync(join(tmpdir(), 'lastid-model-'));
  after(() => {
    try { rmSync(cacheDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  });
  assert.equal(modelInstalled({ cacheDir }), false);
  const onnxDir = join(cacheDir, 'Xenova', 'all-MiniLM-L6-v2', 'onnx');
  mkdirSync(onnxDir, { recursive: true });
  writeFileSync(join(onnxDir, 'model_quantized.onnx'), 'stub');
  assert.equal(modelInstalled({ cacheDir }), true);
});

// ensureEmbeddingsRuntime decision matrix — injected predicates + install spy so
// it's exercised without touching the filesystem or running npm. This is the
// "keep them opted in across `/plugin update`" guarantee.
test('ensureEmbeddingsRuntime: dep already present → no install', async () => {
  let installed = 0;
  const res = await ensureEmbeddingsRuntime({
    _embeddingsInstalled: async () => true,
    _modelInstalled: () => true,
    _install: () => { installed += 1; return { status: 0, locked: false }; },
  });
  assert.deepEqual(res, { ok: true, action: 'present' });
  assert.equal(installed, 0);
});

test('ensureEmbeddingsRuntime: no model (never opted in) → not-opted-in, no install', async () => {
  let installed = 0;
  const res = await ensureEmbeddingsRuntime({
    _embeddingsInstalled: async () => false,
    _modelInstalled: () => false,
    _install: () => { installed += 1; return { status: 0, locked: false }; },
  });
  assert.deepEqual(res, { ok: false, action: 'not-opted-in' });
  assert.equal(installed, 0);
});

test('ensureEmbeddingsRuntime: model cached but dep orphaned → reinstall (kept opted in)', async () => {
  let installed = 0;
  let installedNow = false;
  const res = await ensureEmbeddingsRuntime({
    _embeddingsInstalled: async () => installedNow, // false, then true after install
    _modelInstalled: () => true,
    _install: () => { installed += 1; installedNow = true; return { status: 0, locked: false }; },
  });
  assert.deepEqual(res, { ok: true, action: 'installed' });
  assert.equal(installed, 1);
});

test('ensureEmbeddingsRuntime: install fails → install-failed', async () => {
  const res = await ensureEmbeddingsRuntime({
    _embeddingsInstalled: async () => false,
    _modelInstalled: () => true,
    _install: () => ({ status: 1, locked: false }),
  });
  assert.deepEqual(res, { ok: false, action: 'install-failed' });
});

test('ensureEmbeddingsRuntime: another process holds the install lock → install-in-progress', async () => {
  const res = await ensureEmbeddingsRuntime({
    _embeddingsInstalled: async () => false,
    _modelInstalled: () => true,
    _install: () => ({ status: 1, locked: true }),
  });
  assert.deepEqual(res, { ok: false, action: 'install-in-progress' });
});
