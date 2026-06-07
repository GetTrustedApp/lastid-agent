/**
 * mls-state-store seal/open + diskKvCallbacks, including the MLS-custody
 * wrapKey path: a broker-native agent seals/opens its MLS state with the
 * broker-derived wrap key (byte-identical to deriveWrapKey) instead of the raw
 * slot seed. The load-bearing property: a file sealed under the seed opens under
 * the equivalent wrapKey and vice-versa, so the cutover never strands state.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import {
  deriveWrapKey,
  sealStateBlob,
  openStateBlob,
  sealStateBlobWithKey,
  openStateBlobWithKey,
  diskKvCallbacks,
  stateFilePath,
} from '../lib/mls-state-store.js';

const SEED = Buffer.alloc(32, 0x42);
const STATE = Buffer.from('mls-keystore-blob-bytes').toString('base64');

test('seal/open round-trips with the raw slot seed (legacy)', () => {
  const sealed = sealStateBlob(SEED, STATE);
  assert.equal(openStateBlob(SEED, sealed), STATE);
});

test('CROSS-COMPAT: a file sealed under the seed opens under the broker-equivalent wrapKey', () => {
  // The broker returns exactly deriveWrapKey(seed) (proven by the Rust KAT +
  // the live probe). So the broker-native open path must read legacy files.
  const wrapKey = deriveWrapKey(SEED);
  const sealedBySeed = sealStateBlob(SEED, STATE);
  assert.equal(openStateBlobWithKey(wrapKey, sealedBySeed), STATE, 'wrapKey opens seed-sealed');
  // …and the reverse: a wrapKey-sealed file opens under the seed.
  const sealedByKey = sealStateBlobWithKey(wrapKey, STATE);
  assert.equal(openStateBlob(SEED, sealedByKey), STATE, 'seed opens wrapKey-sealed');
});

test('a WRONG wrap key fails to open (AEAD tag)', () => {
  const sealed = sealStateBlobWithKey(deriveWrapKey(SEED), STATE);
  assert.throws(() => openStateBlobWithKey(Buffer.alloc(32, 0xff), sealed));
});

test('requireWrapKey: a non-32-byte key is rejected on both seal + open', () => {
  assert.throws(() => sealStateBlobWithKey(Buffer.alloc(16), STATE), /32-byte/);
  assert.throws(() => openStateBlobWithKey(Buffer.alloc(16), 'AAAA'), /32-byte/);
});

test('diskKvCallbacks: wrapKey path flushes + loads (broker-native, no raw seed)', async () => {
  const scope = `__mls_wrapkey_${process.pid}`;
  const path = stateFilePath(scope);
  try {
    const wrapKey = deriveWrapKey(SEED);
    const kv = diskKvCallbacks({ wrapKey, scope });
    assert.equal(await kv.loadBlob(), null, 'no file yet → null');
    await kv.flushBlob(STATE);
    assert.equal(await kv.loadBlob(), STATE, 'round-trips via the broker key');

    // A listener that opened the SAME scope with the raw seed reads the same file.
    const legacyKv = diskKvCallbacks({ slotSeed: SEED, scope });
    assert.equal(await legacyKv.loadBlob(), STATE, 'seed path opens wrapKey-sealed file');
  } finally {
    rmSync(dirname(path), { recursive: true, force: true });
  }
});

test('diskKvCallbacks: wrapKey takes precedence when both are supplied', async () => {
  const scope = `__mls_both_${process.pid}`;
  const path = stateFilePath(scope);
  try {
    // Seal a file with the real key via the wrapKey path…
    const wrapKey = deriveWrapKey(SEED);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, sealStateBlobWithKey(wrapKey, STATE), 'utf-8');
    // …then open with both supplied but a BOGUS seed — wrapKey must win.
    const kv = diskKvCallbacks({ wrapKey, slotSeed: Buffer.alloc(32, 0x01), scope });
    assert.equal(await kv.loadBlob(), STATE);
  } finally {
    rmSync(dirname(path), { recursive: true, force: true });
  }
});
