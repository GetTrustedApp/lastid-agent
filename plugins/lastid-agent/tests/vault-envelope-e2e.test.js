/**
 * End-to-end two-layer envelope, with the REAL wasm — the cross-layer +
 * cross-runtime interop that a base64/format mismatch would silently break:
 *
 *   INNER  console seals the secret to the agent slot key (encryptContent)
 *   OUTER  IdP wraps that opaque blob to the handle pubkey (wasm sdkSealToHandle)
 *   OPEN   agent opens the wrap with the handle priv key (wasm sdkOpenWithHandle)
 *   UNSEAL agent decrypts the inner with its slot key (decryptContent)
 *
 * Proves the layers compose to the original secret, and that a different handle
 * key cannot open the wrap (fails closed).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { encryptContent } from '../lib/agent-content-crypto.js';
import { resolveVaultSecret } from '../lib/vault-cache.js';
import { genVaultHandleKeypair, openWithHandle } from '../lib/sdk-bindings.js';

// The IdP-side seal isn't exposed in sdk-bindings (the agent never seals), so
// reach the raw vendored wasm for sdkSealToHandle — exactly what the IdP loads.
const localRequire = createRequire(import.meta.url);
const wasm = localRequire('../vendor/lastid-agent-wasm/lastid_agent_wasm.js');

test('two-layer envelope composes end-to-end with real wasm', async () => {
  const slotSeed = Buffer.alloc(32, 7);

  // INNER (console): secret JSON sealed to the agent's slot key.
  const innerB64 = encryptContent(
    slotSeed,
    Buffer.from(JSON.stringify({ item_id: 'v', secret: 'sk-LIVE', secret_secondary: 'refresh-LIVE' }), 'utf8'),
  ).toString('base64');

  // Agent mints the ephemeral handle keypair.
  const kp = await genVaultHandleKeypair();

  // OUTER (IdP): wrap the OPAQUE inner to the handle pubkey, bound to handle_id.
  const wrapped = wasm.sdkSealToHandle(kp.public_sec1_b64, 'handle-1', innerB64);
  assert.notEqual(wrapped, innerB64, 'wrap transforms the blob');

  // Agent: open the wrap (handle priv) → unseal (slot) → secret.
  const out = await resolveVaultSecret('v', {
    slotSeed,
    handle: { token: 'handle-1', handlePubB64: kp.public_sec1_b64, handlePrivB64: kp.secret_sec1_b64 },
    fetchWrappedSecret: async () => wrapped,
    openWithHandle,
  });
  assert.equal(out.secret, 'sk-LIVE');
  assert.equal(out.secret_secondary, 'refresh-LIVE');
  out.zeroize();
});

test('a different handle key cannot open the wrap → fails closed', async () => {
  const slotSeed = Buffer.alloc(32, 7);
  const innerB64 = encryptContent(
    slotSeed,
    Buffer.from(JSON.stringify({ item_id: 'v', secret: 'sk-LIVE' }), 'utf8'),
  ).toString('base64');
  const minted = await genVaultHandleKeypair();
  const wrapped = wasm.sdkSealToHandle(minted.public_sec1_b64, 'handle-1', innerB64);

  const attacker = await genVaultHandleKeypair();
  let rejected = null;
  const out = await resolveVaultSecret('v', {
    slotSeed,
    handle: { token: 'handle-1', handlePubB64: attacker.public_sec1_b64, handlePrivB64: attacker.secret_sec1_b64 },
    fetchWrappedSecret: async () => wrapped,
    openWithHandle,
    onReject: (_id, why) => (rejected = why),
  });
  assert.equal(out, null);
  assert.match(rejected, /unwrap failed/);
});

test('the wrong handle_id cannot open the wrap (binding) → fails closed', async () => {
  const slotSeed = Buffer.alloc(32, 7);
  const innerB64 = encryptContent(
    slotSeed,
    Buffer.from(JSON.stringify({ item_id: 'v', secret: 'sk-LIVE' }), 'utf8'),
  ).toString('base64');
  const kp = await genVaultHandleKeypair();
  // Sealed bound to handle-A …
  const wrapped = wasm.sdkSealToHandle(kp.public_sec1_b64, 'handle-A', innerB64);
  // … but the agent's handle token is handle-B → rejected.
  let rejected = null;
  const out = await resolveVaultSecret('v', {
    slotSeed,
    handle: { token: 'handle-B', handlePubB64: kp.public_sec1_b64, handlePrivB64: kp.secret_sec1_b64 },
    fetchWrappedSecret: async () => wrapped,
    openWithHandle,
    onReject: (_id, why) => (rejected = why),
  });
  assert.equal(out, null);
  assert.match(rejected, /unwrap failed/);
});
