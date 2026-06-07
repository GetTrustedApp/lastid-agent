/**
 * Agent-side provisioning client.
 *
 * Drives the wallet-mediated, BIP85-rooted agent provisioning loop. The
 * agent's stable Ed25519 identity is NOT randomly generated on the host
 * — it is derived from the human's BIP85 `ai_agent_seed` at slot N. The
 * wallet picks the slot, derives the keypair, and seals the slot seed
 * to a one-shot ECDH-P256 envelope key this process supplies.
 *
 * Sequence:
 *
 *   1. Generate an EPHEMERAL P-256 ECDH keypair locally (Node's
 *      `crypto`). This is the LIDE-envelope recipient. NOT the agent's
 *      identity.
 *   2. POST `/v1/oid4vci/agent-provision/initiate` with
 *      `ephemeral_pubkey_jwk` (EC P-256). Receive `user_code` +
 *      `device_code`.
 *   3. Poll `/v1/oid4vci/agent-provision/poll`. The wallet, on approval,
 *      derives slot N's seed from `ai_agent_seed`, derives the Ed25519
 *      identity keypair, signs `human_authorization` with the
 *      delegation_authority key, seals the slot seed to our ephemeral
 *      P-256 pubkey, and POSTs `/complete`. The IdP atomically
 *      allocates slot N and mints the credential offer.
 *   4. On approval the poll response carries
 *      `{ credential_offer_uri, sealed_slot_seed, slot_index,
 *        agent_did }`. We unseal the slot seed with our ephemeral
 *      private key, derive the Ed25519 keypair (HKDF-SHA512 over the
 *      slot seed with info `lastid/agent-keypair/v1`, mirroring the
 *      Rust SDK exactly), and discard the ephemeral key.
 *   5. Exchange the pre-authorized code at `/v1/oid4vci/token`, then
 *      claim the SD-JWT VC at `/v1/oid4vci/credential` with an EdDSA
 *      proof JWT signed by the DERIVED Ed25519 key.
 *
 * The slot seed (32 bytes) + the issued SD-JWT VC + the agent's DID +
 * the slot index are persisted to the host keychain. Next launch can
 * re-derive the identity directly without involving the wallet, and a
 * full host wipe can be recovered by re-running provisioning on slot
 * N+M (the IdP allocates the next free slot).
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  sign as cryptoSign,
  hkdfSync,
} from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createRequire } from 'node:module';
import {
  agentDeviceIdFromP256Jwk,
  agentDeviceIdFromEd25519Jwk,
  machineDeviceIdFromP256Jwk,
} from './agent-device-id.js';
import { getMachineSePubkeyJwk as defaultGetMachineSePubkeyJwk } from './broker-client.js';
import {
  brokerProvisionInitiate as defaultBrokerProvisionInitiate,
  brokerProvisionPoll as defaultBrokerProvisionPoll,
} from './broker-ipc.js';

// The agent's stable identity crypto is owned by the Rust SDK, surfaced
// through the bundled P-256 WASM. We load it directly here (rather than
// via sdk-bindings.js) so the synchronous derivation path stays sync and
// has no init/await dependency — provisioning derives the keypair inline.
const wasmRequire = createRequire(import.meta.url);
const agentWasm = wasmRequire('../vendor/lastid-agent-wasm/lastid_agent_wasm.js');

/** serde_wasm_bindgen returns JWKs as a JS Map; normalize to a plain object. */
function jwkToObject(jwk) {
  if (jwk instanceof Map) return Object.fromEntries(jwk);
  return jwk;
}

// Production IdP by default. Override per-host via the
// `LASTID_IDP_URL` env var or per-invocation via the CLI's
// `--idp <url>` flag. The IdP a freshly-provisioned agent binds
// to gets persisted to the keychain so subsequent sessions of
// that agent route to the same env automatically.
const DEFAULT_IDP = 'https://human.lastid.co';

// LIDE envelope wire-format constants (must match
// `lastid-envelope/src/format.rs`).
const ENVELOPE_MAGIC = Buffer.from([0x4c, 0x49, 0x44, 0x45]); // "LIDE"
const ENVELOPE_VERSION = 0x0001;
const SUITE_ECDH_P256_ONLY = 0x0001;
const HEADER_SIZE = 14;
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const DEK_SIZE = 32;
const RECIPIENT_TYPE_ECDH_P256 = 0x01;

// HKDF info string — must match the Rust SDK exactly. (The
// agent-keypair HKDF info now lives Rust-side only; the WASM owns the
// slot-seed → P-256 scalar derivation.)
const ECDH_DEK_WRAP_INFO = Buffer.from('lastid/v2/ecdh-p256/dek-wrap', 'utf-8');

// HKDF info string for the Ed25519 backward-compat path — must match the
// Rust SDK's original Ed25519 agent-keypair derivation exactly. Existing
// (pre-P256) agents derive their stable Ed25519 seed as
// HKDF-SHA512(ikm=slot_seed, salt=∅, info=`lastid/agent-keypair/v1`)[:32].
const AGENT_KEYPAIR_HKDF_INFO = Buffer.from('lastid/agent-keypair/v1', 'utf-8');

function b64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function b64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj), 'utf-8'));
}

function b64urlDecode(s) {
  // Node's Buffer.from accepts base64url directly; normalize just in
  // case the IdP ever pads.
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Generate an EPHEMERAL ECDH-P256 keypair. This is the envelope
 * recipient for the wallet's sealed slot seed. NOT the agent's
 * stable identity. The private key is discarded after one unseal.
 *
 * Returns { privateKey: KeyObject, publicJwk: { kty, crv, x, y } }.
 */
export function generateEphemeralEnvelopeKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const pubJwk = publicKey.export({ format: 'jwk' });
  return {
    privateKey,
    publicJwk: {
      kty: pubJwk.kty,
      crv: pubJwk.crv,
      x: pubJwk.x,
      y: pubJwk.y,
    },
  };
}

/**
 * Step 1: tell the IdP we want a credential. Surface user_code to the
 * operator so the wallet's approval screen can cross-check.
 */
export async function initiateProvisioning(opts) {
  const idp = opts.idpUrl ?? DEFAULT_IDP;
  // `parent_human_did` is optional in the browser-driven OAuth-
  // device-code flow — when the plugin doesn't know the operator's
  // DID up front, the IdP binds it atomically on the browser
  // console's first authenticated `/pending` GET (see
  // lastid-idp/src/services/agent/agent-provisioning-store.ts
  // attachParentHumanDid). Only include the field when actually
  // supplied; otherwise sending `undefined` serializes as
  // `parent_human_did: null` which the IdP regex-rejects.
  const body = {
    ephemeral_pubkey_jwk: opts.ephemeralPubkeyJwk,
    runtime_name: opts.runtimeName ?? 'lastid-agent-plugin',
    project_hint: opts.projectHint ?? null,
  };
  if (opts.parentHumanDid) {
    body.parent_human_did = opts.parentHumanDid;
  }
  // The broker's per-machine SE pubkey, when available (macOS + a signed
  // broker present). Lets the wallet sign a `device_authorization` over the
  // machine `md-` at approval, so the IdP registers a parent-owned machine
  // device. The CALLER resolves it via the broker bridge (getMachineSePubkeyJwk)
  // and passes it here; omitted → legacy no-flag-day flow (no machine device).
  if (opts.machineSePubkeyJwk) {
    body.machine_se_pubkey_jwk = opts.machineSePubkeyJwk;
  }
  const response = await fetch(`${idp}/v1/oid4vci/agent-provision/initiate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(
      `initiate failed: ${response.status} ${await response.text()}`,
    );
  }
  return response.json();
}

/**
 * Step 2: poll until the wallet approves. On approval returns
 * `{ credential_offer_uri, sealed_slot_seed, slot_index, agent_did }`.
 * The caller drives the OID4VCI claim flow and unseals the slot seed.
 */
export async function pollUntilApproved(opts) {
  const idp = opts.idpUrl ?? DEFAULT_IDP;
  const intervalMs = (opts.intervalSeconds ?? 5) * 1000;
  const deadlineMs = Date.now() + (opts.timeoutSeconds ?? 600) * 1000;
  while (Date.now() < deadlineMs) {
    const response = await fetch(`${idp}/v1/oid4vci/agent-provision/poll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ device_code: opts.deviceCode }),
    });
    if (response.status === 410) {
      throw new Error(
        `provisioning rejected: ${response.status} ${await response.text()}`,
      );
    }
    if (response.ok) {
      const body = await response.json();
      if (body.status === 'approved' && body.credential_offer_uri) {
        if (!body.sealed_slot_seed || typeof body.slot_index !== 'number') {
          throw new Error(
            'provisioning approved but missing sealed_slot_seed/slot_index — IdP/wallet skew?',
          );
        }
        return {
          credentialOfferUri: body.credential_offer_uri,
          sealedSlotSeed: body.sealed_slot_seed,
          // Optional — present only when the wallet sealed one. Absent for
          // older wallets; the agent then has no project-tier memories.
          sealedProjectRootSeed:
            typeof body.sealed_project_root_seed === 'string'
              ? body.sealed_project_root_seed
              : null,
          slotIndex: body.slot_index,
          agentDid: body.agent_did,
        };
      }
    }
    await delay(intervalMs);
  }
  throw new Error('provisioning timed out before wallet approval');
}

/**
 * Unseal the slot seed from a base64url LIDE envelope using this
 * process's ephemeral P-256 private key. Returns the 32-byte slot seed.
 *
 * Mirrors `lastid-envelope::envelope_decrypt` + `unwrap_ecdh_p256`
 * for the EcdhP256Only suite.
 */
export function unsealSlotSeed(sealedB64Url, ephemeralPrivateKey) {
  const env = b64urlDecode(sealedB64Url);
  if (env.length < HEADER_SIZE) {
    throw new Error('sealed_slot_seed envelope shorter than header');
  }

  // Header
  const magic = env.subarray(0, 4);
  if (!magic.equals(ENVELOPE_MAGIC)) {
    throw new Error(`bad envelope magic: ${magic.toString('hex')}`);
  }
  const version = env.readUInt16LE(4);
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${version}`);
  }
  const suite = env.readUInt16LE(6);
  if (suite !== SUITE_ECDH_P256_ONLY) {
    throw new Error(
      `unsupported envelope suite for slot-seed unseal: 0x${suite.toString(16)} (expected EcdhP256Only)`,
    );
  }
  // flags = env[8]; not relevant for slot seed (no compression / AAD).
  const recipientCount = env[9];
  const payloadLen = env.readUInt32LE(10);
  if (recipientCount !== 1) {
    throw new Error(
      `expected exactly 1 envelope recipient for slot-seed sealing, got ${recipientCount}`,
    );
  }

  // Recipient block: [1B type] [2B key_id_len LE] [key_id] [2B encap_len LE] [encap]
  let cursor = HEADER_SIZE;
  const rtype = env[cursor];
  cursor += 1;
  if (rtype !== RECIPIENT_TYPE_ECDH_P256) {
    throw new Error(`unsupported recipient type: ${rtype} (expected EcdhP256=1)`);
  }
  const keyIdLen = env.readUInt16LE(cursor);
  cursor += 2 + keyIdLen; // skip key_id bytes — we have only one recipient
  const encapLen = env.readUInt16LE(cursor);
  cursor += 2;
  const encap = env.subarray(cursor, cursor + encapLen);
  cursor += encapLen;

  // ECDH-P256 encap layout: [65B ephemeral pubkey SEC1] [12B nonce] [48B wrapped DEK]
  const expectedEncapLen = 65 + NONCE_SIZE + DEK_SIZE + TAG_SIZE;
  if (encap.length !== expectedEncapLen) {
    throw new Error(
      `ECDH-P256 encap is ${encap.length}, expected ${expectedEncapLen}`,
    );
  }
  const sndEphSec1 = encap.subarray(0, 65);
  const wrapNonce = encap.subarray(65, 65 + NONCE_SIZE);
  const wrappedDek = encap.subarray(65 + NONCE_SIZE); // 48 bytes (32 + 16 tag)

  // ECDH: shared secret with the sender's ephemeral pubkey.
  const senderPubKey = createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: b64url(sndEphSec1.subarray(1, 33)),
      y: b64url(sndEphSec1.subarray(33, 65)),
    },
    format: 'jwk',
  });
  const sharedSecret = diffieHellman({
    privateKey: ephemeralPrivateKey,
    publicKey: senderPubKey,
  });

  // HKDF-SHA256(salt=header_bytes, ikm=shared_secret, info=ECDH_DEK_WRAP_INFO) → 32 bytes
  const headerBytes = env.subarray(0, HEADER_SIZE);
  const wrapKey = Buffer.from(
    hkdfSync('sha256', sharedSecret, headerBytes, ECDH_DEK_WRAP_INFO, 32),
  );

  // AES-256-GCM unwrap DEK.
  const dek = aesGcmDecrypt(wrapKey, wrapNonce, wrappedDek);

  // Payload: [12B nonce] [payload_len bytes ciphertext+tag]
  const payloadNonce = env.subarray(cursor, cursor + NONCE_SIZE);
  cursor += NONCE_SIZE;
  const payloadCt = env.subarray(cursor, cursor + payloadLen);

  const slotSeed = aesGcmDecrypt(dek, payloadNonce, payloadCt);
  if (slotSeed.length !== 32) {
    throw new Error(`slot seed must decrypt to 32 bytes, got ${slotSeed.length}`);
  }
  return slotSeed;
}

function aesGcmDecrypt(key, nonce, ciphertextAndTag) {
  if (ciphertextAndTag.length < TAG_SIZE) {
    throw new Error('ciphertext shorter than GCM tag');
  }
  const ct = ciphertextAndTag.subarray(0, ciphertextAndTag.length - TAG_SIZE);
  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - TAG_SIZE);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function aesGcmEncrypt(key, nonce, plaintext) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

/**
 * Inverse of `unsealSlotSeed`: seal a 32-byte slot seed into a
 * base64url LIDE envelope (EcdhP256Only suite) for a recipient's P-256
 * public JWK.
 *
 * This is the wallet/IdP side of the handshake — in production the
 * agent only ever UNSEALS. It lives here, next to `unsealSlotSeed` and
 * sharing the same wire-format constants, so the two halves can never
 * drift; it is exposed only via `_internal` for the end-to-end
 * provisioning test, which stands up a mock IdP that must produce
 * envelopes the real `unsealSlotSeed` accepts.
 */
function sealSlotSeed(slotSeed, recipientPublicJwk) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new TypeError('slotSeed must be a 32-byte Buffer');
  }
  const payloadLen = slotSeed.length + TAG_SIZE; // ciphertext + GCM tag

  // Header — must match unsealSlotSeed's parser exactly.
  const header = Buffer.alloc(HEADER_SIZE);
  ENVELOPE_MAGIC.copy(header, 0);
  header.writeUInt16LE(ENVELOPE_VERSION, 4);
  header.writeUInt16LE(SUITE_ECDH_P256_ONLY, 6);
  header[8] = 0; // flags: no compression / AAD
  header[9] = 1; // exactly one recipient
  header.writeUInt32LE(payloadLen, 10);

  // Sender ephemeral P-256 keypair; ECDH against the recipient pubkey.
  const sender = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const sndJwk = sender.publicKey.export({ format: 'jwk' });
  const sndEphSec1 = Buffer.concat([
    Buffer.from([0x04]),
    b64urlDecode(sndJwk.x),
    b64urlDecode(sndJwk.y),
  ]);
  const sharedSecret = diffieHellman({
    privateKey: sender.privateKey,
    publicKey: createPublicKey({ key: recipientPublicJwk, format: 'jwk' }),
  });

  // wrapKey = HKDF-SHA256(salt=header, ikm=shared_secret, info=DEK_WRAP).
  const wrapKey = Buffer.from(
    hkdfSync('sha256', sharedSecret, header, ECDH_DEK_WRAP_INFO, 32),
  );

  const dek = randomBytes(DEK_SIZE);
  const wrapNonce = randomBytes(NONCE_SIZE);
  const wrappedDek = aesGcmEncrypt(wrapKey, wrapNonce, dek); // 32 + 16
  const payloadNonce = randomBytes(NONCE_SIZE);
  const payloadCt = aesGcmEncrypt(dek, payloadNonce, slotSeed); // 32 + 16

  // encap: [65B sender SEC1] [12B wrap nonce] [48B wrapped DEK]
  const encap = Buffer.concat([sndEphSec1, wrapNonce, wrappedDek]);
  // recipient block: [1B type] [2B key_id_len=0] [2B encap_len] [encap]
  const recipientBlock = Buffer.alloc(1 + 2 + 2);
  recipientBlock[0] = RECIPIENT_TYPE_ECDH_P256;
  recipientBlock.writeUInt16LE(0, 1); // key_id_len
  recipientBlock.writeUInt16LE(encap.length, 3); // encap_len

  const env = Buffer.concat([
    header,
    recipientBlock,
    encap,
    payloadNonce,
    payloadCt,
  ]);
  return b64url(env);
}

/**
 * Derive the agent's stable NIST P-256 (ES256) identity from its 32-byte
 * slot seed. The derivation is owned by the Rust SDK
 * (`lastid_identity::AgentKeypair::from_seed`) and reached through the
 * bundled P-256 WASM (`agentKeypairFromSeed`) — single source of truth,
 * so the plugin cannot drift from the SDK/IdP on the seed→DID chain.
 *
 * Returns `{ signingKey, publicJwk, signingSeed, agentDid }`:
 *   - signingKey:  Node P-256 KeyObject (used by `node:crypto`
 *                  KeyObject-shaped paths — memory-audit chain signing
 *                  and any other ECDSA-via-node consumer).
 *   - publicJwk:   `{ kty:'EC', crv:'P-256', x, y }` (the agent's holder
 *                  / cnf JWK; backs `did:lastid:agent:` + device-id).
 *   - signingSeed: Raw 32-byte P-256 private scalar (used by the WASM
 *                  signing exports — `mintPopJwt`, `mintOid4vciProofJwtEs256`,
 *                  `signSessionFingerprint`, `signParentAuthorization` — which
 *                  take raw key bytes, not KeyObjects). Despite the legacy
 *                  name this is the ECDSA scalar, NOT an Ed25519 seed.
 *
 * The seed/scalar is intentionally NOT zeroized here — the caller now
 * owns its lifetime. Callers that only need the public identity should
 * destructure `{ publicJwk, agentDid }`; callers that sign keep the
 * scalar for the session and discard at teardown.
 */
/**
 * BACKWARD-COMPAT (existing Ed25519 agents). Derive the agent's stable
 * Ed25519 (EdDSA) identity from its 32-byte slot seed. This is the
 * ORIGINAL pre-P256 derivation — existing agents (`did:lastid:agent:z6Mk…`)
 * keep it so their DPoP proof stays EdDSA, their VC cnf matches, and their
 * `ad-` device_id is the Ed25519 one the IdP key-package store is keyed by.
 *
 * HKDF-SHA512(ikm=slot_seed, salt=∅, info=`lastid/agent-keypair/v1`) → 32-byte
 * Ed25519 seed → RFC 8410 PKCS8 → `createPrivateKey`. Returns
 * `{ signingKey, publicJwk:{kty:'OKP',crv:'Ed25519',x}, signingSeed }`.
 * PURE JS (no wasm) — mirrors the Rust SDK's original Ed25519 path.
 */
export function deriveAgentEd25519Keypair(slotSeed) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('slot seed must be a 32-byte Buffer');
  }
  const signingSeed = Buffer.from(
    hkdfSync('sha512', slotSeed, Buffer.alloc(0), AGENT_KEYPAIR_HKDF_INFO, 32),
  );

  // RFC 8410 §7: Ed25519 private key PKCS8 = SEQUENCE { version=0, alg, OCTET STRING(OCTET STRING(seed)) }
  // We construct the DER inline: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes seed>
  const pkcs8 = Buffer.concat([
    Buffer.from([
      0x30, 0x2e,
      0x02, 0x01, 0x00,
      0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
      0x04, 0x22,
      0x04, 0x20,
    ]),
    signingSeed,
  ]);
  const signingKey = createPrivateKey({
    key: pkcs8,
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(signingKey);
  const pubJwk = publicKey.export({ format: 'jwk' });
  return {
    signingKey,
    publicJwk: {
      kty: pubJwk.kty,
      crv: pubJwk.crv,
      x: pubJwk.x,
    },
    signingSeed,
  };
}

/**
 * Feature-detect an existing agent's identity algorithm from its DID.
 * The canonical multicodec-0xed01 (ed25519-pub) multibase prefix is
 * `z6Mk`; P-256 (`did:key` p256-pub=0x1200) encodes to `zDn…`. We branch
 * purely on the multibase suffix so NO key material is needed to pick the
 * derivation/sign path for a stored agent.
 *
 * @param {string} agentDid e.g. `did:lastid:agent:z6Mk…` or `…:zDn…`
 * @returns {'ed25519'|'p256'}
 */
export function agentKeyTypeFromDid(agentDid) {
  const PREFIX = 'did:lastid:agent:';
  const multibase =
    typeof agentDid === 'string' && agentDid.startsWith(PREFIX)
      ? agentDid.slice(PREFIX.length)
      : '';
  return multibase.startsWith('z6Mk') ? 'ed25519' : 'p256';
}

/**
 * Dispatcher: derive the right keypair for an EXISTING agent given its
 * stored DID. Ed25519 agents (`z6Mk…`) get the pure-JS EdDSA path; everyone
 * else (new agents) gets the wasm-owned P-256 path. The returned shape is
 * uniform (`{ signingKey, publicJwk, signingSeed, agentDid }`) so call sites
 * don't branch — the Ed25519 path attaches the passed-in DID (the wasm path
 * already returns its own derived `agentDid`).
 *
 * NEW-agent provisioning does NOT go through here — it calls
 * `deriveAgentP256Keypair` directly (new agents are always P-256).
 *
 * @param {Buffer} slotSeed 32-byte BIP85 slot seed
 * @param {string} agentDid the agent's stored DID (selects the algo)
 */
export function deriveAgentKeypair(slotSeed, agentDid) {
  if (agentKeyTypeFromDid(agentDid) === 'ed25519') {
    const kp = deriveAgentEd25519Keypair(slotSeed);
    return { ...kp, agentDid };
  }
  return deriveAgentP256Keypair(slotSeed);
}

export function deriveAgentP256Keypair(slotSeed) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new Error('slot seed must be a 32-byte Buffer');
  }
  // The Rust side runs HKDF-SHA512(info `lastid/agent-keypair/v1`) over the
  // slot seed → P-256 scalar, then encodes the DID/JWK. We never reimplement
  // that here; we just call into it.
  const kp = agentWasm.agentKeypairFromSeed(new Uint8Array(slotSeed));
  const publicJwk = jwkToObject(kp.publicJwk);
  const signingSeed = Buffer.from(kp.signingKeyBytes);

  // Build a Node P-256 private KeyObject from the raw 32-byte scalar so the
  // KeyObject-shaped consumers (memory-audit chain signing) keep working.
  // PKCS8 for an EC P-256 private key embeds the scalar + the public point.
  const signingKey = p256PrivateKeyFromScalar(signingSeed, publicJwk);

  return {
    signingKey,
    publicJwk,
    signingSeed,
    agentDid: kp.agentDid,
  };
}

/**
 * Construct a Node P-256 private `KeyObject` from a raw 32-byte ECDSA
 * scalar plus the matching public JWK coordinates. Node's JWK importer
 * accepts an EC private JWK (`d` + `x` + `y`), which is the simplest
 * lossless path — no manual DER assembly, and it validates the scalar
 * against the curve.
 */
function p256PrivateKeyFromScalar(scalar, publicJwk) {
  return createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: b64url(scalar),
      x: publicJwk.x,
      y: publicJwk.y,
    },
    format: 'jwk',
  });
}

/**
 * Derive this agent runtime's stable `ad-<hash>` device_id from its 32-byte
 * slot seed. The single source for the device_id across the MLS layer — the
 * KeyPackage publish (`mls-publish`), the shared orchestrator handle, and the
 * MlsClient fallback all call this so the value stamped into the MLS
 * credential matches the one the IdP key-package store is keyed by.
 *
 * Feature-detects from the agent DID when one is supplied: an existing
 * Ed25519 agent (`z6Mk…`) derives its `ad-` id from the Ed25519 OKP JWK,
 * NOT the P-256 one. When `agentDid` is omitted the P-256 path is used —
 * preserving the current behavior for new-agent callers that don't (yet)
 * have a stored DID at the call site.
 *
 * @param {Buffer} slotSeed 32-byte BIP85 slot seed
 * @param {string} [agentDid] the agent's stored DID (selects the algo)
 * @returns {string} e.g. `ad-1a2b…`
 */
export function deriveAgentDeviceId(slotSeed, agentDid) {
  if (agentDid && agentKeyTypeFromDid(agentDid) === 'ed25519') {
    return agentDeviceIdFromEd25519Jwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
  }
  const { publicJwk } = deriveAgentP256Keypair(slotSeed);
  return agentDeviceIdFromP256Jwk(publicJwk);
}

/**
 * Resolve this agent runtime's MLS device_id — the ONE value the MLS layer
 * (credential stamp in `mls-client`, KeyPackage publish in `mls-publish`)
 * uses, so both sides provably agree (a disagreement here is the multi-device
 * two-sources class).
 *
 * Precedence:
 *   1. `persistedDeviceId` — the value PINNED at provisioning (a machine-bound
 *      agent's `md-…`, persisted in the keychain). Stable across plugin/broker
 *      changes: once set it never re-derives, so a machine-bound agent keeps
 *      the same id even if the broker later goes missing.
 *   2. Legacy fallback — `deriveAgentDeviceId(slotSeed, agentDid)`, i.e. the
 *      agent's own `ad-…`. This is the NO-FLAG-DAY seam: every agent
 *      provisioned before machine-binding has no persisted id and so keeps its
 *      current `ad-` device_id byte-for-byte until it is reissued.
 *
 * @param {{ persistedDeviceId?: string|null, slotSeed: Buffer, agentDid?: string }} args
 * @returns {string}
 */
export function resolveAgentDeviceId({ persistedDeviceId, slotSeed, agentDid }) {
  if (typeof persistedDeviceId === 'string' && persistedDeviceId.length > 0) {
    return persistedDeviceId;
  }
  return deriveAgentDeviceId(slotSeed, agentDid);
}

/**
 * Multibase base58btc alphabet + encoder for the Ed25519 backward-compat
 * DID branch. We don't pull in a base58 library; this inline encoder
 * matches `multibase z` (and the Rust SDK's
 * `lastid_identity::did::agent_did_from_pubkey` Ed25519 path).
 */
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes) {
  // Adapted minimally from the standard base58 encoder. Handles
  // leading zero bytes as the prefix `1`s (required by base58btc).
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) + BigInt(b);
  }
  let out = '';
  while (n > 0n) {
    const rem = Number(n % 58n);
    out = BASE58_ALPHABET[rem] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

/**
 * Derive the agent's `did:lastid:agent:` DID from the public JWK.
 *
 * Dual-algo / feature-detected from the JWK key type:
 *   - OKP / Ed25519 (existing agents): multicodec(ed25519-pub=0xed01) ||
 *     pubkey_bytes, multibase base58btc-encoded → `…:z6Mk…`. PURE JS,
 *     mirrors `lastid_identity::did::agent_did_from_pubkey` Ed25519 path.
 *   - EC / P-256 (new agents): did:key P-256 multicodec(p256-pub=0x1200)
 *     || compressed-SEC1, encoding owned by the Rust SDK and reached
 *     through the WASM `agentDidFromPubkey` — single source of truth, so
 *     the plugin can't drift from the SDK/IdP DID form.
 */
export function agentDidFromPublicJwk(pubJwk) {
  const jwk = jwkToObject(pubJwk);
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const pub = b64urlDecode(jwk.x);
    if (pub.length !== 32) {
      throw new Error(`Ed25519 pubkey must be 32 bytes, got ${pub.length}`);
    }
    // multicodec prefix: 0xed 0x01 (ed25519-pub)
    const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), pub]);
    return 'did:lastid:agent:z' + base58btcEncode(multicodec);
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('agent pubkey must be EC/P-256 or OKP/Ed25519');
  }
  const x = b64urlDecode(jwk.x);
  const y = b64urlDecode(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(
      `P-256 pubkey coords must be 32 bytes each, got x=${x.length} y=${y.length}`,
    );
  }
  // Uncompressed SEC1 point: 0x04 || X || Y. The WASM accepts either
  // compressed (33) or uncompressed (65) and re-encodes canonically.
  const sec1 = Buffer.concat([Buffer.from([0x04]), x, y]);
  return agentWasm.agentDidFromPubkey(new Uint8Array(sec1));
}

/**
 * Parse an `openid-credential-offer://` URI.
 */
export function parseCredentialOffer(uri) {
  const url = new URL(uri);
  const inline = url.searchParams.get('credential_offer');
  let offer;
  if (inline) {
    offer = JSON.parse(inline);
  } else {
    throw new Error(
      'by-reference credential_offer_uri not supported yet (no credential_offer query param)',
    );
  }
  const grantKey = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const preAuth = offer.grants?.[grantKey]?.['pre-authorized_code'];
  if (!preAuth) {
    throw new Error('credential offer missing pre-authorized_code grant');
  }
  return {
    credentialIssuer: offer.credential_issuer,
    credentialConfigurationIds: offer.credential_configuration_ids,
    preAuthorizedCode: preAuth,
  };
}

export async function exchangeToken(offer) {
  const tokenUrl = `${offer.credentialIssuer}/v1/oid4vci/token`;
  const form = new URLSearchParams();
  form.set('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
  form.set('pre-authorized_code', offer.preAuthorizedCode);
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  if (!response.ok) {
    throw new Error(
      `token exchange failed: ${response.status} ${await response.text()}`,
    );
  }
  const body = await response.json();
  return { accessToken: body.access_token, cNonce: body.c_nonce };
}

// Media-type tag for the parent-authorization JWS — MUST match the SDK
// (`lastid-identity/src/parent_authorization.rs`) and the IdP verifier
// (`lastid-idp/src/crypto/parent-authorization.ts`). Distinct from the
// human-auth typ so the IdP can't confuse the two trust sources.
const PARENT_AUTH_TYP = 'jwt+lastid-parent-auth-v1';

/**
 * Sign a parent-authorization JWS with the parent agent's identity key —
 * DUAL-ALGO, PURE JS, no wasm. Feature-detected from the parent's
 * `signingKey.asymmetricKeyType`, exactly like `dpop.js` mintDpopJwt:
 *
 *   - Ed25519 (existing agents): header `alg:'EdDSA'`, raw 64-byte Ed25519
 *     signature (`cryptoSign(null, …, signingKey)`).
 *   - P-256 (new agents): header `alg:'ES256'`, raw 64-byte r||s ECDSA
 *     signature (`cryptoSign('sha256', …, { dsaEncoding: 'ieee-p1363' })`).
 *
 * Same wire shape for both:
 *   header  = { typ: 'jwt+lastid-parent-auth-v1', alg, kid? }
 *   payload = claimsJson (verbatim bytes — stringify once at the call site)
 *   sig     = raw signature over `header_b64.payload_b64`, base64url
 *
 * The IdP's `verifyParentAuthorization` is DUAL-ALGO: it derives the expected
 * alg from the parent's cnf pubkey (Ed25519 OKP → EdDSA, P-256 EC → ES256)
 * and requires `header.alg` to match — so each parent type signs with its own
 * curve and the IdP accepts it. Built in pure `node:crypto`, so no wasm
 * rebuild is needed (the bundled WASM `signParentAuthorization` is bypassed —
 * it only emits one alg and can't feature-detect from a Node KeyObject).
 *
 * @param {import('node:crypto').KeyObject} signingKey - parent's Ed25519 or P-256 KeyObject
 * @param {string} claimsJson - the EXACT serialized claims value (verbatim payload)
 * @param {string} [kid]
 * @returns {string} compact JWS (EdDSA or ES256)
 */
export function signParentAuthorization(signingKey, claimsJson, kid) {
  const keyType = signingKey?.asymmetricKeyType;
  const isEd25519 = keyType === 'ed25519';
  if (!isEd25519 && keyType !== 'ec') {
    throw new Error(
      'signParentAuthorization: requires an Ed25519 or P-256 signing key',
    );
  }
  const header = {
    typ: PARENT_AUTH_TYP,
    alg: isEd25519 ? 'EdDSA' : 'ES256',
    ...(kid ? { kid } : {}),
  };
  const headerB64 = b64url(Buffer.from(JSON.stringify(header), 'utf-8'));
  const payloadB64 = b64url(Buffer.from(claimsJson, 'utf-8'));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = isEd25519
    ? // EdDSA: node returns the raw 64-byte Ed25519 signature directly.
      cryptoSign(null, Buffer.from(signingInput, 'utf-8'), signingKey)
    : // ES256: SHA-256 + ECDSA over P-256, raw r||s (ieee-p1363) — NOT DER.
      cryptoSign('sha256', Buffer.from(signingInput, 'utf-8'), {
        key: signingKey,
        dsaEncoding: 'ieee-p1363',
      });
  return `${signingInput}.${b64url(sig)}`;
}

/**
 * Mint the OID4VCI proof JWT. Dual-algo / feature-detected:
 *
 *   - Ed25519 (existing agents): when an Ed25519 `signingKey` KeyObject is
 *     supplied, sign EdDSA over the header/payload directly in JS
 *     (`cryptoSign(null, …, signingKey)` returns raw 64-byte Ed25519 sig).
 *     The header embeds the holder JWK as `agentPubkeyJwk`. This is the
 *     ORIGINAL pre-P256 behavior.
 *   - P-256 (new agents): `signingSeed` is the agent's raw 32-byte P-256
 *     scalar (from `deriveAgentP256Keypair`); the header/payload wire shape
 *     and the ES256 signature are produced by the Rust SDK via the WASM
 *     `mintOid4vciProofJwtEs256`, so the proof can't drift from what the IdP
 *     verifies. The WASM embeds the JWK derived from the scalar, so any
 *     passed `agentPubkeyJwk` is ignored on this path.
 */
export function mintProofJwt({
  credentialIssuer,
  cNonce,
  agentDid,
  agentPubkeyJwk,
  signingKey,
  signingSeed,
}) {
  // Ed25519 backward-compat path: feature-detect on the KeyObject type.
  if (signingKey && signingKey.asymmetricKeyType === 'ed25519') {
    const header = {
      typ: 'openid4vci-proof+jwt',
      alg: 'EdDSA',
      jwk: agentPubkeyJwk,
    };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: agentDid,
      aud: credentialIssuer,
      iat: now,
      nonce: cNonce,
    };
    const headerB64 = b64urlJson(header);
    const payloadB64 = b64urlJson(payload);
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigBytes = cryptoSign(null, Buffer.from(signingInput, 'utf-8'), signingKey);
    return `${signingInput}.${b64url(sigBytes)}`;
  }
  if (!Buffer.isBuffer(signingSeed) && !(signingSeed instanceof Uint8Array)) {
    throw new Error('mintProofJwt: signingSeed must be the raw P-256 scalar bytes');
  }
  const now = Math.floor(Date.now() / 1000);
  return agentWasm.mintOid4vciProofJwtEs256(
    new Uint8Array(signingSeed),
    agentDid,
    credentialIssuer,
    cNonce,
    BigInt(now),
  );
}

export async function claimCredential({
  credentialIssuer,
  accessToken,
  proofJwt,
}) {
  const credentialUrl = `${credentialIssuer}/v1/oid4vci/credential`;
  const body = {
    format: 'vc+sd-jwt',
    // IdP expects a types array (W3C VC `type` field shape). Include
    // both the generic VerifiableCredential and the specific agent type
    // so the IdP picks the right issuer strategy. `vct` is also sent
    // for SD-JWT VC compliance.
    types: ['VerifiableCredential', 'LastID.Agent.Base'],
    vct: 'LastID.Agent.Base',
    proof: {
      proof_type: 'jwt',
      jwt: proofJwt,
    },
  };
  const response = await fetch(credentialUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(
      `credential issuance failed: ${response.status} ${await response.text()}`,
    );
  }
  return response.json();
}

/**
 * Top-level orchestrator: ephemeral envelope keypair → initiate → wait
 * for wallet → unseal slot seed → derive Ed25519 identity → claim VC.
 *
 * `onUserCode` is invoked once with `{ userCode, expiresIn }` so the
 * caller can render the code; the wallet's WebSocket push will pop the
 * approval screen on the operator's devices.
 *
 * Returned slot seed is the recoverable identity root for this agent —
 * persist it in the OS keychain so subsequent launches don't need the
 * wallet round-trip.
 */
export async function provisionAgent({
  idpUrl,
  parentHumanDid,
  runtimeName,
  projectHint,
  onUserCode,
  intervalSeconds = 5,
  timeoutSeconds = 600,
  // Injectable broker bridge (tests supply a fake; production uses the real
  // signed broker). Returns this machine's SE pubkey JWK, or null when no
  // broker is present → legacy no-machine-device provisioning.
  getMachineSePubkeyJwk = defaultGetMachineSePubkeyJwk,
}) {
  const ephemeral = generateEphemeralEnvelopeKeypair();
  // Ask the signed broker for this machine's SE pubkey (macOS only); null →
  // omitted, provisioning falls back to the legacy no-machine-device flow.
  // When present, this same key both (a) is presented to /initiate so the
  // wallet signs a device_authorization registering the parent-owned machine
  // device, and (b) pins this agent's MLS device_id to that machine's `md-…`.
  const machineSePubkeyJwk = getMachineSePubkeyJwk();
  const initiate = await initiateProvisioning({
    idpUrl,
    parentHumanDid,
    runtimeName,
    projectHint,
    ephemeralPubkeyJwk: ephemeral.publicJwk,
    machineSePubkeyJwk,
  });
  if (typeof onUserCode === 'function') {
    await onUserCode({
      userCode: initiate.user_code,
      expiresIn: initiate.expires_in,
    });
  }
  const approved = await pollUntilApproved({
    idpUrl,
    deviceCode: initiate.device_code,
    intervalSeconds,
    timeoutSeconds,
  });

  // Unseal the wallet-derived slot seed and immediately derive our
  // P-256 identity. Ephemeral private key is no longer needed.
  const slotSeed = unsealSlotSeed(approved.sealedSlotSeed, ephemeral.privateKey);
  const { publicJwk, signingSeed } = deriveAgentP256Keypair(slotSeed);

  // Unseal the operator's project-memory root seed too, if the wallet sealed
  // one to the same ephemeral recipient (the envelope format is identical, so
  // `unsealSlotSeed` handles it). Best-effort + fail-open: an older wallet
  // omits it, and a malformed/foreign envelope must NOT break provisioning —
  // the agent simply has no project-tier memories.
  let projectRootSeed = null;
  if (approved.sealedProjectRootSeed) {
    try {
      projectRootSeed = unsealSlotSeed(approved.sealedProjectRootSeed, ephemeral.privateKey);
    } catch (err) {
      process.stderr.write(
        `[lastid-agent] project root seed unseal failed (non-fatal): ${err?.message ?? err}\n`,
      );
      projectRootSeed = null;
    }
  }

  // Cross-check: the IdP told us the agent_did at /poll; what we
  // derived from the unsealed slot seed must match exactly. If it
  // doesn't, the seed-to-DID chain is broken and we MUST refuse to
  // continue rather than claim a VC bound to a key we don't really hold.
  const derivedDid = agentDidFromPublicJwk(publicJwk);
  if (approved.agentDid && approved.agentDid !== derivedDid) {
    throw new Error(
      `agent_did mismatch: IdP says ${approved.agentDid} but we derived ${derivedDid} from the unsealed slot seed`,
    );
  }

  const offer = parseCredentialOffer(approved.credentialOfferUri);
  const { accessToken, cNonce } = await exchangeToken(offer);
  const proofJwt = mintProofJwt({
    credentialIssuer: offer.credentialIssuer,
    cNonce,
    agentDid: derivedDid,
    agentPubkeyJwk: publicJwk,
    signingSeed,
  });
  const issued = await claimCredential({
    credentialIssuer: offer.credentialIssuer,
    accessToken,
    proofJwt,
  });

  // Pin the MLS device_id at provisioning (L5). When a machine SE key was
  // presented, this agent is machine-bound: its device_id is the machine's
  // `md-…` (byte-identical to the IdP's machine device + the Rust derivation).
  // Otherwise null → the keychain stores nothing and the MLS layer falls back
  // to the legacy `ad-` derivation (no-flag-day). The agent's IDENTITY is
  // always its own key; only the device LABEL becomes the machine.
  const deviceId = machineSePubkeyJwk
    ? machineDeviceIdFromP256Jwk(machineSePubkeyJwk)
    : null;

  return {
    agentDid: derivedDid,
    slotSeed,
    projectRootSeed,
    slotIndex: approved.slotIndex,
    publicJwk,
    deviceId,
    vcCompact: issued.credential,
    cNonce: issued.c_nonce ?? null,
    cNonceExpiresIn: issued.c_nonce_expires_in ?? null,
  };
}

/**
 * Provision a new agent THROUGH the signed broker (FORK1 Phase 4). The broker
 * (already running unprovisioned for `scope`) generates the ephemeral, unseals
 * the slot seed, claims the VC, and PERSISTS everything to the keychain itself —
 * so unlike {@link provisionAgent}, the slot seed never enters this process and
 * the result carries NO `slotSeed`/`vcCompact`. Node drives only the `user_code`
 * UX + the poll loop.
 *
 * The caller routes here (instead of `provisionAgent`) when the broker path is
 * active (flag on + macOS + a broker up); on `persistedByBroker` the caller must
 * NOT call `persistAgentVc` (the broker already did, and node has no seed).
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} [a.runtimeName]
 * @param {string} [a.projectHint]
 * @param {string} [a.parentHumanDid]
 * @param {(info:{userCode:string, expiresIn:number|null}) => Promise<void>|void} [a.onUserCode]
 * @param {number} [a.intervalSeconds]
 * @param {number} [a.timeoutSeconds]
 * @param {typeof defaultBrokerProvisionInitiate} [a.initiate] - test override
 * @param {typeof defaultBrokerProvisionPoll} [a.poll] - test override
 * @returns {Promise<{agentDid:string, slotIndex:number|null, deviceId:string|null, persistedByBroker:true}>}
 */
export async function provisionAgentViaBroker({
  scope = 'main',
  runtimeName,
  projectHint,
  parentHumanDid,
  onUserCode,
  intervalSeconds = 5,
  timeoutSeconds = 600,
  initiate = defaultBrokerProvisionInitiate,
  poll = defaultBrokerProvisionPoll,
} = {}) {
  const init = await initiate({ scope, runtimeName, projectHint, parentHumanDid });
  if (typeof onUserCode === 'function') {
    await onUserCode({ userCode: init.userCode, expiresIn: init.expiresIn });
  }
  const intervalMs = intervalSeconds * 1000;
  const deadlineMs = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadlineMs) {
    // brokerProvisionPoll throws on a wallet rejection / broker error — let it
    // propagate (same posture as pollUntilApproved's 410 throw).
    const r = await poll({ scope, provisionId: init.provisionId });
    if (r.status === 'complete') {
      return {
        agentDid: r.agentDid,
        slotIndex: r.slotIndex,
        deviceId: r.deviceId,
        persistedByBroker: true,
      };
    }
    await delay(intervalMs);
  }
  throw new Error('broker provisioning timed out before wallet approval');
}

// Internal re-exports for tests.
export const _internal = {
  b64url,
  b64urlJson,
  b64urlDecode,
  unsealSlotSeed,
  sealSlotSeed,
  deriveAgentP256Keypair,
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
  base58btcEncode,
};
