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

// HKDF info strings — must match the Rust SDK exactly.
const ECDH_DEK_WRAP_INFO = Buffer.from('lastid/v2/ecdh-p256/dek-wrap', 'utf-8');
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
 * Derive the agent's Ed25519 stable identity from its 32-byte slot
 * seed. Mirrors `lastid_identity::AgentKeypair::from_seed` exactly:
 * HKDF-SHA512 with info `lastid/agent-keypair/v1` produces the 32-byte
 * Ed25519 signing seed.
 *
 * Returns `{ signingKey, publicJwk, signingSeed }`:
 *   - signingKey:  Node KeyObject (used by `node:crypto` paths — DPoP,
 *                  OID4VCI proof JWT minting).
 *   - publicJwk:   `{ kty, crv, x }` (used to derive `did:lastid:agent:`).
 *   - signingSeed: Raw 32-byte Buffer (used by the wasm side — wasm
 *                  exports take raw seeds, not KeyObjects). The
 *                  SessionFingerprint signer needs this; everything
 *                  else can ignore it.
 *
 * The seed is intentionally NOT zeroized here — the caller now owns
 * its lifetime. Callers that only need the KeyObject path should
 * destructure just `{ signingKey, publicJwk }` and let the seed buffer
 * GC normally. Callers that need wasm signing (DesktopMcpClient,
 * sub-agent enrollment) keep the buffer for as long as the session
 * lasts and discard at session teardown.
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
 * Derive the agent's `did:lastid:agent:` DID from the Ed25519 pubkey
 * JWK. Multibase base58btc-encoded multicodec(ed25519-pub=0xed01) ||
 * pubkey_bytes — matches `lastid_identity::did::agent_did_from_pubkey`.
 *
 * We don't pull in a base58 library; instead use a small inline
 * implementation matching `multibase z`.
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

export function agentDidFromPublicJwk(pubJwk) {
  if (pubJwk.kty !== 'OKP' || pubJwk.crv !== 'Ed25519') {
    throw new Error('agent pubkey must be OKP/Ed25519');
  }
  const pub = b64urlDecode(pubJwk.x);
  if (pub.length !== 32) {
    throw new Error(`Ed25519 pubkey must be 32 bytes, got ${pub.length}`);
  }
  // multicodec prefix: 0xed 0x01 (ed25519-pub)
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), pub]);
  return 'did:lastid:agent:z' + base58btcEncode(multicodec);
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

export function mintProofJwt({
  credentialIssuer,
  cNonce,
  agentDid,
  agentPubkeyJwk,
  signingKey,
}) {
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
}) {
  const ephemeral = generateEphemeralEnvelopeKeypair();
  const initiate = await initiateProvisioning({
    idpUrl,
    parentHumanDid,
    runtimeName,
    projectHint,
    ephemeralPubkeyJwk: ephemeral.publicJwk,
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
  // Ed25519 identity. Ephemeral private key is no longer needed.
  const slotSeed = unsealSlotSeed(approved.sealedSlotSeed, ephemeral.privateKey);
  const { signingKey, publicJwk } = deriveAgentEd25519Keypair(slotSeed);

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
    signingKey,
  });
  const issued = await claimCredential({
    credentialIssuer: offer.credentialIssuer,
    accessToken,
    proofJwt,
  });

  return {
    agentDid: derivedDid,
    slotSeed,
    projectRootSeed,
    slotIndex: approved.slotIndex,
    publicJwk,
    vcCompact: issued.credential,
    cNonce: issued.c_nonce ?? null,
    cNonceExpiresIn: issued.c_nonce_expires_in ?? null,
  };
}

// Internal re-exports for tests.
export const _internal = {
  b64url,
  b64urlJson,
  b64urlDecode,
  unsealSlotSeed,
  sealSlotSeed,
  deriveAgentEd25519Keypair,
  agentDidFromPublicJwk,
  base58btcEncode,
};
