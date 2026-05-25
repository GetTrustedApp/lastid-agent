/**
 * Agent content crypto — slot_seed-keyed encryption for the rules/
 * memories an operator distributes to THIS agent.
 *
 * Wire format: the canonical **LastID envelope, SymmetricOnly suite
 * (0x0003)** from `lastid-envelope` — so the operator side is a thin
 * wrapper over the existing Rust `envelope_encrypt` (reuse the SDK, no
 * bespoke crypto), and this is the Node peer that reads it. The agent
 * already reimplements the LIDE EcdhP256 suite (agent-provisioning.js
 * `unsealSlotSeed`); this is the same machinery for the Symmetric suite.
 *
 * Keying (saas-migration.md §3): the symmetric KEK is derived from the
 * agent's 32-byte slot_seed — shared by the operator (re-derives it via
 * `derive_agent_slot_seed`) and the agent (holds it in the keychain):
 *   KEK = HKDF-SHA512(slot_seed, salt=empty, info=CONTENT_KEY_INFO, 32)
 * independent of the Ed25519 signing key (info "lastid/agent-keypair/v1").
 *
 * Envelope layout (must match lastid-envelope/src/{envelope,recipient,format}.rs):
 *   header(14): "LIDE" | version(2 LE)=1 | suite(2 LE)=0x0003 | flags(1)
 *               | recipient_count(1) | payload_len(4 LE)=len(ct+tag)
 *   recipient:  type(1)=0x04 Symmetric | key_id_len(2 LE) | key_id
 *               | encap_len(2 LE) | encap
 *     encap:    salt(16) | wrap_nonce(12) | AES-256-GCM(KEK, wrap_nonce, DEK)=48
 *   payload:    payload_nonce(12) | AES-256-GCM(DEK, payload_nonce, content)
 * DEK is a random 32-byte data key; the KEK wraps it (KEK is used as the
 * AES key directly — Symmetric suite does NOT HKDF over the header).
 *
 * Pure node:crypto — decryption runs at sync time with nothing else up.
 */
import crypto from 'node:crypto';

export const CONTENT_KEY_INFO = 'lastid/agent-content-enc/v1';
export const KEY_LEN = 32;
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const DEK_LEN = 32;
export const SALT_LEN = 16;

// LIDE envelope wire constants (lastid-envelope/src/format.rs).
const ENVELOPE_MAGIC = Buffer.from([0x4c, 0x49, 0x44, 0x45]); // "LIDE"
const ENVELOPE_VERSION = 0x0001;
const SUITE_SYMMETRIC_ONLY = 0x0003;
const RECIPIENT_TYPE_SYMMETRIC = 0x04;
const HEADER_SIZE = 14;
// key_id is opaque to decryption (we resolve the KEK from the slot_seed,
// not the id). A stable label keeps operator-side envelopes self-describing.
const KEY_ID = 'agent-content/v1';

/** Derive the 32-byte symmetric KEK from a 32-byte slot_seed. */
export function deriveContentKey(slotSeed) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new TypeError('slotSeed must be a 32-byte Buffer');
  }
  return Buffer.from(
    crypto.hkdfSync('sha512', slotSeed, Buffer.alloc(0), Buffer.from(CONTENT_KEY_INFO, 'utf8'), KEY_LEN),
  );
}

function u16le(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}

function gcmEncrypt(key, nonce, plaintext) {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]); // ciphertext || 16B tag
}

function gcmDecrypt(key, nonce, ctAndTag) {
  if (ctAndTag.length < TAG_LEN) throw new Error('ciphertext shorter than GCM tag');
  const ct = ctAndTag.subarray(0, ctAndTag.length - TAG_LEN);
  const tag = ctAndTag.subarray(ctAndTag.length - TAG_LEN);
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

/**
 * Encrypt content into a LIDE SymmetricOnly envelope. Returns the packed
 * envelope Buffer. `opts.key` supplies a pre-derived KEK; `opts.dek` /
 * `opts.payloadNonce` / `opts.wrapNonce` are for deterministic test
 * vectors only (production uses fresh random values, like the Rust side).
 */
export function encryptContent(slotSeed, plaintext, opts = {}) {
  const kek = opts.key ? Buffer.from(opts.key) : deriveContentKey(slotSeed);
  const dek = opts.dek ?? crypto.randomBytes(DEK_LEN);
  const payloadNonce = opts.payloadNonce ?? crypto.randomBytes(NONCE_LEN);
  const wrapNonce = opts.wrapNonce ?? crypto.randomBytes(NONCE_LEN);
  try {
    const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    const ciphertext = gcmEncrypt(dek, payloadNonce, pt); // ct || tag

    const header = Buffer.alloc(HEADER_SIZE);
    ENVELOPE_MAGIC.copy(header, 0);
    header.writeUInt16LE(ENVELOPE_VERSION, 4);
    header.writeUInt16LE(SUITE_SYMMETRIC_ONLY, 6);
    header[8] = 0; // flags
    header[9] = 1; // recipient_count
    header.writeUInt32LE(ciphertext.length, 10);

    const wrappedDek = gcmEncrypt(kek, wrapNonce, dek); // 48
    const encap = Buffer.concat([Buffer.alloc(SALT_LEN, 0), wrapNonce, wrappedDek]); // 16+12+48
    const keyId = Buffer.from(KEY_ID, 'utf8');
    const recipientBlock = Buffer.concat([
      Buffer.from([RECIPIENT_TYPE_SYMMETRIC]),
      u16le(keyId.length),
      keyId,
      u16le(encap.length),
      encap,
    ]);

    return Buffer.concat([header, recipientBlock, payloadNonce, ciphertext]);
  } finally {
    kek.fill(0);
    if (!opts.dek) dek.fill(0);
  }
}

/**
 * Decrypt a LIDE SymmetricOnly envelope (Buffer or base64 string) under
 * the slot_seed KEK. Iterates recipient blocks and unwraps the first
 * Symmetric one. Throws on a bad envelope, wrong key, or tampering.
 */
export function decryptContent(slotSeed, packed, opts = {}) {
  const env = Buffer.isBuffer(packed) ? packed : Buffer.from(String(packed), 'base64');
  if (env.length < HEADER_SIZE) throw new Error('envelope shorter than header');
  if (!env.subarray(0, 4).equals(ENVELOPE_MAGIC)) {
    throw new Error(`bad envelope magic: ${env.subarray(0, 4).toString('hex')}`);
  }
  if (env.readUInt16LE(4) !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${env.readUInt16LE(4)}`);
  }
  if (env.readUInt16LE(6) !== SUITE_SYMMETRIC_ONLY) {
    throw new Error(`unsupported suite for content: 0x${env.readUInt16LE(6).toString(16)} (expected SymmetricOnly)`);
  }
  const recipientCount = env[9];
  const payloadLen = env.readUInt32LE(10);

  const kek = opts.key ? Buffer.from(opts.key) : deriveContentKey(slotSeed);
  try {
    let cursor = HEADER_SIZE;
    let dek = null;
    for (let i = 0; i < recipientCount; i += 1) {
      const rtype = env[cursor];
      cursor += 1;
      const keyIdLen = env.readUInt16LE(cursor);
      cursor += 2 + keyIdLen; // skip key_id (KEK comes from slot_seed)
      const encapLen = env.readUInt16LE(cursor);
      cursor += 2;
      const encap = env.subarray(cursor, cursor + encapLen);
      cursor += encapLen;
      if (rtype === RECIPIENT_TYPE_SYMMETRIC && dek === null) {
        const wrapNonce = encap.subarray(SALT_LEN, SALT_LEN + NONCE_LEN);
        const wrappedDek = encap.subarray(SALT_LEN + NONCE_LEN);
        dek = gcmDecrypt(kek, wrapNonce, wrappedDek);
      }
    }
    if (!dek) throw new Error('no symmetric recipient block');
    const payloadNonce = env.subarray(cursor, cursor + NONCE_LEN);
    const ciphertext = env.subarray(cursor + NONCE_LEN, cursor + NONCE_LEN + payloadLen);
    try {
      return gcmDecrypt(dek, payloadNonce, ciphertext);
    } finally {
      dek.fill(0);
    }
  } finally {
    kek.fill(0);
  }
}

/** Encrypt a JSON-serialisable object; returns the packed envelope buffer. */
export function encryptJson(slotSeed, obj, opts = {}) {
  return encryptContent(slotSeed, Buffer.from(JSON.stringify(obj), 'utf8'), opts);
}

/** Decrypt a packed envelope / base64 string back into a parsed object. */
export function decryptJson(slotSeed, packed, opts = {}) {
  return JSON.parse(decryptContent(slotSeed, packed, opts).toString('utf8'));
}
