/**
 * Agent content crypto — slot_seed-derived symmetric encryption for the
 * rules/memories an operator distributes to THIS agent.
 *
 * Design: saas-migration.md §3. The operator (any of their devices) and
 * this agent share the agent's 32-byte slot_seed:
 *   - the operator re-derives it via
 *     `derive_agent_slot_seed(ai_agent_seed, slot_index)`,
 *   - the agent holds it in the OS keychain (see keychain.js).
 * A domain-separated HKDF off that seed yields an AES-256 content key,
 * independent of the Ed25519 signing key the slot_seed also derives
 * (`AgentKeypair::from_seed`, info "lastid/agent-keypair/v1" — distinct
 * from ours, so no derivation collision).
 *
 * Both ends MUST agree on these primitives byte-for-byte (the operator
 * side runs in Rust/WASM via lastid-envelope; this is the Node decrypt
 * peer):
 *   KDF:    HKDF-SHA512, salt = empty, info = CONTENT_KEY_INFO, 32 bytes
 *   cipher: AES-256-GCM, 12-byte nonce, 16-byte tag
 *   wire:   nonce(12) || ciphertext || tag(16)
 *
 * Empty salt here equals Rust's `Hkdf::<Sha512>::new(None, ikm)`:
 * RFC-5869 treats an absent salt as HashLen zero bytes, and HMAC pads
 * any sub-block key with zeros, so empty and HashLen-zero salts produce
 * the same PRK.
 *
 * Pure node:crypto — no SDK/WASM dependency, so the decrypt path works
 * with nothing else running.
 */
import crypto from 'node:crypto';

export const CONTENT_KEY_INFO = 'lastid/agent-content-enc/v1';
export const NONCE_LEN = 12;
export const TAG_LEN = 16;
export const KEY_LEN = 32;

/**
 * Derive the 32-byte AES content key from a 32-byte slot_seed.
 * Deterministic; callers may cache the result for the session.
 */
export function deriveContentKey(slotSeed) {
  if (!Buffer.isBuffer(slotSeed) || slotSeed.length !== 32) {
    throw new TypeError('slotSeed must be a 32-byte Buffer');
  }
  // hkdfSync returns an ArrayBuffer. salt = empty buffer matches the
  // Rust `None` salt (see header note).
  const out = crypto.hkdfSync(
    'sha512',
    slotSeed,
    Buffer.alloc(0),
    Buffer.from(CONTENT_KEY_INFO, 'utf8'),
    KEY_LEN,
  );
  return Buffer.from(out);
}

/**
 * Encrypt plaintext under the slot_seed content key.
 * Returns the packed wire buffer: nonce(12) || ciphertext || tag(16).
 *
 * `opts.nonce` is for tests/known-answer vectors only — production
 * callers omit it so a fresh random nonce is used per message.
 * `opts.key` lets a caller pass a pre-derived content key (e.g. the
 * operator encrypting N global copies) instead of a slot_seed.
 */
export function encryptContent(slotSeed, plaintext, opts = {}) {
  const key = opts.key ? Buffer.from(opts.key) : deriveContentKey(slotSeed);
  try {
    const iv = opts.nonce ?? crypto.randomBytes(NONCE_LEN);
    if (!Buffer.isBuffer(iv) || iv.length !== NONCE_LEN) {
      throw new TypeError(`nonce must be a ${NONCE_LEN}-byte Buffer`);
    }
    const pt = Buffer.isBuffer(plaintext)
      ? plaintext
      : Buffer.from(String(plaintext), 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (opts.aad != null) {
      cipher.setAAD(Buffer.isBuffer(opts.aad) ? opts.aad : Buffer.from(opts.aad, 'utf8'));
    }
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ct, tag]);
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypt a packed wire buffer (nonce||ct||tag), or a base64 string of
 * one, under the slot_seed content key. Throws on auth failure (wrong
 * key, tampering, truncation).
 */
export function decryptContent(slotSeed, packed, opts = {}) {
  const buf = Buffer.isBuffer(packed) ? packed : Buffer.from(String(packed), 'base64');
  if (buf.length < NONCE_LEN + TAG_LEN) {
    throw new Error('ciphertext too short');
  }
  const iv = buf.subarray(0, NONCE_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ct = buf.subarray(NONCE_LEN, buf.length - TAG_LEN);
  const key = opts.key ? Buffer.from(opts.key) : deriveContentKey(slotSeed);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    if (opts.aad != null) {
      decipher.setAAD(Buffer.isBuffer(opts.aad) ? opts.aad : Buffer.from(opts.aad, 'utf8'));
    }
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

/** Encrypt a JSON-serialisable object; returns the packed wire buffer. */
export function encryptJson(slotSeed, obj, opts = {}) {
  return encryptContent(slotSeed, Buffer.from(JSON.stringify(obj), 'utf8'), opts);
}

/** Decrypt a packed buffer / base64 string back into a parsed object. */
export function decryptJson(slotSeed, packed, opts = {}) {
  return JSON.parse(decryptContent(slotSeed, packed, opts).toString('utf8'));
}
