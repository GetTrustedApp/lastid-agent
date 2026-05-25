/**
 * Verify the operator's delegation_authority signature on an agent-state
 * record (saas-migration.md §6 / §3.6).
 *
 * The operator signs each record with their delegation_authority key
 * (sign_human_authorization), producing a compact ES256 (P-256) JWS:
 *   header  = { typ: "jwt+lastid-human-auth-v1", alg: "ES256", kid? }
 *   payload = { kind, id, target, version, status, content_sha256 }  (verbatim)
 *   sig     = raw r||s (ieee-p1363), base64url
 *
 * The payload binds a SHA-256 of the content, NOT the content itself —
 * the JWS is stored server-side, so signing plaintext would leak it.
 *
 * The agent verifies the ES256 signature over the LITERAL transmitted
 * `header.payload` segments (no re-serialization), then independently
 * checks `content_sha256` against the SHA-256 of the decrypted bytes and
 * that the signed claims bind this record (id / kind / target / version /
 * status). The operator's P-256 public key (x/y) is supplied by the IdP
 * in the agent-state GET response (`operator_delegation_jwk`), the same
 * precedent as approval rows.
 *
 * Pure node:crypto — no SDK/WASM dependency, so it runs at sync time
 * with nothing else up.
 */
import crypto from 'node:crypto';

const EXPECTED_TYP = 'jwt+lastid-human-auth-v1';

function b64urlToBuf(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/** SHA-256 hex of a Buffer / string. */
export function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * Verify a compact ES256 JWS against an operator P-256 public key
 * `{ x_b64u, y_b64u }`. Returns the parsed payload claims on success;
 * throws on any failure. Does NOT check claim binding — the caller does.
 */
export function verifyEs256Jws(jwsCompact, operatorJwk) {
  const parts = String(jwsCompact).split('.');
  if (parts.length !== 3) throw new Error('sig is not a compact JWS');
  const [h, p, s] = parts;
  const header = JSON.parse(b64urlToBuf(h).toString('utf8'));
  if (header.alg !== 'ES256') throw new Error(`unexpected alg ${header.alg}`);
  if (header.typ !== EXPECTED_TYP) throw new Error(`unexpected typ ${header.typ}`);
  const key = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: operatorJwk.x_b64u, y: operatorJwk.y_b64u },
    format: 'jwk',
  });
  // The Rust signer emits a raw r||s signature (not DER), so verify must
  // use the ieee-p1363 encoding.
  const ok = crypto.verify(
    'sha256',
    Buffer.from(`${h}.${p}`, 'utf8'),
    { key, dsaEncoding: 'ieee-p1363' },
    b64urlToBuf(s),
  );
  if (!ok) throw new Error('ES256 signature invalid');
  return JSON.parse(b64urlToBuf(p).toString('utf8'));
}

// ── agent-authored signatures (EdDSA over the agent's Ed25519 key) ──────
//
// Operator records are ES256 (delegation_authority). Agent-authored records
// (memory write-backs) are signed by the AGENT's own Ed25519 key and verified
// against the author agent's DID-embedded public key — so every memory carries
// verifiable provenance, not just the operator's.

const AGENT_TYP = 'jwt+lastid-agent-auth-v1';
const AGENT_DID_PREFIX = 'did:lastid:agent:z';
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function bufToB64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/** Decode a base58btc string to a Buffer (inverse of agent-provisioning's encoder). */
function base58btcDecode(str) {
  const map = new Map();
  for (let i = 0; i < B58_ALPHABET.length; i += 1) map.set(B58_ALPHABET[i], i);
  const bytes = [0];
  for (const ch of String(str)) {
    const val = map.get(ch);
    if (val === undefined) throw new Error(`invalid base58 character '${ch}'`);
    let carry = val;
    for (let j = 0; j < bytes.length; j += 1) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry = Math.floor(carry / 256);
    }
  }
  // Leading '1' chars encode leading zero bytes.
  for (let k = 0; k < String(str).length && str[k] === '1'; k += 1) bytes.push(0);
  return Buffer.from(bytes.reverse());
}

/**
 * Recover an Ed25519 public KeyObject from a `did:lastid:agent:z…` DID.
 * The DID is `z` + base58btc(multicodec ed25519-pub 0xed01 || 32-byte pubkey).
 * Pure node:crypto — no SDK/WASM (runs at sync time).
 */
export function agentEd25519PublicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith(AGENT_DID_PREFIX)) {
    throw new Error('not a did:lastid:agent DID');
  }
  const decoded = base58btcDecode(did.slice(AGENT_DID_PREFIX.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('bad ed25519-pub multicodec prefix');
  }
  const pub = decoded.subarray(2); // 32-byte raw Ed25519 public key
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url') },
    format: 'jwk',
  });
}

/**
 * Sign agent-state record claims as a compact EdDSA JWS with the agent's
 * Ed25519 private key. `claims` binds the record (id/kind/target/version/
 * status) + content_sha256 — the same shape the operator's ES256 sig binds.
 */
export function signAgentRecordJws(claims, signingKey) {
  const h = bufToB64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: AGENT_TYP }), 'utf8'));
  const p = bufToB64url(Buffer.from(JSON.stringify(claims), 'utf8'));
  const sig = crypto.sign(null, Buffer.from(`${h}.${p}`, 'utf8'), signingKey);
  return `${h}.${p}.${bufToB64url(sig)}`;
}

/**
 * Verify a compact EdDSA JWS against an Ed25519 public KeyObject. Returns the
 * parsed claims; throws on any failure. Caller checks claim binding.
 */
export function verifyEdDsaJws(jwsCompact, publicKey) {
  const parts = String(jwsCompact).split('.');
  if (parts.length !== 3) throw new Error('sig is not a compact JWS');
  const [h, p, s] = parts;
  const header = JSON.parse(b64urlToBuf(h).toString('utf8'));
  if (header.alg !== 'EdDSA') throw new Error(`unexpected alg ${header.alg}`);
  if (header.typ !== AGENT_TYP) throw new Error(`unexpected typ ${header.typ}`);
  const ok = crypto.verify(null, Buffer.from(`${h}.${p}`, 'utf8'), publicKey, b64urlToBuf(s));
  if (!ok) throw new Error('EdDSA signature invalid');
  return JSON.parse(b64urlToBuf(p).toString('utf8'));
}

/**
 * Verify an agent-state record's provenance.
 *
 * @param {object} record       - wire record { id, kind, target, version, status?, sig? }
 * @param {Buffer|null} contentBytes - decrypted content bytes (active records), else null
 * @param {{x_b64u:string,y_b64u:string}|null} operatorJwk - operator delegation key
 * @param {{agentDid?:string}} [opts] - the syncing agent's own DID (the author
 *        of its slot_seed self-copies, when the record carries no author_agent_did)
 * @returns {{ok:true} | {ok:false, reason:string}}
 *
 * Policy: FAIL-CLOSED for EVERY record — rules AND memories. No signature, no
 * key, bad sig, hash mismatch, or bad binding all reject, so nothing without
 * verifiable provenance ever affects the agent. Operator-authored records are
 * ES256 (delegation_authority); agent-authored records are EdDSA over the
 * author agent's Ed25519 key (author_agent_did for shared project records, else
 * the syncing agent's own DID for its slot_seed self-copies).
 */
export function verifyRecordSignature(record, contentBytes, operatorJwk, opts = {}) {
  const hasSig = typeof record.sig === 'string' && record.sig.length > 0;
  if (!hasSig) {
    return { ok: false, reason: `${record.kind ?? 'record'} has no signature` };
  }

  const author = record.author === 'agent' ? 'agent' : 'operator';
  let claims;
  if (author === 'agent') {
    const authorDid = record.author_agent_did || opts.agentDid;
    if (!authorDid) return { ok: false, reason: 'no author DID for agent signature' };
    let key;
    try {
      key = agentEd25519PublicKeyFromDid(authorDid);
    } catch (e) {
      return { ok: false, reason: `author key: ${e.message}` };
    }
    try {
      claims = verifyEdDsaJws(record.sig, key);
    } catch (e) {
      return { ok: false, reason: `signature: ${e.message}` };
    }
  } else {
    if (!operatorJwk || !operatorJwk.x_b64u || !operatorJwk.y_b64u) {
      return { ok: false, reason: 'no operator delegation key to verify against' };
    }
    try {
      claims = verifyEs256Jws(record.sig, operatorJwk);
    } catch (e) {
      return { ok: false, reason: `signature: ${e.message}` };
    }
  }

  // The signed claims must bind THIS record (a valid sig over a different
  // record must not be replayable onto this one).
  const status = record.status ?? 'active';
  if (
    claims.id !== record.id ||
    claims.kind !== record.kind ||
    String(claims.target ?? '') !== String(record.target ?? '') ||
    Number(claims.version) !== Number(record.version) ||
    String(claims.status ?? 'active') !== status
  ) {
    return { ok: false, reason: 'signature does not bind this record' };
  }

  // Active records bind a content hash (the sig never carries plaintext).
  if (status === 'active') {
    if (!contentBytes) return { ok: false, reason: 'active record missing content' };
    if (claims.content_sha256 !== sha256Hex(contentBytes)) {
      return { ok: false, reason: 'content hash mismatch' };
    }
  }
  return { ok: true };
}
