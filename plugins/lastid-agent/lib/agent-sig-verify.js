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

/**
 * Verify an agent-state record's provenance.
 *
 * @param {object} record       - wire record { id, kind, target, version, status?, sig? }
 * @param {Buffer|null} contentBytes - decrypted content bytes (active records), else null
 * @param {{x_b64u:string,y_b64u:string}|null} operatorJwk - operator delegation key
 * @returns {{ok:true} | {ok:false, reason:string}}
 *
 * Policy: RULES are fail-closed — no key / no sig / bad sig / hash
 * mismatch / bad binding all reject, so an unverified rule never affects
 * enforcement. MEMORIES are verify-if-signed: unsigned is allowed
 * (advisory), signed-but-invalid is rejected.
 */
export function verifyRecordSignature(record, contentBytes, operatorJwk) {
  const isRule = record.kind === 'rule';
  const hasSig = typeof record.sig === 'string' && record.sig.length > 0;

  if (!hasSig) {
    return isRule ? { ok: false, reason: 'rule has no signature' } : { ok: true };
  }
  if (!operatorJwk || !operatorJwk.x_b64u || !operatorJwk.y_b64u) {
    return isRule
      ? { ok: false, reason: 'no operator delegation key to verify against' }
      : { ok: true };
  }

  let claims;
  try {
    claims = verifyEs256Jws(record.sig, operatorJwk);
  } catch (e) {
    return { ok: false, reason: `signature: ${e.message}` };
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
