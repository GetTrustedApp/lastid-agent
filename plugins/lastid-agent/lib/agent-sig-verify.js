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
import { createRequire } from 'node:module';

// Agent-authored signatures are now ES256 (P-256) and produced/verified by
// the Rust SDK via the bundled WASM — single source of truth with the
// SDK/IdP, and it removes the hand-rolled base58/multicodec DID decoder
// that was the previous drift risk. The operator (delegation_authority)
// path below stays pure node:crypto: it's human crypto, already P-256, and
// must run at agent-state sync time with nothing else up.
const wasmRequire = createRequire(import.meta.url);
const agentWasm = wasmRequire('../vendor/lastid-agent-wasm/lastid_agent_wasm.js');

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

// ── agent-authored signatures (ES256 over the agent's P-256 key) ────────
//
// Operator records are ES256 (delegation_authority, verified with
// node:crypto above). Agent-authored records (memory write-backs) are signed
// by the AGENT's own P-256 (ES256) key and verified against the author
// agent's DID-embedded public key — so every memory carries verifiable
// provenance, not just the operator's. The DID→pubkey decode + the
// sign/verify are owned by the Rust SDK via the bundled WASM, so the plugin
// can't drift from the SDK/IdP on the agent identity.

const AGENT_TYP = 'jwt+lastid-agent-auth-v1';

function bufToB64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * Recover the agent's compressed-SEC1 (33-byte) P-256 public key from a
 * `did:lastid:agent:z…` DID, via the WASM `parseAgentDid`. Returns a
 * Uint8Array suitable for `verifyP256`.
 */
export function agentP256PubkeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:lastid:agent:z')) {
    throw new Error('not a did:lastid:agent DID');
  }
  // WASM throws on a malformed DID / wrong multicodec / bad point.
  return agentWasm.parseAgentDid(did);
}

// Multibase base58btc alphabet — same table the agent-provisioning DID
// ENCODER uses; here we DECODE the `z…` suffix of an existing Ed25519
// agent DID back to bytes (pure JS, no wasm — the Ed25519 verify path
// must run at sync time with nothing else up, same as the operator path).
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = (() => {
  const m = new Map();
  for (let i = 0; i < BASE58_ALPHABET.length; i += 1) m.set(BASE58_ALPHABET[i], i);
  return m;
})();

function base58btcDecode(str) {
  let n = 0n;
  for (const ch of str) {
    const v = BASE58_INDEX.get(ch);
    if (v === undefined) throw new Error(`invalid base58 char: ${ch}`);
    n = n * 58n + BigInt(v);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  // Restore leading-zero bytes encoded as leading '1's.
  for (const ch of str) {
    if (ch === '1') bytes.unshift(0);
    else break;
  }
  return Buffer.from(bytes);
}

/**
 * Recover an existing agent's raw 32-byte Ed25519 public key from its
 * `did:lastid:agent:z6Mk…` DID. The multibase `z` suffix decodes to
 * multicodec(ed25519-pub=0xed01) || 32-byte pubkey — the inverse of the
 * encoder in agent-provisioning.js. Pure JS so it runs at sync time.
 * Returns a Uint8Array suitable for building an OKP JWK.
 */
export function agentEd25519PublicKeyFromDid(did) {
  const PREFIX = 'did:lastid:agent:z';
  if (typeof did !== 'string' || !did.startsWith(PREFIX)) {
    throw new Error('not a did:lastid:agent DID');
  }
  const decoded = base58btcDecode(did.slice(PREFIX.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('DID is not an Ed25519 (0xed01) agent DID');
  }
  return new Uint8Array(decoded.subarray(2));
}

/**
 * Sign agent-state record claims as a compact JWS — DUAL-ALGO, matching the
 * signing agent's own identity key. `claims` binds the record
 * (id/kind/target/version/status) + content_sha256 — the same shape the
 * operator's ES256 sig binds.
 *
 *   - P-256 (new agents): `alg:'ES256'`, signature from the WASM `signP256`
 *     (raw r||s), matching how the IdP/SDK sign + verify.
 *   - Ed25519 (existing agents): `alg:'EdDSA'`, raw 64-byte Ed25519 signature
 *     via pure `node:crypto` (`sign(null, …, ed25519Key)`) — the same
 *     primitive dpop.js uses. Feeding an Ed25519 seed into the P-256 signer
 *     was the regression: the sync verifier (dual-algo below) rejected it.
 *
 * Feature-detected from the signer material:
 *   - an Ed25519 `signingKey` KeyObject (`asymmetricKeyType === 'ed25519'`)
 *     → EdDSA path.
 *   - else the raw 32-byte P-256 scalar → ES256 path.
 *
 * @param {object} claims
 * @param {Uint8Array|Buffer|import('node:crypto').KeyObject} signer
 *        Either the agent's raw 32-byte P-256 scalar
 *        (`deriveAgentKeypair(...).signingSeed` for a P-256 agent), OR an
 *        options object `{ signingKey, signingSeed }` from
 *        `deriveAgentKeypair(slotSeed, agentDid)` (the caller passes both;
 *        the Ed25519 KeyObject selects EdDSA, otherwise the scalar selects
 *        ES256). A bare Buffer/Uint8Array is still accepted (P-256 scalar)
 *        for backward-compat.
 */
export function signAgentRecordJws(claims, signer) {
  // Normalize the two accepted shapes: a bare P-256 scalar, or
  // { signingKey, signingSeed } from deriveAgentKeypair.
  const signingKey =
    signer && typeof signer === 'object' && 'signingKey' in signer
      ? signer.signingKey
      : undefined;
  const signingSeed =
    signer && typeof signer === 'object' && 'signingSeed' in signer
      ? signer.signingSeed
      : signer;

  const isEd25519 = signingKey?.asymmetricKeyType === 'ed25519';
  const alg = isEd25519 ? 'EdDSA' : 'ES256';
  const h = bufToB64url(Buffer.from(JSON.stringify({ alg, typ: AGENT_TYP }), 'utf8'));
  const p = bufToB64url(Buffer.from(JSON.stringify(claims), 'utf8'));
  const signingInput = Buffer.from(`${h}.${p}`, 'utf8');

  const sig = isEd25519
    ? // EdDSA: node returns the raw 64-byte Ed25519 signature directly.
      crypto.sign(null, signingInput, signingKey)
    : // ES256: WASM signP256 over the raw P-256 scalar → raw r||s.
      agentWasm.signP256(new Uint8Array(signingSeed), signingInput);
  return `${h}.${p}.${bufToB64url(sig)}`;
}

/**
 * Verify a compact agent-authored record JWS — DUAL-ALGO, feature-detected
 * from the record's own `header.alg`. Returns the parsed claims; throws on
 * any failure. Caller checks claim binding.
 *
 *   - ES256: verify against the agent's compressed-SEC1 P-256 pubkey
 *     (`agentP256PubkeyFromDid`) via the WASM `verifyP256`.
 *   - EdDSA: verify against the agent's raw 32-byte Ed25519 pubkey
 *     (`agentEd25519PublicKeyFromDid`) via pure `node:crypto`
 *     (`verify(null, …)` over an OKP JWK).
 *
 * Verification is NOT weakened: an EdDSA header is verified ONLY against the
 * Ed25519 key and an ES256 header ONLY against the P-256 key. The caller
 * supplies BOTH-capable key material via `keyForDid` so we never verify a
 * record against a key of the wrong curve.
 *
 * @param {string} jwsCompact
 * @param {{ es256?: Uint8Array, ed25519?: Uint8Array }} keys
 *        Pre-derived pubkeys for the author DID (one per algo). Only the one
 *        matching the record's alg is used.
 */
export function verifyAgentRecordJws(jwsCompact, keys) {
  const parts = String(jwsCompact).split('.');
  if (parts.length !== 3) throw new Error('sig is not a compact JWS');
  const [h, p, s] = parts;
  const header = JSON.parse(b64urlToBuf(h).toString('utf8'));
  if (header.typ !== AGENT_TYP) throw new Error(`unexpected typ ${header.typ}`);
  const signingInput = Buffer.from(`${h}.${p}`, 'utf8');
  const sig = b64urlToBuf(s);

  if (header.alg === 'EdDSA') {
    if (!keys.ed25519) throw new Error('no Ed25519 key for EdDSA record');
    const pubKeyObj = crypto.createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(keys.ed25519).toString('base64url'),
      },
      format: 'jwk',
    });
    // EdDSA raw 64-byte signature → verify with algorithm `null`.
    const ok = crypto.verify(null, signingInput, pubKeyObj, new Uint8Array(sig));
    if (!ok) throw new Error('EdDSA signature invalid');
    return JSON.parse(b64urlToBuf(p).toString('utf8'));
  }

  if (header.alg === 'ES256') {
    if (!keys.es256) throw new Error('no P-256 key for ES256 record');
    const ok = agentWasm.verifyP256(
      new Uint8Array(keys.es256),
      signingInput,
      new Uint8Array(sig),
    );
    if (!ok) throw new Error('ES256 signature invalid');
    return JSON.parse(b64urlToBuf(p).toString('utf8'));
  }

  throw new Error(`unexpected alg ${header.alg}`);
}

/**
 * BACKWARD-COMPAT shim: verify an ES256-only agent record JWS against a
 * single P-256 pubkey. Kept for any external caller; the dual-algo
 * `verifyAgentRecordJws` is the path the record verifier uses.
 */
export function verifyAgentEs256Jws(jwsCompact, pubkeyBytes) {
  return verifyAgentRecordJws(jwsCompact, { es256: pubkeyBytes });
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
 * ES256 (delegation_authority); agent-authored records are ES256 over the
 * author agent's P-256 key (author_agent_did for shared project records, else
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
    // Feature-detect the author's identity algo from its DID's multibase
    // prefix: existing Ed25519 agents are `z6Mk…`, P-256 agents are `zDn…`.
    // We recover ONLY the key matching the agent's curve, then the dual-algo
    // verifier checks the record's header.alg against it (it rejects any
    // alg/key mismatch — verification is not weakened).
    const isEd25519 = authorDid.startsWith('did:lastid:agent:z6Mk');
    const keys = {};
    try {
      if (isEd25519) {
        keys.ed25519 = agentEd25519PublicKeyFromDid(authorDid);
      } else {
        keys.es256 = agentP256PubkeyFromDid(authorDid);
      }
    } catch (e) {
      return { ok: false, reason: `author key: ${e.message}` };
    }
    try {
      claims = verifyAgentRecordJws(record.sig, keys);
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
