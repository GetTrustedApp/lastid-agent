/**
 * Local cache of the agent's vault SHARES — stored SEALED at rest.
 *
 * The agent holds `vault:use`, never `read`: the credential secret stays
 * encrypted on disk (the same slot_seed-sealed blob the operator published) and
 * is unfurled ONLY by the listener at inject time. The sync writes sealed blobs
 * here without decrypting; `vault_list` decodes on demand and returns metadata
 * via `vaultListView`, which DROPS the secret. A regression that persists or
 * returns the plaintext secret would put a credential in the LLM's context —
 * the whole thing this design prevents.
 *
 * Single-writer: the listener's agent-state sync owns writes (same posture as
 * the operator-store / groups map). Stored at
 * `~/.lastid-agent/<scope>/vault-shares.json`, one entry per share id.
 */
import { readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { decryptContent } from './agent-content-crypto.js';
import { verifyRecordSignature } from './agent-sig-verify.js';

export function vaultCachePath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'vault-shares.json');
}

function readAll(scope) {
  try {
    const obj = JSON.parse(readFileSync(vaultCachePath(scope), 'utf8'));
    return obj && typeof obj === 'object' ? obj : {};
  } catch {
    return {};
  }
}

function writeAll(scope, obj) {
  const p = vaultCachePath(scope);
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const tmp = `${p}.tmp`;
  writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
  renameSync(tmp, p);
}

/**
 * Apply synced vault records. Active → upsert the SEALED blob + routing
 * metadata (never decrypted here); revoked → delete (the agent drops it).
 * Returns the number of entries changed. Malformed records are skipped.
 */
export function applyVaultRecords(scope, records) {
  const all = readAll(scope);
  let changed = 0;
  for (const r of records ?? []) {
    if (!r || typeof r.id !== 'string' || r.id.length === 0) continue;
    if (r.status === 'revoked') {
      if (all[r.id]) {
        delete all[r.id];
        changed += 1;
      }
      continue;
    }
    if (typeof r.enc_b64 !== 'string' || r.enc_b64.length === 0) continue;
    all[r.id] = {
      id: r.id,
      version: Number.isInteger(r.version) ? r.version : 0,
      status: 'active',
      enc_b64: r.enc_b64, // SEALED — never decrypted at rest
      // target + sig are kept so the inject path can verify the operator
      // signature at use time (the bundle isn't decrypted at sync).
      target: r.target ?? r.for_agent_did ?? null,
      sig: typeof r.sig === 'string' ? r.sig : null,
      for_agent_did: r.for_agent_did ?? r.target ?? null,
      updated_at: r.updated_at ?? null,
    };
    changed += 1;
  }
  if (changed > 0) writeAll(scope, all);
  return changed;
}

/** All cached sealed shares (newest write order not guaranteed). */
export function listVaultCache(scope = 'main') {
  return Object.values(readAll(scope));
}

/** Path to the NON-SECRET CLI binding index (item ids + binary names only). */
export function cliBindingsPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'cli-bindings.json');
}

/**
 * Recompute the CLI binding index from the cached vault shares and write it to
 * cli-bindings.json: { bindings: [{ item_id, binaries }] } for every
 * env-injection share. Read by the PreToolUse hook (cheap — no keychain, no
 * decrypt) to transparently rewrite `aws …` → `lastid-agent run --item <id> --
 * aws …`. Carries NO secret: only item ids + binary names (both already in the
 * operator-signed share). Best-effort; returns the bindings it wrote.
 */
export function refreshCliBindings(scope = 'main', slotSeed, deps = {}) {
  const bindings = [];
  try {
    const { items: decoded } = decryptedVaultViews(scope, slotSeed, deps);
    for (const v of decoded) {
      if (v?.injection?.type !== 'env') continue;
      const binaries = Array.isArray(v.binaries)
        ? v.binaries.filter((b) => typeof b === 'string' && b.length > 0)
        : [];
      if (binaries.length > 0 && typeof v.id === 'string') {
        bindings.push({ item_id: v.id, binaries });
      }
    }
    const p = cliBindingsPath(scope);
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    const tmp = `${p}.tmp`;
    writeFileSync(tmp, JSON.stringify({ bindings, updated_at: new Date().toISOString() }), { mode: 0o600 });
    renameSync(tmp, p);
  } catch {
    /* best-effort — the hook treats a missing/empty index as "no bindings" */
  }
  return bindings;
}

/** Read the CLI binding index (or [] when absent). NO secret — safe in a hook. */
export function readCliBindings(scope = 'main') {
  try {
    const obj = JSON.parse(readFileSync(cliBindingsPath(scope), 'utf8'));
    return Array.isArray(obj?.bindings) ? obj.bindings : [];
  } catch {
    return [];
  }
}

/** One cached sealed share by id, or null. */
export function getVaultShare(scope, id) {
  return readAll(scope)[id] ?? null;
}

/**
 * Resolve a cached share to its DECODED + VERIFIED bundle, or null. Decrypts
 * the sealed blob with the agent's slot_seed, then verifies the operator's
 * delegation signature over {kind:vault,id,target,version,status,content_sha256}
 * AND that content_sha256 matches the decrypted bytes. A blob the IdP can't
 * have produced (wrong slot_seed → garbage) or an unsigned/forged share returns
 * null — so neither vault_list nor the inject path will ever use it.
 *
 * Used by both the listener (inject) and vault_list. The DECODED bundle carries
 * the secret — callers MUST strip it (vaultListView) before returning anything
 * to the agent; only the inject path reads the secret.
 *
 * @returns {object|null} the decoded share content (incl. secret)
 */
export function resolveVaultShare(scope, id, { slotSeed, operatorJwk, onReject } = {}) {
  const entry = getVaultShare(scope, id);
  if (!entry || !entry.enc_b64) return null;
  let bytes;
  try {
    bytes = decryptContent(slotSeed, entry.enc_b64);
  } catch {
    if (onReject) onReject(id, 'undecryptable (wrong slot_seed / corrupt)');
    return null;
  }
  const record = {
    kind: 'vault',
    id,
    target: entry.target ?? entry.for_agent_did ?? null,
    version: entry.version ?? 0,
    status: 'active',
    sig: entry.sig ?? null,
    author: 'operator',
  };
  const v = verifyRecordSignature(record, bytes, operatorJwk ?? null, {});
  if (!(v === true || (v && v.ok === true))) {
    if (onReject) onReject(id, `unverified: ${(v && v.reason) || 'bad signature'}`);
    return null;
  }
  try {
    return JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    if (onReject) onReject(id, 'decoded bytes are not JSON');
    return null;
  }
}

/**
 * Resolve the JIT-released SECRET for a share, via the TWO-LAYER envelope. The
 * secret is NEVER cached:
 *   1. `fetchWrappedSecret(id, handlePubB64, handleId)` POSTs the handle's
 *      public key to the IdP, which wraps the (opaque, slot-sealed) secret to it
 *      → `wrapped_secret_b64`.
 *   2. `openWithHandle(handlePrivB64, handleId, wrapped)` opens the OUTER layer
 *      with the handle's private key → the inner (slot-sealed) bytes.
 *   3. `decryptContent(slotSeed, inner)` opens the INNER layer → the secret JSON.
 * Returns `{ secret, secret_secondary?, zeroize() }` or null.
 *
 * `zeroize()` overwrites the decrypted byte buffers — call it the instant the
 * secret has been injected. (JS strings are immutable + GC-managed, so the
 * parsed string copy itself can't be wiped; zeroize wipes the decrypted Buffers
 * — the controllable copies — and the caller drops references. The secret never
 * touches disk; the handle private key lives only in memory and is revoked.)
 *
 * Fails closed: no release (404 → null), an outer-layer open failure (wrong
 * handle key / handle_id / tamper), an undecryptable inner blob (only the
 * operator can seal to this slot_seed), or an embedded item_id that doesn't
 * match the requested share (a relay serving another share's secret).
 */
export async function resolveVaultSecret(
  id,
  { slotSeed, handle, fetchWrappedSecret, openWithHandle, onReject } = {},
) {
  const handlePubB64 = handle?.handlePubB64;
  const handlePrivB64 = handle?.handlePrivB64;
  const handleId = handle?.token;
  if (!handlePubB64 || !handlePrivB64 || !handleId) {
    if (onReject) onReject(id, 'handle has no ephemeral keypair (cannot unwrap)');
    return null;
  }
  let wrapped;
  try {
    wrapped = await fetchWrappedSecret(id, handlePubB64, handleId);
  } catch (e) {
    if (onReject) onReject(id, `secret fetch failed: ${e?.message ?? e}`);
    return null;
  }
  if (typeof wrapped !== 'string' || wrapped.length === 0) {
    if (onReject) onReject(id, 'no secret released');
    return null;
  }
  // Outer layer: open the handle wrap with the (in-memory) handle private key.
  let inner;
  try {
    inner = Buffer.from(await openWithHandle(handlePrivB64, handleId, wrapped));
  } catch (e) {
    if (onReject) onReject(id, `handle unwrap failed (wrong key/id or tamper): ${e?.message ?? e}`);
    return null;
  }
  // Inner layer: unseal with the agent's slot_seed.
  let bytes;
  try {
    bytes = decryptContent(slotSeed, inner);
  } catch {
    try {
      inner.fill(0);
    } catch {
      /* best-effort */
    }
    if (onReject) onReject(id, 'undecryptable secret (wrong slot_seed / corrupt)');
    return null;
  }
  // The secret is now in plaintext (in `bytes`). This timestamp opens the
  // CREDENTIALED window — the true exposure span the metric reports is from
  // here to zeroize (after inject + the outbound call). Measuring from the
  // decrypt (not from the start of the JIT fetch) excludes the time the secret
  // was still wrapped/in-flight from the IdP.
  const decryptedAtMs = Date.now();
  const wipe = () => {
    try {
      bytes.fill(0);
      inner.fill(0);
    } catch {
      /* best-effort */
    }
  };
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    wipe();
    if (onReject) onReject(id, 'released secret is not JSON');
    return null;
  }
  // Bind the released secret to THIS share — reject a (validly-sealed) blob
  // served under the wrong id.
  if (parsed.item_id !== id) {
    wipe();
    if (onReject) onReject(id, `released secret item_id mismatch (got ${parsed.item_id})`);
    return null;
  }
  if (typeof parsed.secret !== 'string' || parsed.secret.length === 0) {
    wipe();
    if (onReject) onReject(id, 'released secret is empty');
    return null;
  }
  return {
    secret: parsed.secret,
    secret_secondary:
      typeof parsed.secret_secondary === 'string' ? parsed.secret_secondary : undefined,
    // When the secret entered plaintext — the start of the credentialed window.
    decryptedAtMs,
    zeroize: wipe,
  };
}

/**
 * Metadata-only view of a DECODED vault bundle — DROPS the secret. This is the
 * ONLY shape `vault_list` may return to the agent. Keep this the single choke
 * point: never spread the raw decoded bundle into a tool result.
 */
export function vaultListView(decoded, id = null) {
  const bundle = decoded && typeof decoded === 'object' ? decoded : {};
  // Explicitly pull BOTH secrets OUT so neither can ride along, whatever else
  // the bundle carries (AWS/OAuth credentials carry a companion secret). The
  // `acl` blob is operator-signing detail the agent doesn't need — drop it too.
  const { secret, secret_secondary, acl, ...meta } = bundle;
  return {
    id: id ?? meta.item_id ?? null,
    ...meta,
    has_secret: typeof secret === 'string' && secret.length > 0,
    has_secondary_secret: typeof secret_secondary === 'string' && secret_secondary.length > 0,
    // Human-readable usage context for the agent: how to use it + the limits
    // it should expect. Never the secret.
    usage: usageContext(meta),
    constraints_summary: summarizeConstraints(meta.constraints),
  };
}

/**
 * Decode EVERY cached sealed share to its metadata-only view (secret dropped by
 * vaultListView). Undecryptable entries (wrong slot / corrupt) and revoked ones
 * are skipped — never surface a partial. This is the single decode-all choke
 * point shared by the `vault_list` MCP tool and the `vault-list` CLI subcommand
 * (which feeds the session-start credential awareness block). Deps are
 * injectable so the decode loop is unit-testable without real crypto.
 *
 * Returns `{ items, undecryptable }` (NOT a bare array) so the caller can
 * surface the count of skipped shares. Silent skips were how the 2026-05-28
 * sub-agent seal-key-mismatch bug went unnoticed for so long — every share
 * was sealed under BIP85 slot 0's key, every decrypt failed AEAD, every one
 * got swallowed here, and `vault_list` cheerfully returned 0 items as if the
 * operator had shared nothing. A non-zero undecryptable count is a signal,
 * not noise.
 */
export function decryptedVaultViews(
  scope = 'main',
  slotSeed,
  { listCache = listVaultCache, decrypt = decryptContent } = {},
) {
  const items = [];
  const undecryptable = [];
  for (const sealed of listCache(scope)) {
    if (!sealed || typeof sealed.enc_b64 !== 'string' || sealed.status === 'revoked') continue;
    try {
      const bytes = decrypt(slotSeed, sealed.enc_b64);
      const decoded = JSON.parse(Buffer.from(bytes).toString('utf8'));
      items.push(vaultListView(decoded, sealed.id));
    } catch (err) {
      // Record what we couldn't open so a wrong-key bug surfaces in vault_list
      // instead of presenting as "operator shared nothing." Reason is the
      // exception message, truncated to a single short line.
      const reason = err instanceof Error
        ? (err.message || 'decrypt failed').split('\n')[0].slice(0, 140)
        : String(err).slice(0, 140);
      undecryptable.push({ id: sealed.id, reason });
    }
  }
  return { items, undecryptable };
}

/** A short "how to use this" line for the agent, from the share metadata. */
export function usageContext(meta) {
  const parts = [];
  if (meta.service) parts.push(`service: ${meta.service}`);
  if (meta.account) parts.push(`account: ${meta.account}`);
  if (meta.key_label) parts.push(`credential: ${meta.key_label}`);
  const inj = meta.injection?.type;
  if (inj === 'oauth_bearer') parts.push('attached as an OAuth bearer token (auto-refreshed)');
  else if (inj === 'header') parts.push(`attached as the ${meta.injection?.name ?? 'Authorization'} header`);
  else if (inj === 'query_param') parts.push(`attached as the ${meta.injection?.name ?? 'api_key'} query param`);
  else if (inj === 'basic_auth') parts.push('attached as HTTP basic auth');
  else if (inj === 'env') {
    const vars = Array.isArray(meta.injection?.env_map)
      ? meta.injection.env_map.map((e) => e?.name).filter(Boolean)
      : [];
    const bins = Array.isArray(meta.binaries) ? meta.binaries : [];
    // Tell the agent this credential is for a CLI, not http_fetch: run it via
    // `lastid-agent run` so the secret is injected as env into the child.
    parts.push(
      `injected as env (${vars.join(', ') || 'see env_map'}) for CLI use — run it with ` +
        `\`lastid-agent run --item ${meta.item_id ?? '<id>'} -- ${bins[0] ?? '<command>'} …\``,
    );
  }
  if (meta.docs_url) parts.push(`docs: ${meta.docs_url}`);
  return parts.join(' · ') || undefined;
}

/** Plain-language summary of the canonical {type}-tagged constraints so the
 *  agent knows the limits before it tries to use the credential. */
export function summarizeConstraints(constraints) {
  if (!Array.isArray(constraints) || constraints.length === 0) return undefined;
  const dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hhmm = (m) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
  const offset = (o) => (o === 0 ? 'UTC' : `UTC${o >= 0 ? '+' : ''}${o / 60}`);
  return constraints
    .map((c) => {
      switch (c?.type) {
        case 'recurring_schedule': {
          const days = (Array.isArray(c.days) ? c.days : []).map((d) => dayNames[d] ?? d).join('/');
          return `usable ${days} ${hhmm(c.start_minute)}–${hhmm(c.end_minute)} ${offset(c.utc_offset_minutes)}`;
        }
        case 'time_window':
          return `usable ${c.not_before} → ${c.not_after}`;
        case 'rate_per_minute':
          return `max ${c.max}/min`;
        case 'amount_cap':
          return `amount cap ${c.max} ${c.unit}`;
        case 'scope_required':
          return `scoped to ${c.name}=${c.value}`;
        default:
          return c?.type ?? 'constraint';
      }
    })
    .join('; ');
}
