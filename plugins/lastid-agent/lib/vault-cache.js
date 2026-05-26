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
