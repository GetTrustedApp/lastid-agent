/**
 * Project-tier content crypto (saas-migration §project-memories, Option B).
 *
 * Project memories are SHARED across all of an operator's agents ("any agent
 * working in this repo"), so unlike slot_seed-keyed agent/global memories they
 * can't be encrypted per-recipient. Instead they use a key EVERY one of the
 * operator's agents can derive but no one else can:
 *
 *   project_root_seed — a 32-byte operator-scoped secret delivered to each of
 *   the operator's agents at provisioning (alongside its slot_seed). Same for
 *   all the operator's agents; never leaves them; never reaches the IdP.
 *
 *   content key = HKDF-SHA512(project_root_seed, salt=project_key,
 *                             info="lastid/project-content-enc/v1", 32)
 *
 * So a project memory is stored ONCE (not fanned out per agent), encrypted
 * under its project's content key; any of the operator's agents re-derives the
 * key from (project_root_seed, project_key) and reads it, and any agent with
 * the write capability can author one the others immediately see.
 *
 * Privacy: the IdP must group an operator's project memories per-project, but
 * must NOT learn the repo names. So the on-wire routing id is an HMAC, not the
 * project_key itself:
 *
 *   routing_id = HMAC-SHA256(project_root_seed, "lastid/project-routing/v1\0"
 *                            || project_key)   (hex)
 *
 * Every agent recomputes the same routing_id to match; the IdP sees only an
 * opaque hex string. No plaintext repo name, and no content, ever leaves.
 *
 * Reuses the LIDE SymmetricOnly envelope from agent-content-crypto.js (it
 * accepts a pre-derived KEK via `opts.key`), so there is no new wire format.
 */
import crypto from 'node:crypto';
import { encryptContent, decryptContent } from './agent-content-crypto.js';

export const PROJECT_CONTENT_KEY_INFO = 'lastid/project-content-enc/v1';
export const PROJECT_ROUTING_INFO = 'lastid/project-routing/v1';
export const KEY_LEN = 32;

/**
 * Reserved "project key" for the GLOBAL tier (memories AND rules). Global
 * operator memories/rules are shared across ALL the operator's agents —
 * semantically the same shape as a project memory, but injected/enforced ALWAYS
 * rather than repo-gated. So they ride the project Option-B rails (one shared
 * record under a key derived from project_root_seed), keyed by this reserved
 * routing id instead of a repo. The record's `kind` (rule|memory) — not the
 * routing — distinguishes them downstream, so both tiers reuse this one key.
 *
 * A real project_key is a normalized git remote ("host/org/repo"); this
 * reserved value has no host or slash, so it can never be one and its routing
 * id can't collide with any repo's. (It's only ever HMAC input — the
 * project_key itself is never serialized or sent, only the hex routing id.) The
 * browser console MUST use the byte-identical sentinel (lastid.co
 * agent-state.ts GLOBAL_SHARED_PROJECT_KEY) so both sides derive the same global
 * routing id. Changing it orphans every shared-global record — wire constant.
 * Kept visible/ASCII on purpose: an invisible char here would be a silent
 * cross-repo mismatch waiting to happen.
 */
export const GLOBAL_SHARED_PROJECT_KEY = '__lastid_global_v1__';

function assertSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new TypeError('projectRootSeed must be a 32-byte Buffer');
  }
}
function assertProjectKey(projectKey) {
  if (typeof projectKey !== 'string' || projectKey.length === 0) {
    throw new TypeError('projectKey must be a non-empty string');
  }
}

function assertRoutingId(routingId) {
  if (typeof routingId !== 'string' || routingId.length === 0) {
    throw new TypeError('routingId must be a non-empty string');
  }
}

/**
 * Derive the opaque per-project routing id the IdP uses to scope/group an
 * operator's project memories without learning the repo name. HMAC under the
 * shared project_root_seed → every one of the operator's agents computes the
 * same id; an outsider (and the IdP) cannot invert it to the project_key.
 *
 * This id is stored in plaintext on the record, so it ALSO seeds the content
 * key below — letting a reader who has only the record (routing_id) decrypt
 * without first knowing the repo name (which lives inside the ciphertext).
 */
export function deriveProjectRoutingId(projectRootSeed, projectKey) {
  assertSeed(projectRootSeed);
  assertProjectKey(projectKey);
  const h = crypto.createHmac('sha256', projectRootSeed);
  h.update(PROJECT_ROUTING_INFO);
  h.update('\0'); // domain separator so info||key can't be ambiguous
  h.update(projectKey, 'utf8');
  return h.digest('hex');
}

/**
 * Derive the 32-byte per-project content KEK from the operator's
 * project_root_seed and the project's ROUTING ID (not the repo name).
 *
 * Why keyed on routing_id, not project_key: when an agent syncs a project
 * record it has only the plaintext routing_id — the repo name (project_key) is
 * inside the ciphertext. Deriving the content key from routing_id breaks that
 * circular dependency (reader derives the key from the record alone, decrypts,
 * THEN learns project_key). Security is unchanged: it comes from the secret
 * project_root_seed (the HKDF IKM); the routing_id is a public, per-project
 * salt. A writer computes routing_id = deriveProjectRoutingId(seed, project_key)
 * first, so both sides agree.
 */
export function deriveProjectContentKey(projectRootSeed, routingId) {
  assertSeed(projectRootSeed);
  assertRoutingId(routingId);
  return Buffer.from(
    crypto.hkdfSync(
      'sha512',
      projectRootSeed,
      Buffer.from(routingId, 'utf8'),
      Buffer.from(PROJECT_CONTENT_KEY_INFO, 'utf8'),
      KEY_LEN,
    ),
  );
}

/**
 * Encrypt project content into a LIDE SymmetricOnly envelope under the project
 * content key (keyed by `routingId`). Returns the packed envelope Buffer.
 * `opts` forwards deterministic test vectors (dek/nonces) to encryptContent.
 */
export function encryptProjectContent(projectRootSeed, routingId, plaintext, opts = {}) {
  const key = deriveProjectContentKey(projectRootSeed, routingId);
  try {
    return encryptContent(null, plaintext, { ...opts, key });
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypt a project-content envelope (Buffer or base64) under the project
 * content key (keyed by `routingId`). Throws on the wrong seed, wrong
 * routing_id, or tampering.
 */
export function decryptProjectContent(projectRootSeed, routingId, packed, opts = {}) {
  const key = deriveProjectContentKey(projectRootSeed, routingId);
  try {
    return decryptContent(null, packed, { ...opts, key });
  } finally {
    key.fill(0);
  }
}

/** Encrypt a JSON-serialisable object as project content; returns the buffer. */
export function encryptProjectJson(projectRootSeed, routingId, obj, opts = {}) {
  return encryptProjectContent(projectRootSeed, routingId, Buffer.from(JSON.stringify(obj), 'utf8'), opts);
}

/** Decrypt a project-content envelope back into a parsed object. */
export function decryptProjectJson(projectRootSeed, routingId, packed, opts = {}) {
  return JSON.parse(decryptProjectContent(projectRootSeed, routingId, packed, opts).toString('utf8'));
}
