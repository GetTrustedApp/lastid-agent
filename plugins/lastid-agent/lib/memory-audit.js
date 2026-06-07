/**
 * Agent memory audit chain (local, signed) — PER-AGENT, genesis + checkpointed.
 *
 * Every memory/tool CUD appends a record to an append-only chain. Each record is
 * blake3-linked to its predecessor (prev_hash) and ES256 (P-256)-signed with the
 * agent's stable key (deriveAgentP256Keypair) — tamper-evident + provenance.
 *
 * NOTE (cross-system contract): the console's chain verifier
 * (lastid.co `agent-audit-verify.ts`) must verify the SAME ES256 (P-256)
 * raw r||s signature over the canonical core bytes. The agent identity
 * migrated Ed25519→P-256; the console verifier must match or shipped
 * chains read as `signature_invalid`.
 *
 * KEYED PER AGENT, not per scope. A scope (~/.lastid-agent/<scope>/) can host
 * TWO agents at once (e.g. two slots both running in 'main'); a single
 * per-scope chain would interleave their records and two writers would fork it,
 * so every per-agent verify reads "broken." Instead each agent gets its own
 * chain file under `<scope>/audit/<slug>.jsonl` with its own seq/prev_hash, so
 * concurrent agents never collide and each chain verifies on its own.
 *
 *   - GENESIS: an agent's first record is seq 0 with prev_hash=null.
 *   - CHECKPOINT: every CHECKPOINT_INTERVAL records a `ChainCheckpoint` record
 *     is appended (anchors the chain so a partial/drained view still verifies,
 *     and marks a segment boundary the console renders as a divider).
 *
 * The records carry only NON-SENSITIVE metadata (event_type, memory_id, kind,
 * fields_changed, …) — never the memory claim — so they can ship to the IdP for
 * the operator to view cross-device without leaking content.
 */
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, renameSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { sign as ecSign, verify as ecVerify, createPublicKey, randomBytes } from 'node:crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

/** Event type for a checkpoint record (mirrors lastid-core AuditEventType). */
export const CHECKPOINT_EVENT = 'ChainCheckpoint';
/** Append a checkpoint every N records (count includes checkpoints). */
export const CHECKPOINT_INTERVAL = 500;

/** Filesystem-safe slug for an agent DID, so one file maps to one agent. A
 *  blake3 prefix keeps it short, collision-free, and free of path characters. */
export function agentChainSlug(agentDid) {
  const did = typeof agentDid === 'string' && agentDid.length > 0 ? agentDid : 'unknown';
  return bytesToHex(blake3(Buffer.from(did, 'utf-8'))).slice(0, 24);
}

function auditDir(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'audit');
}

/** This agent's chain file within the scope. */
export function memoryAuditPath(scope = 'main', agentDid = null) {
  return join(auditDir(scope), `${agentChainSlug(agentDid)}.jsonl`);
}
function shipCursorPath(scope = 'main', agentDid = null) {
  return join(auditDir(scope), `${agentChainSlug(agentDid)}.cursor.json`);
}

/** blake3 hex — matches the SDK's audit chaining algorithm, reproduced
 *  cross-runtime by the console with the same @noble/hashes blake3. */
function blake3Hex(buf) {
  return bytesToHex(blake3(buf));
}

/** Deterministic JSON (sorted keys, recursive) so the signed/hashed bytes are
 *  reproducible by a verifier. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

export function readMemoryAudit(scope = 'main', agentDid = null) {
  let raw;
  try {
    raw = readFileSync(memoryAuditPath(scope, agentDid), 'utf8');
  } catch {
    return [];
  }
  const out = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      /* skip a corrupt line */
    }
  }
  return out;
}

function lastEntry(scope, agentDid) {
  const all = readMemoryAudit(scope, agentDid);
  return all.length > 0 ? all[all.length - 1] : null;
}

/** A fresh chain generation id, minted at every genesis. Lets the console group
 *  by (agent_did, chain_id) so a re-rooted run (re-provision, on-break self-heal)
 *  is a SEPARATE segment from older records under the same DID — old broken
 *  per-scope records never merge with / collide seq against the new clean run. */
function newChainId() {
  return bytesToHex(randomBytes(16));
}

/** The core that is hashed + signed — field set + null defaults MUST match the
 *  console verifier (agent-audit-verify.ts). A genesis record (prev=null) mints
 *  a new chain_id; every later record inherits its predecessor's. */
function recordCore(prev, { agentDid, eventType, memoryId, metadata }) {
  return {
    chain_id: prev ? prev.chain_id : newChainId(),
    seq: prev ? Number(prev.seq) + 1 : 0,
    timestamp: new Date().toISOString(),
    agent_did: agentDid ?? null,
    event_type: eventType,
    memory_id: memoryId ?? null,
    metadata: metadata ?? {},
    prev_hash: prev ? prev.integrity_hash : null,
  };
}

/** Reconstruct the hashed core of an EXISTING record (same field set + null
 *  defaults as recordCore) — shared by verify + the tail-integrity check. */
function coreFromRecord(r) {
  return {
    chain_id: r.chain_id ?? null,
    seq: r.seq,
    timestamp: r.timestamp,
    agent_did: r.agent_did ?? null,
    event_type: r.event_type,
    memory_id: r.memory_id ?? null,
    metadata: r.metadata ?? {},
    prev_hash: r.prev_hash ?? null,
  };
}

/** O(1) tail check: does the head record's integrity_hash still match its core?
 *  If not, the chain's tail is corrupt/tampered and we must not link onto it. */
function tailIntact(rec) {
  return blake3Hex(Buffer.from(canonicalJson(coreFromRecord(rec)), 'utf-8')) === rec.integrity_hash;
}

/**
 * Compute the record signature. `signer` is EITHER:
 *   - a node KeyObject (LEGACY agent): sign in-process with the seed-derived key.
 *   - an async `(bytes) => Promise<string>` (BROKER-NATIVE agent): the broker
 *     holds the key + raw-ES256-signs the bytes, returning the same base64 sig —
 *     so the seed never enters node yet the audit chain stays fully signed.
 *   - falsy: no signature (records are still hash-linked).
 * Returns the base64 signature or null. Never throws (logs + degrades).
 */
async function computeAuditSignature(signer, bytes) {
  if (!signer) return null;
  try {
    if (typeof signer === 'function') {
      return await signer(bytes);
    }
    // ES256: SHA-256 + ECDSA P-256, raw r||s (ieee-p1363) — matches the agent's
    // identity alg and the console verifier (and the broker's raw sign).
    return ecSign('sha256', bytes, { key: signer, dsaEncoding: 'ieee-p1363' }).toString('base64');
  } catch (err) {
    process.stderr.write(`[lastid-agent] memory-audit sign failed: ${err?.message ?? err}\n`);
    return null;
  }
}

async function signAndWrite(scope, agentDid, signingKey, core) {
  const bytes = Buffer.from(canonicalJson(core), 'utf-8');
  const integrity_hash = blake3Hex(bytes);
  const signature = await computeAuditSignature(signingKey, bytes);
  const record = { ...core, integrity_hash, signature };
  const path = memoryAuditPath(scope, agentDid);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  appendFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return record;
}

/**
 * Append a signed, hash-linked audit record to THIS AGENT's chain. The agent's
 * first record is the genesis (seq 0, prev_hash=null). After a normal append,
 * a checkpoint is stamped when the chain crosses a CHECKPOINT_INTERVAL boundary.
 * Best-effort caller wrapping recommended — a failed audit append should not
 * fail the underlying op, but it SHOULD be logged.
 */
export async function appendMemoryAudit({ scope = 'main', signingKey, agentDid = null, eventType, memoryId = null, metadata = {} }) {
  let prev = lastEntry(scope, agentDid);
  // ON-BREAK SELF-HEAL: never chain onto a corrupt tail. If the head record's
  // hash no longer matches its core (tampered/truncated/partial write), re-root
  // a NEW generation (genesis: new chain_id, seq 0, prev_hash null) instead of
  // extending a broken link — so a break flags + heals forward rather than
  // poisoning every future record. The console shows the old generation as
  // broken history and the new one verifies from its genesis.
  if (prev && !tailIntact(prev)) {
    process.stderr.write(`[lastid-agent] audit tail broken at seq ${prev.seq} — re-rooting a new chain generation\n`);
    metadata = { ...(metadata ?? {}), healed_from_break: true, broke_after_seq: Number(prev.seq) };
    prev = null;
  }
  const record = await signAndWrite(scope, agentDid, signingKey, recordCore(prev, { agentDid, eventType, memoryId, metadata }));
  // Checkpoint boundary: stamp a ChainCheckpoint right after the record that
  // crosses a multiple of the interval. Never recurse on checkpoints.
  if (eventType !== CHECKPOINT_EVENT) {
    const seq = Number(record.seq);
    if (seq > 0 && (seq + 1) % CHECKPOINT_INTERVAL === 0) {
      await maybeCheckpoint({ scope, signingKey, agentDid });
    }
  }
  return record;
}

/**
 * Append a ChainCheckpoint record anchoring the chain at its current head. The
 * checkpoint links like any record; its metadata carries the anchored seq +
 * head integrity_hash so a verifier (or a partial/drained view) can re-root
 * from it. The console renders checkpoints as segment dividers.
 */
export async function maybeCheckpoint({ scope = 'main', signingKey, agentDid = null } = {}) {
  const prev = lastEntry(scope, agentDid);
  if (!prev) return null; // nothing to checkpoint yet (no genesis)
  return signAndWrite(scope, agentDid, signingKey, recordCore(prev, {
    agentDid,
    eventType: CHECKPOINT_EVENT,
    memoryId: null,
    metadata: { anchored_seq: Number(prev.seq), anchored_hash: prev.integrity_hash },
  }));
}

/**
 * Verify THIS agent's chain: each record's integrity_hash matches blake3(core),
 * prev_hash links correctly (seq 0 ⇒ prev_hash null = genesis), and (when
 * publicKey given) the ES256 (P-256) signature verifies. Returns { intact, total,
 * firstFailure? }.
 */
export function verifyMemoryAudit(scope = 'main', agentDid = null, publicKey = null) {
  const all = readMemoryAudit(scope, agentDid);
  let prevHash = null;
  for (let i = 0; i < all.length; i++) {
    const r = all[i];
    const bytes = Buffer.from(canonicalJson(coreFromRecord(r)), 'utf-8');
    if (blake3Hex(bytes) !== r.integrity_hash) {
      return { intact: false, total: all.length, firstFailure: { seq: r.seq, kind: 'integrity_hash_mismatch' } };
    }
    if ((r.prev_hash ?? null) !== prevHash) {
      return { intact: false, total: all.length, firstFailure: { seq: r.seq, kind: 'hash_link_mismatch' } };
    }
    if (publicKey && r.signature) {
      const ok = ecVerify('sha256', bytes, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(r.signature, 'base64'));
      if (!ok) {
        return { intact: false, total: all.length, firstFailure: { seq: r.seq, kind: 'signature_invalid' } };
      }
    }
    prevHash = r.integrity_hash;
  }
  return { intact: true, total: all.length };
}

/** Public-key (for verify) derived from the agent signing KeyObject. */
export function publicKeyFor(signingKey) {
  try {
    return createPublicKey(signingKey);
  } catch {
    return null;
  }
}

/**
 * Self-check THIS agent's chain and HEAL a deep break. The append-time self-heal
 * only catches a broken TAIL; a break in the MIDDLE leaves an intact tail, so a
 * plain append keeps extending the broken generation. This verifies the whole
 * chain and, on ANY break, stamps a genesis-rooted ChainCheckpoint (new
 * chain_id, seq 0, prev_hash null) flagging the break — so the chain
 * "checkpoints and starts chaining again" from a clean root (the console shows
 * the broken generation as history + this reset as a red divider + new genesis).
 * The listener runs this RANDOMLY (not only on demand). Returns the report
 * (with healed:true when a reset was written). Best-effort; never throws.
 */
export async function auditSelfCheck({ scope = 'main', signingKey, agentDid = null, publicKey = null } = {}) {
  let report;
  try {
    report = verifyMemoryAudit(scope, agentDid, publicKey);
  } catch (err) {
    process.stderr.write(`[lastid-agent] audit self-check failed to read: ${err?.message ?? err}\n`);
    return { intact: true, total: 0 };
  }
  if (report.intact || report.total === 0) return report;
  process.stderr.write(
    `[lastid-agent] audit self-check: chain broken at seq ${report.firstFailure?.seq} ` +
      `(${report.firstFailure?.kind}) — checkpoint + re-genesis\n`,
  );
  try {
    await signAndWrite(scope, agentDid, signingKey, recordCore(null, {
      agentDid,
      eventType: CHECKPOINT_EVENT,
      memoryId: null,
      metadata: {
        chain_reset: true,
        broke_at_seq: report.firstFailure?.seq ?? null,
        failure_kind: report.firstFailure?.kind ?? null,
      },
    }));
  } catch (err) {
    process.stderr.write(`[lastid-agent] audit self-check heal failed: ${err?.message ?? err}\n`);
    return report;
  }
  return { ...report, healed: true };
}

/** Every agent DID slug that has a chain file in this scope (for shipping all
 *  agents' chains, since a scope can host more than one). Returns slugs. */
export function listChainSlugs(scope = 'main') {
  try {
    return readdirSync(auditDir(scope))
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => f.slice(0, -'.jsonl'.length));
  } catch {
    return [];
  }
}

// ── IdP shipping cursor (per agent: entries past `shipped` haven't reached the IdP) ──

function readShipCursor(scope, agentDid) {
  try {
    const n = JSON.parse(readFileSync(shipCursorPath(scope, agentDid), 'utf8'))?.shipped;
    return Number.isInteger(n) ? n : 0;
  } catch {
    return 0;
  }
}
function writeShipCursor(scope, agentDid, shipped) {
  const path = shipCursorPath(scope, agentDid);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify({ shipped }), { mode: 0o600 });
  renameSync(tmp, path);
}

/** This agent's records not yet shipped to the IdP (seq >= cursor). */
export function unshippedEntries(scope = 'main', agentDid = null) {
  const cursor = readShipCursor(scope, agentDid);
  return readMemoryAudit(scope, agentDid).filter((r) => Number(r.seq) >= cursor);
}

// Drain in SIZE-BOUNDED chunks. The IdP caps the request body (1mb); shipping a
// large backlog in one POST 413s and the cursor never advances. So ship oldest-
// first chunks well under the limit, advancing the cursor per chunk (offline-
// safe: a failed chunk leaves the cursor to retry).
const MAX_BATCH_BYTES = 512 * 1024;
const MAX_BATCH_COUNT = 200;
const MAX_BATCHES_PER_RUN = 100;

/**
 * Ship THIS agent's unshipped audit records to the IdP via the injected `post`
 * fn (async (records) => boolean), in size-bounded oldest-first CHUNKS. Advances
 * the cursor after each successful chunk; a failed chunk stops the run and
 * leaves the cursor so we retry. Best-effort + offline-safe. Returns the total
 * shipped across chunks.
 */
export async function shipUnshipped(
  scope,
  agentDid,
  post,
  { maxBatchBytes = MAX_BATCH_BYTES, maxBatchCount = MAX_BATCH_COUNT, maxBatches = MAX_BATCHES_PER_RUN } = {},
) {
  let shipped = 0;
  for (let i = 0; i < maxBatches; i += 1) {
    const pending = unshippedEntries(scope, agentDid).sort((a, b) => Number(a.seq) - Number(b.seq));
    if (pending.length === 0) break;
    const batch = [];
    let bytes = 2; // "[]"
    for (const r of pending) {
      const sz = JSON.stringify(r).length + 1;
      if (batch.length > 0 && (bytes + sz > maxBatchBytes || batch.length >= maxBatchCount)) break;
      batch.push(r);
      bytes += sz;
    }
    const ok = await Promise.resolve(post(batch)).catch(() => false);
    if (!ok) break;
    writeShipCursor(scope, agentDid, Math.max(...batch.map((r) => Number(r.seq))) + 1);
    shipped += batch.length;
    if (batch.length === pending.length) break;
  }
  return shipped;
}
