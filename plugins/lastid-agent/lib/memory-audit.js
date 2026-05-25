/**
 * Agent memory audit chain (local, signed) — replaces the desktop audit
 * chain for locally-served memory tools.
 *
 * Every memory CUD (write/draft/update/forget/promote) appends a record to an
 * append-only chain at ~/.lastid-agent/<scope>/memory-audit.jsonl. Each record
 * is sha256-linked to its predecessor (prev_hash) and Ed25519-signed with the
 * agent's stable key (deriveAgentEd25519Keypair) — tamper-evident + provenance-
 * attributed, the same guarantees the desktop chain gave.
 *
 * The records carry only NON-SENSITIVE metadata (event_type, memory_id, kind,
 * bedrock, fields_changed, hard_delete, reason) — never the memory claim — so
 * they can be shipped to the IdP (see shipUnshipped / agent-state /audit) for
 * the operator to view cross-device without leaking content.
 */
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { createHash, sign as edSign, verify as edVerify, createPublicKey } from 'node:crypto';

export function memoryAuditPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'memory-audit.jsonl');
}
function shipCursorPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'memory-audit-cursor.json');
}

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
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

export function readMemoryAudit(scope = 'main') {
  let raw;
  try {
    raw = readFileSync(memoryAuditPath(scope), 'utf8');
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

function lastEntry(scope) {
  const all = readMemoryAudit(scope);
  return all.length > 0 ? all[all.length - 1] : null;
}

/**
 * Append a signed, hash-linked audit record. `signingKey` is the agent's
 * Ed25519 private KeyObject (from deriveAgentEd25519Keypair). Returns the
 * record. Best-effort caller wrapping recommended — a failed audit append
 * should not fail the underlying memory op, but it SHOULD be logged.
 */
export function appendMemoryAudit({ scope = 'main', signingKey, agentDid = null, eventType, memoryId = null, metadata = {} }) {
  const prev = lastEntry(scope);
  const core = {
    seq: prev ? Number(prev.seq) + 1 : 0,
    timestamp: new Date().toISOString(),
    agent_did: agentDid,
    event_type: eventType,
    memory_id: memoryId,
    metadata: metadata ?? {},
    prev_hash: prev ? prev.integrity_hash : null,
  };
  const bytes = Buffer.from(canonicalJson(core), 'utf-8');
  const integrity_hash = sha256Hex(bytes);
  let signature = null;
  if (signingKey) {
    try {
      signature = edSign(null, bytes, signingKey).toString('base64');
    } catch (err) {
      process.stderr.write(`[lastid-agent] memory-audit sign failed: ${err?.message ?? err}\n`);
    }
  }
  const record = { ...core, integrity_hash, signature };
  const path = memoryAuditPath(scope);
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return record;
}

/**
 * Verify the chain: each record's integrity_hash matches sha256(canonical
 * core), prev_hash links correctly, and (when publicKey given) the Ed25519
 * signature verifies. Returns { intact, total, firstFailure? }.
 */
export function verifyMemoryAudit(scope = 'main', publicKey = null) {
  const all = readMemoryAudit(scope);
  let prevHash = null;
  for (let i = 0; i < all.length; i++) {
    const r = all[i];
    const core = {
      seq: r.seq,
      timestamp: r.timestamp,
      agent_did: r.agent_did ?? null,
      event_type: r.event_type,
      memory_id: r.memory_id ?? null,
      metadata: r.metadata ?? {},
      prev_hash: r.prev_hash ?? null,
    };
    const bytes = Buffer.from(canonicalJson(core), 'utf-8');
    if (sha256Hex(bytes) !== r.integrity_hash) {
      return { intact: false, total: all.length, firstFailure: { seq: r.seq, kind: 'integrity_hash_mismatch' } };
    }
    if ((r.prev_hash ?? null) !== prevHash) {
      return { intact: false, total: all.length, firstFailure: { seq: r.seq, kind: 'hash_link_mismatch' } };
    }
    if (publicKey && r.signature) {
      const ok = edVerify(null, bytes, publicKey, Buffer.from(r.signature, 'base64'));
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

// ── IdP shipping cursor (entries past `shipped` haven't reached the IdP) ──

function readShipCursor(scope) {
  try {
    const n = JSON.parse(readFileSync(shipCursorPath(scope), 'utf8'))?.shipped;
    return Number.isInteger(n) ? n : 0;
  } catch {
    return 0;
  }
}
function writeShipCursor(scope, shipped) {
  const path = shipCursorPath(scope);
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify({ shipped }), { mode: 0o600 });
  renameSync(tmp, path);
}

/** Records not yet shipped to the IdP (seq >= cursor). */
export function unshippedEntries(scope = 'main') {
  const cursor = readShipCursor(scope);
  return readMemoryAudit(scope).filter((r) => Number(r.seq) >= cursor);
}

/**
 * Ship unshipped audit records to the IdP via the injected `post` fn
 * (async (records) => boolean). Advances the cursor only on success.
 * Best-effort + offline-safe: a failed post leaves the cursor so we retry.
 * Returns the number shipped.
 */
export async function shipUnshipped(scope, post) {
  const pending = unshippedEntries(scope);
  if (pending.length === 0) return 0;
  const ok = await Promise.resolve(post(pending)).catch(() => false);
  if (ok) {
    const maxSeq = Math.max(...pending.map((r) => Number(r.seq)));
    writeShipCursor(scope, maxSeq + 1);
    return pending.length;
  }
  return 0;
}
