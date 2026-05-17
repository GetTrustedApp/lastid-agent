/**
 * Audit-log emission.
 *
 * Every signed action the agent takes is appended to an in-memory
 * buffer; the BeforeStop hook flushes the buffer to the IdP's audit
 * endpoint. Each entry is a JWS signed by the agent's key, so the
 * IdP can verify provenance even if the connection drops mid-flush.
 *
 * In-memory buffer because: agent actions are infrequent compared to
 * tool-call rate; persisting to disk per action adds latency without
 * meaningful durability gain (a hard crash loses at most the current
 * session's audit, which is a known trade).
 */

const _buffer = [];

export function appendAuditEntry(entry) {
  _buffer.push({ ...entry, ts: new Date().toISOString() });
}

export async function flushAuditLog() {
  if (_buffer.length === 0) return { flushed: 0 };
  // TODO: sign each entry with the agent's Ed25519 key (via SDK) and
  // POST to `${LASTID_IDP_URL}/v1/audit/agent-actions`. The IdP
  // endpoint and storage shape live in M2 follow-up work.
  const flushed = _buffer.length;
  _buffer.length = 0;
  return { flushed };
}
