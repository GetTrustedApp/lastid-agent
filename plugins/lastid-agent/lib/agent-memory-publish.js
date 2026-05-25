/**
 * Agent memory write-through to the IdP server store.
 *
 * Per saas-migration §slot_seed write-back: the agent encrypts a memory's
 * content under its OWN slot_seed and POSTs it to /v1/agent-state/memories
 * (agent VC + DPoP). The IdP stores it (author=agent, self-copy only); the
 * operator reads it by re-deriving that slot_seed (browser/desktop/mobile),
 * and the agent's other sessions sync it back. The local memory store is a
 * write-through cache, NOT the authoritative home — that's the IdP.
 *
 * `target='global'` is a DRAFT proposal: the agent can only write its own
 * copy (it lacks peer slot_seeds), so the operator promotes + fans out. The
 * memory's own draft/active state rides inside the encrypted content; the
 * agent-state record status is active (live) or revoked (tombstone).
 */
import { encryptContent } from './agent-content-crypto.js';
import { deriveAgentEd25519Keypair } from './agent-provisioning.js';
import { mintDpopJwt } from './dpop.js';

export const MEMORIES_PATH = '/v1/agent-state/memories';

/** The durable content we sync for a memory (everything the operator + other
 *  sessions need to reconstruct it; the embedding stays local + re-derived). */
export function memorySyncContent(m) {
  return {
    kind: m.kind,
    subject: m.subject,
    claim: m.claim,
    ...(m.summary ? { summary: m.summary } : {}),
    bedrock: m.bedrock === true,
    sensitivity: m.sensitivity,
    source_kind: m.source?.kind,
    confidence: m.confidence,
    decay: m.decay,
    status: m.status, // the MEMORY's state (active|drafted|forgotten)
    created_at: m.created_at,
    authored_by: 'agent',
  };
}

function authHeaders({ idpUrl, agentDid, vcCompact, signingKey }) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${vcCompact}`,
    DPoP: mintDpopJwt({ agentDid, httpMethod: 'POST', httpUri: `${idpUrl}${MEMORIES_PATH}`, signingKey }),
  };
}

/**
 * Write-through one memory to the IdP. `status` is the agent-state RECORD
 * status: 'active' (write/update) carries the encrypted content; 'revoked'
 * (forget) is a content-less tombstone. Returns true on a 2xx.
 */
export async function publishAgentMemory({ idpUrl, loaded, memory, status = 'active', version, fetchImpl = globalThis.fetch }) {
  if (typeof fetchImpl !== 'function' || !idpUrl || !loaded?.slotSeed) return false;
  const agentDid = loaded.agentDid;
  const target = memory.tier === 'global' ? 'global' : agentDid;
  const ver = Number.isInteger(version) ? version : Number(memory.version) || 1;

  let body;
  if (status === 'revoked') {
    body = { id: memory.id, target, status: 'revoked', version: ver, copies: [{ agent_did: agentDid }] };
  } else {
    const enc_b64 = encryptContent(
      loaded.slotSeed,
      Buffer.from(JSON.stringify(memorySyncContent(memory)), 'utf8'),
    ).toString('base64');
    body = { id: memory.id, target, status: 'active', version: ver, copies: [{ agent_did: agentDid, enc_b64 }] };
  }

  let signingKey;
  try {
    ({ signingKey } = deriveAgentEd25519Keypair(loaded.slotSeed));
  } catch {
    return false;
  }
  let res;
  try {
    res = await fetchImpl(`${idpUrl}${MEMORIES_PATH}`, {
      method: 'POST',
      headers: authHeaders({ idpUrl, agentDid, vcCompact: loaded.vcCompact, signingKey }),
      body: JSON.stringify(body),
      // Don't let a slow/down IdP hang the memory tool call.
      ...(typeof AbortSignal?.timeout === 'function' ? { signal: AbortSignal.timeout(5000) } : {}),
    });
  } catch {
    return false; // offline/timeout → caller marks the memory unsynced for retry
  }
  return res?.ok === true || (typeof res?.status === 'number' && res.status >= 200 && res.status < 300);
}
