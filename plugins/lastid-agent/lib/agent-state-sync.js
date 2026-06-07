/**
 * Agent-state sync client.
 *
 * saas-migration.md §2.3/§6: the agent pulls its slot_seed-encrypted
 * rules + memories from the IdP agent-state store, VERIFIES the operator's
 * delegation_authority signature, decrypts locally, and applies them to
 * the OperatorStore. The same incremental `?since=<cursor>` GET serves
 * both real-time (WS doorbell) and bootstrap/catch-up.
 *
 * Auth mirrors ws-client.js: agent VC SD-JWT as a `Bearer` token + a
 * fresh `DPoP` proof per request (htu = origin+path).
 *
 * The IdP embeds the operator's delegation_authority public key
 * (`operator_delegation_jwk`) in the response so the agent can verify
 * each record's signature without a separate fetch (same precedent as
 * approval rows). RULES are fail-closed — an unverified rule is dropped.
 */
import { authedIdpFetch } from './mls-groups-api.js';
import { brokerAvailable, brokerDecryptContent } from './broker-ipc.js';
import { brokerIdpEnabled } from './broker-supervisor.js';
import { decryptContent } from './agent-content-crypto.js';
import { applyVaultRecords, refreshCliBindings } from './vault-cache.js';
import {
  decryptProjectContent,
  deriveProjectRoutingId,
  GLOBAL_SHARED_PROJECT_KEY,
} from './project-crypto.js';
import { verifyRecordSignature } from './agent-sig-verify.js';

export const RULES_PATH = '/v1/agent-state/rules';
export const MEMORIES_PATH = '/v1/agent-state/memories';
export const VAULT_PATH = '/v1/agent-state/vault';
export const AUDIT_POLICY_PATH = '/v1/agent-state/audit-policy';
export const SELF_PROTECTION_PATH = '/v1/agent-state/self-protection';
// Subagents — operator-authored peer agents this primary has authority to
// invoke. Sealed under THIS agent's slot_seed by the operator's console,
// fanned per-recipient, picked up here on `subagent.changed` doorbell.
// Applied to disk via applySubagentRecord (lib/subagents.js): writes the
// sub-scope's agent.md + updates the parent's subagents.json index, so
// `lastid_invoke_subagent` resolves immediately without any CLI step.
export const SUBAGENTS_PATH = '/v1/agent-state/subagents';

/**
 * Decode one wire record into the OperatorStore shape. Revoked /
 * forgotten records carry no ciphertext — they pass through so the store
 * removes them. Active records decrypt their JSON content. Returns the
 * store record plus the raw decrypted bytes (for signature/hash checks).
 */
export function decodeRecord(record, slotSeed, projectRootSeed = null, opts = {}) {
  // A shared record (wire target 'project') whose routing_id matches the
  // operator's GLOBAL routing is a global memory OR rule riding the project
  // Option-B rails — retarget it to 'global' so it injects/enforces ALWAYS
  // (operator-store global tier), not repo-gated like a real project record.
  // Kind-agnostic: a global rule and a global memory share this routing and are
  // told apart by `record.kind` downstream. The routing is derived from the
  // project_root_seed already sealed to this agent, so no new key + no
  // re-provision. DECRYPTION still keys off the WIRE target below (the record is
  // sealed under the project content key either way), and signature
  // verification runs on the wire record (target 'project') upstream — so this
  // only changes where the decoded record lands locally.
  let target = record.target ?? null;
  if (record.target === 'project' && Buffer.isBuffer(projectRootSeed) && typeof record.routing_id === 'string') {
    try {
      if (record.routing_id === deriveProjectRoutingId(projectRootSeed, GLOBAL_SHARED_PROJECT_KEY)) {
        target = 'global';
      }
    } catch {
      /* derivation failed — leave as project */
    }
  }
  const base = {
    id: record.id,
    kind: record.kind,
    target,
    version: Number(record.version) || 0,
    updated_at: record.updated_at ?? null,
    // The IdP's plaintext routing field. For rules it carries the tool name
    // the rule binds to; for subagent records it carries the slug, which the
    // listener needs to resolve a tombstone-driven revoke (a revoke carries
    // no ciphertext, so without this the slug is unrecoverable here).
    ...(typeof record.tool === 'string' && record.tool.length > 0 ? { tool: record.tool } : {}),
  };
  if (record.status && record.status !== 'active') {
    return { storeRecord: { ...base, status: record.status }, contentBytes: null };
  }
  // Project-tier records are encrypted under the project content key (derived
  // from the record's plaintext routing_id + the operator's project_root_seed),
  // NOT the agent's slot_seed. Without the project seed (older agent) we can't
  // read them — surface as undecryptable so the caller skips, not crashes.
  let contentBytes;
  if (Buffer.isBuffer(opts.decryptedContent)) {
    // FORK1 Phase 3: the SIGNED BROKER already decrypted this record (it holds
    // the slot/project seeds). We use those plaintext bytes directly — the seeds
    // never reach node. Verification downstream runs on these same bytes.
    contentBytes = opts.decryptedContent;
  } else if (record.target === 'project') {
    if (!Buffer.isBuffer(projectRootSeed) || typeof record.routing_id !== 'string') {
      throw new Error('project record but no project_root_seed/routing_id');
    }
    contentBytes = decryptProjectContent(projectRootSeed, record.routing_id, record.enc_b64);
  } else {
    contentBytes = decryptContent(slotSeed, record.enc_b64);
  }
  const content = JSON.parse(contentBytes.toString('utf8'));
  return { storeRecord: { ...base, status: 'active', content }, contentBytes };
}

async function fetchKind({ idpUrl, path, since, agentDid, vcCompact, signingKey, fetchImpl }) {
  // FORK1 (Phase 2): route through the shared, broker-aware authedIdpFetch. The
  // legacy path is byte-identical (Bearer + DPoP; htu strips the ?since query the
  // same way) and, when LASTID_BROKER_IDP is on + a broker is up, the signed
  // broker makes the call. Scope is ambient (getActiveScope). authedIdpFetch
  // returns the parsed body; we shape the per-kind result from it as before.
  const body = await authedIdpFetch({
    idpUrl,
    method: 'GET',
    path: `${path}?since=${encodeURIComponent(since)}`,
    agentDid,
    vcCompact,
    signingKey,
    fetchImpl,
  });
  return {
    records: Array.isArray(body?.records) ? body.records : [],
    cursor: typeof body?.cursor === 'number' ? body.cursor : since,
    operatorJwk: body?.operator_delegation_jwk ?? null,
  };
}

/**
 * Pull incremental agent-state, verify provenance, and apply it locally.
 *
 * @param {Object} deps
 * @param {string} deps.idpUrl
 * @param {string} deps.agentDid
 * @param {string} deps.vcCompact          - agent VC SD-JWT (bearer)
 * @param {import('node:crypto').KeyObject} deps.signingKey - agent Ed25519 (DPoP)
 * @param {Buffer} deps.slotSeed           - 32-byte content-decryption seed
 * @param {import('./operator-store.js').OperatorStore} deps.store
 * @param {Function} [deps.fetchImpl]      - injectable fetch (default global)
 * @param {{x_b64u,y_b64u}} [deps.operatorJwk] - override operator key (tests)
 * @param {Function} [deps.verifyRecord]   - override the provenance check (tests);
 *        (record, contentBytes) => true | { ok, reason }. Defaults to the built-in
 *        delegation_authority verification.
 * @param {(record, reason) => void} [deps.onReject] - observability hook.
 * @returns {Promise<{applied:number, cursor:number, fetched:number, rejected:number}>}
 */
export async function syncAgentState({
  idpUrl,
  agentDid,
  vcCompact,
  signingKey,
  slotSeed,
  projectRootSeed = null,
  store,
  memoryStore = null,
  scope = 'main',
  fetchImpl = globalThis.fetch,
  operatorJwk = null,
  verifyRecord = null,
  onReject = null,
  // Injectable so the FORK1 broker-decrypt path is unit-testable without a real
  // broker. Default to the module-level broker helpers.
  _brokerEnabled = brokerIdpEnabled,
  _brokerAvailable = brokerAvailable,
  _brokerDecryptContent = brokerDecryptContent,
}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('syncAgentState: no fetch implementation available');
  }
  // PER-KIND incremental cursors. Each kind fetches from ITS OWN high-water, so
  // a fast-moving kind (memories) can never advance a SHARED cursor past a
  // slower kind's pending record (a vault share) and strand it from future
  // `?since=` pulls — the cross-kind stranding bug this replaces. A legacy store
  // with no per-kind map returns 0 for every kind → one self-healing full
  // re-pull that recovers anything the old single cursor had skipped.
  const sinceRule = store.cursorFor('rule');
  const sinceMemory = store.cursorFor('memory');
  const sinceVault = store.cursorFor('vault');
  const sinceAudit = store.cursorFor('audit_policy');
  const sinceSelfProt = store.cursorFor('self_protection');
  const sinceSubagent = store.cursorFor('subagent');
  const [rules, memories, vault, auditPolicy, selfProtection, subagents] = await Promise.all([
    // Rules + memories also fail soft to empty — an agent provisioned WITHOUT
    // rule:read or memory:read (e.g. a narrow-scoped sub-agent like log-diver
    // with only vault:use) gets a 403 from those endpoints. An uncaught reject
    // here would explode the entire Promise.all and silently strand vault +
    // subagent + audit_policy pulls (Log Diver vault-share invisible bug,
    // 2026-05-28). Per-kind cursor stays put so the kind self-heals if the
    // operator later grants the cap.
    fetchKind({ idpUrl, path: RULES_PATH, since: sinceRule, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceRule, operatorJwk: null }),
    ),
    fetchKind({ idpUrl, path: MEMORIES_PATH, since: sinceMemory, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceMemory, operatorJwk: null }),
    ),
    // Vault shares. We store them SEALED (no decrypt here) — the listener
    // verifies + unfurls only at inject time. A failed vault fetch must not
    // break rules/memories, so fail soft to empty AND return the unchanged
    // vault cursor so it isn't advanced past records we never received.
    fetchKind({ idpUrl, path: VAULT_PATH, since: sinceVault, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceVault, operatorJwk: null }),
    ),
    // Audit policy (kind 'audit_policy') — the operator's signed control over
    // which classes the agent audits. Sealed per-agent + ES256-signed like a
    // global rule; decoded + verified (fail-closed) + applied below, then
    // honored at the source by audit-policy.js. Fail soft to empty.
    fetchKind({ idpUrl, path: AUDIT_POLICY_PATH, since: sinceAudit, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceAudit, operatorJwk: null }),
    ),
    // Self-protection opt-out (kind 'self_protection') — the operator's signed
    // toggle to turn OFF the agent-key guard. Verified fail-closed here; only
    // HONORED in the integrity-verified store (operator-store macKey), so a
    // forged on-disk record can't disable the guard. Fail soft to empty.
    fetchKind({ idpUrl, path: SELF_PROTECTION_PATH, since: sinceSelfProt, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceSelfProt, operatorJwk: null }),
    ),
    // Subagents (kind 'subagent') — operator-authored peer agents the operator
    // signed under THIS primary's slot_seed. Decoded + applied to disk below
    // via applySubagentRecord: writes the sub-scope's agent.md + updates the
    // parent's subagents.json so `lastid_invoke_subagent` resolves immediately
    // — no human install step. Fail soft to empty so a missing/old IdP can't
    // break the rest of the sync.
    fetchKind({ idpUrl, path: SUBAGENTS_PATH, since: sinceSubagent, agentDid, vcCompact, signingKey, fetchImpl }).catch(
      () => ({ records: [], cursor: sinceSubagent, operatorJwk: null }),
    ),
  ]);

  // Vault: persist the sealed blobs to the local vault cache (never decrypted
  // at rest). vault_list decodes on demand + strips the secret; the inject path
  // (listener) verifies the operator signature before use. Best-effort.
  try {
    applyVaultRecords(scope, vault.records);
    // Refresh the non-secret CLI binding index so the PreToolUse hook can
    // transparently rewrite a bound binary (`aws …` → `lastid-agent run …`)
    // without a per-call keychain read. Derived only from env-injection shares.
    refreshCliBindings(scope, slotSeed);
  } catch (err) {
    safely(onReject, { id: 'vault-cache', kind: 'vault' }, `vault cache: ${err?.message ?? err}`);
  }

  // Operator delegation key for signature verification. TRUST-ON-FIRST-USE: the
  // IdP supplies it embedded in the sync response, but we PIN it on the first
  // sync and verify against the pinned key thereafter — a later response that
  // hands over a DIFFERENT key (a compromised/forged IdP) is ignored, so it
  // can't swap the verification key and forge operator rules/memories. (A test
  // override via operatorJwk wins, for determinism.)
  const supplied = operatorJwk ?? rules.operatorJwk ?? memories.operatorJwk ?? auditPolicy.operatorJwk ?? selfProtection.operatorJwk ?? subagents.operatorJwk ?? null;
  const pinned = store.pinnedDelegationJwk;
  let opJwk = pinned;
  if (!pinned && supplied) {
    store.pinDelegationJwk(supplied);
    opJwk = supplied;
  } else if (pinned && supplied && (supplied.x_b64u !== pinned.x_b64u || supplied.y_b64u !== pinned.y_b64u)) {
    // Key-swap attempt — verify against the PINNED key, not the swapped one.
    safely(onReject, { id: 'delegation-key', kind: 'rule' },
      'operator delegation key changed since first sync — ignoring sync-supplied key, using the pinned one');
  }
  const verify =
    verifyRecord ??
    ((rec, contentBytes) => verifyRecordSignature(rec, contentBytes, opJwk, { agentDid }));

  const all = [...rules.records, ...memories.records, ...auditPolicy.records, ...selfProtection.records, ...subagents.records];
  // Global high-water = max across every kind. It is NOT used as anyone's
  // `?since=` anymore (that's per-kind now); it only marks "have we ever synced"
  // for the policy cold-start gate (OperatorStore.policyDecision) + the CLI
  // status line.
  let maxCursor = Math.max(
    store.cursor,
    rules.cursor ?? 0,
    memories.cursor ?? 0,
    vault.cursor ?? 0,
    auditPolicy.cursor ?? 0,
    selfProtection.cursor ?? 0,
    subagents.cursor ?? 0,
  );
  // FORK1 Phase 3: when the signed broker is up, decrypt record content THERE
  // (it holds the slot/project seeds) rather than in node. Checked ONCE per
  // sync, not per record. Content decryption keys off the slot/project seed
  // (not the identity key), so it works for any agent algo.
  const brokerDecryptOn = _brokerEnabled() && (await _brokerAvailable(scope));

  const decoded = [];
  let reconciled = 0;
  for (const rec of all) {
    if (typeof rec.cursor === 'number' && rec.cursor > maxCursor) maxCursor = rec.cursor;

    // Pre-decrypt active records via the broker when it's up. On any broker
    // failure, fall back to the local decode below (node still holds the seeds
    // pre-lockdown), so a transient broker hiccup never strands a record.
    let decryptedContent;
    if (brokerDecryptOn && rec.status === 'active' && typeof rec.enc_b64 === 'string') {
      try {
        decryptedContent = await _brokerDecryptContent({
          scope,
          envelopeB64: rec.enc_b64,
          routingId: rec.target === 'project' ? rec.routing_id : undefined,
        });
      } catch {
        decryptedContent = undefined;
      }
    }

    let storeRecord;
    let contentBytes = null;
    try {
      const d = decodeRecord(
        rec,
        slotSeed,
        projectRootSeed,
        Buffer.isBuffer(decryptedContent) ? { decryptedContent } : {},
      );
      storeRecord = d.storeRecord;
      contentBytes = d.contentBytes;
    } catch (err) {
      // Undecryptable (wrong key / corrupt) — skip, don't fail the batch.
      safely(onReject, rec, `decrypt: ${err?.message ?? err}`);
      continue;
    }

    // Provenance gate (rules fail-closed; memories verify-if-signed).
    let v;
    try {
      v = verify(rec, contentBytes);
    } catch (err) {
      v = { ok: false, reason: `verify: ${err?.message ?? err}` };
    }
    const ok = v === true || (v && v.ok === true);
    if (!ok) {
      safely(onReject, rec, (v && v.reason) || 'rejected');
      continue;
    }

    // Reconcile agent-authored memories (+ any memory revoke) into the local
    // memory store — the cross-session/host path. The memory store decides
    // (version-guarded; ignores operator-authored actives).
    if (memoryStore && rec.kind === 'memory') {
      try {
        if (memoryStore.applySync(storeRecord, rec.author)) reconciled += 1;
      } catch (err) {
        safely(onReject, rec, `reconcile: ${err?.message ?? err}`);
      }
    }

    // Subagents — write the sub-scope's agent.md to disk + add to the parent's
    // subagents.json index. This is the doorbell-driven install rail: the
    // operator authored a subagent in the console, sealed it under this
    // primary's slot_seed, posted it; we decrypted above; now we materialize
    // the scope dir so `lastid_invoke_subagent` resolves on the next call —
    // no human install step. A 'revoked' record removes the scope dir; an
    // 'active' record writes/overwrites it.
    if (rec.kind === 'subagent') {
      try {
        // Lazy import — keeps the sync loop free of the subagents FS code
        // when this kind isn't in the batch (most syncs).
        const { applySubagentRecord } = await import('./subagents.js');
        await applySubagentRecord({ scope, storeRecord });

        // For ACTIVE records, also mint the sub-agent's identity (DID +
        // VC). Idempotent: short-circuits if keychain already has a VC
        // for the sub-scope. Fail-soft — a provisioning error logs but
        // doesn't break the sync loop or other kinds. The disk scope is
        // already written above, so even if provisioning fails the
        // operator sees the helper listed (with an empty VC); a future
        // sync re-attempts.
        if (storeRecord.status === 'active' && storeRecord.content?.slug) {
          try {
            const { provisionSubagent } = await import('./subagent-provisioning.js');
            await provisionSubagent({
              idpUrl,
              parentSlotSeed: slotSeed,
              parentSigningKey: signingKey,
              parentDid: agentDid,
              parentVcCompact: vcCompact,
              parentScope: scope,
              parentProjectRootSeed: projectRootSeed,
              subagent: storeRecord.content,
              fetchImpl,
            });
          } catch (err) {
            safely(onReject, rec, `provision subagent: ${err?.message ?? err}`);
          }
        }
      } catch (err) {
        safely(onReject, rec, `apply subagent: ${err?.message ?? err}`);
      }
      // Don't add to decoded[] — subagents live on disk, not in operator-store.
      continue;
    }

    // The agent's OWN authored memory ACTIVES live in the memory store, not the
    // operator-store — skip them here to avoid double-injection. Revokes still
    // flow to the operator-store (it removes the id if it holds it; harmless
    // no-op otherwise). Operator-authored + promoted records apply normally.
    if (rec.kind === 'memory' && rec.author === 'agent' && storeRecord.status !== 'revoked') {
      continue;
    }

    decoded.push(storeRecord);
  }
  // Advance each kind's cursor INDEPENDENTLY to its own returned high-water.
  // A fail-soft kind returned cursor=<its own since>, so a failed/empty fetch
  // leaves that kind's cursor put (re-fetched next sync) and is never leapfrogged
  // by a faster kind — the fix for the cross-kind stranding bug. applyRecords
  // (below) persists these together with the global cursor in one save.
  store.setCursorFor('rule', rules.cursor);
  store.setCursorFor('memory', memories.cursor);
  store.setCursorFor('vault', vault.cursor);
  store.setCursorFor('audit_policy', auditPolicy.cursor);
  store.setCursorFor('self_protection', selfProtection.cursor);
  store.setCursorFor('subagent', subagents.cursor);

  const applied = store.applyRecords(decoded, maxCursor);
  return {
    applied,
    reconciled,
    cursor: store.cursor,
    fetched: all.length,
    rejected: all.length - decoded.length,
  };
}

function safely(fn, ...args) {
  if (typeof fn !== 'function') return;
  try {
    fn(...args);
  } catch {
    // observability hook must never break sync
  }
}

/**
 * Build a WS event handler that turns agent-state change "doorbell"
 * events into a (debounced) sync pull. The doorbell carries only a
 * cursor — no content — so all it does is trigger the same incremental
 * GET used for catch-up. Returns true if it handled the event.
 */
export function makeDoorbellHandler(triggerSync, { debounceMs = 250 } = {}) {
  const CHANGED = new Set(['rules.changed', 'memory.changed', 'vault.changed', 'subagent.changed', 'agent_state.changed']);
  let timer = null;
  return function onEvent(event) {
    const type = typeof event === 'string' ? event : event?.type ?? '';
    if (!CHANGED.has(type)) return false;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      Promise.resolve(triggerSync(event)).catch(() => {});
    }, debounceMs);
    if (typeof timer.unref === 'function') timer.unref();
    return true;
  };
}
