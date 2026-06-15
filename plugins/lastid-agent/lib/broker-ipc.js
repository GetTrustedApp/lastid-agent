/**
 * Plugin → signed-broker IPC bridge (FORK1, Phase 1 of the broker-credential-
 * custody plan: lastid-agent-plugin/docs/broker-credential-custody-plan.md).
 *
 * The lib port of scripts/broker-ipc-call.mjs (the E2E harness's CLI client):
 * one newline-delimited JSON request/response over the broker's unix-domain
 * socket. The broker — not node — holds the slot seed, mints the canonical DPoP
 * resource-token, and makes the IdP call; node only sends {method, path, body}
 * and reads back {status, body}. The credential never enters this process.
 *
 * `brokerIdpFetch` mirrors mls-groups-api.js `authedIdpFetch` (returns parsed
 * JSON, throws on non-2xx) so Phase 2 can swap call sites with no caller change.
 */
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

// Runtime-dir convention: ~/.lastid-agent/<scope>. Mirrors listener-daemon.js
// `dataDirFor` and is exactly where the signed broker writes its `broker.sock`
// + per-launch `broker.token` (--scope <scope>). Kept in lock-step with that
// convention deliberately (the broker, listener, and this client must agree).
export function brokerRuntimeDir(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main');
}
export function brokerSocketPath(scope = 'main') {
  return join(brokerRuntimeDir(scope), 'broker.sock');
}
export function brokerTokenPath(scope = 'main') {
  return join(brokerRuntimeDir(scope), 'broker.token');
}

/** Read the broker's per-launch IPC auth token (0600, written at startup). */
export async function readBrokerToken(scope = 'main') {
  const raw = await readFile(brokerTokenPath(scope), 'utf8');
  return raw.trim();
}

/**
 * Whether a broker is actually running for `scope` — both the socket AND the
 * per-launch token exist. This is the RUNTIME discriminator: a broker-native
 * agent's listener starts a broker (so this is true), while a legacy
 * seed-in-keychain agent never does (false → the call falls back to the node
 * path). The dispatch in authedIdpFetch checks it so the broker path is taken
 * only when a broker is genuinely up.
 */
export async function brokerAvailable(scope = 'main') {
  try {
    await stat(brokerSocketPath(scope));
    await stat(brokerTokenPath(scope));
    return true;
  } catch {
    return false;
  }
}

let _ipcCounter = 0;
function nextRequestId() {
  _ipcCounter += 1;
  return `plg-${process.pid}-${Date.now()}-${_ipcCounter}`;
}

/**
 * One NDJSON request/response over the broker socket. Resolves the parsed broker
 * Response object `{ id, ok, status?, body?, error? }`. REJECTS only on a
 * TRANSPORT failure (can't connect / no response / unparseable line) — an IdP
 * 4xx/5xx is a resolved `{ ok:true, status }`, NOT a rejection (matches the
 * src/protocol.rs contract + broker-ipc-call.mjs).
 *
 * `connect` is injectable (default net.createConnection) so tests drive it with
 * a real temp unix socket without a live broker.
 *
 * @param {object} a
 * @param {string} a.socketPath
 * @param {string} a.token                 - per-launch broker.token
 * @param {'health'|'idp_call'|'machine_pubkey'} a.kind
 * @param {string} [a.method]              - idp_call only
 * @param {string} [a.path]                - idp_call only
 * @param {unknown} [a.body]               - idp_call only
 * @param {typeof net.createConnection} [a.connect]
 * @param {number} [a.timeoutMs]
 * @returns {Promise<{id:string, ok:boolean, status?:number, body?:unknown, error?:{code:string,message:string}}>}
 */
export function brokerIpcCall({
  socketPath,
  token,
  kind,
  method,
  path,
  body,
  fields,
  connect = net.createConnection,
  timeoutMs = 20_000,
}) {
  return new Promise((resolve, reject) => {
    const req = { id: nextRequestId(), auth_token: token, kind };
    if (kind === 'idp_call') {
      req.method = method;
      req.path = path;
      if (body !== undefined) req.body = body;
    }
    // Extra op fields for non-idp_call ops (e.g. sign_agent_record → payload_b64).
    if (fields && typeof fields === 'object') Object.assign(req, fields);

    let sock;
    try {
      sock = connect(socketPath);
    } catch (err) {
      reject(new Error(`broker ipc: connect threw: ${err?.message ?? err}`));
      return;
    }

    let buf = '';
    let done = false;
    const fail = (msg) => {
      if (done) return;
      done = true;
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      reject(new Error(`broker ipc: ${msg}`));
    };

    if (typeof sock.setTimeout === 'function') {
      sock.setTimeout(timeoutMs, () => fail('timeout waiting for broker response'));
    }
    sock.on('error', (e) => fail(`socket error: ${e.message}`));
    sock.on('connect', () => {
      try {
        sock.write(`${JSON.stringify(req)}\n`);
      } catch (err) {
        fail(`write failed: ${err?.message ?? err}`);
      }
    });
    sock.on('data', (chunk) => {
      if (done) return;
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      done = true;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
        reject(new Error(`broker ipc: bad response json: ${err?.message ?? err}`));
        return;
      }
      try {
        sock.end();
      } catch {
        /* ignore */
      }
      resolve(parsed);
    });
    sock.on('end', () => fail('broker closed connection without a response'));
  });
}

/**
 * Liveness/capability probe. Resolves the broker's health body (e.g.
 * `{ ok:true, body:{ device_provisioned:true, … } }`). Throws on transport
 * failure. Used by the supervisor to confirm the broker is up before routing.
 */
export async function brokerHealth({ scope = 'main', socketPath, token, connect, timeoutMs } = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  return brokerIpcCall({ socketPath: sp, token: tok, kind: 'health', connect, timeoutMs });
}

/**
 * Drop-in for mls-groups-api.js `authedIdpFetch`, but the authenticated IdP call
 * is performed BY the signed broker (FORK1): the broker holds the slot seed and
 * mints the canonical DPoP resource-token, so no credential enters node. Accepts
 * the SAME arg shape as `authedIdpFetch` — `idpUrl`/`agentDid`/`vcCompact`/
 * `signingKey` are accepted but IGNORED (the broker owns the origin + auth) — and
 * adds `scope` to locate the running broker's socket + token.
 *
 * Returns the parsed JSON body (`{}` on empty); throws on a broker-layer error
 * OR a non-2xx HTTP status, with a message shaped like authedIdpFetch's
 * (`${method} ${path} failed: HTTP ${status} …`) so existing error handling is
 * unchanged.
 *
 * @param {object} a
 * @param {'GET'|'POST'|'PUT'|'DELETE'} a.method
 * @param {string} a.path                  - leading-slash path, e.g. /v1/groups
 * @param {unknown} [a.body]
 * @param {string} [a.scope]
 * @param {string} [a.socketPath]          - test override
 * @param {string} [a.token]               - test override
 * @param {typeof net.createConnection} [a.connect] - test override
 */
export async function brokerIdpFetch({
  method,
  path,
  body,
  scope = 'main',
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'idp_call',
    method,
    path,
    body,
    connect,
    timeoutMs,
  });

  if (resp.error) {
    // Broker-layer failure (unauthorized IPC token, device_not_provisioned,
    // SSRF-rejected path, upstream transport). Distinct from an IdP HTTP status.
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`${method} ${path} failed: broker ${code}: ${resp.error.message ?? ''}`);
  }

  const status = typeof resp.status === 'number' ? resp.status : 0;
  if (status < 200 || status >= 300) {
    const text =
      resp.body === undefined
        ? ''
        : typeof resp.body === 'string'
          ? resp.body
          : JSON.stringify(resp.body);
    const err = new Error(`${method} ${path} failed: HTTP ${status} ${text}`);
    err.status = status; // parity with authedIdpFetch so 404-branch callers work either path
    err.body = text; // raw body so authedIdpFetch's revocation classifier can read it
    throw err;
  }
  return resp.body ?? {};
}

/**
 * Sign an authored memory/rule record via the signed broker (FORK1 Phase 3).
 * The broker holds the agent's slot-seed-derived P-256 identity key and returns
 * the compact ES256 provenance JWS — BYTE-IDENTICAL to the JS
 * `agent-sig-verify.js::signAgentRecordJws` for the same claims, because node
 * controls the JSON canonicalization here (base64url(JSON.stringify(claims)) is
 * the signed payload, exactly as today) and the broker only adds the fixed
 * header + the deterministic ES256 signature.
 *
 * Broker is P-256-only, so this path is for P-256 (`zDn…`) agents; Ed25519
 * agents keep the local node signer.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {object} [a.claims]       - record claims (node JSON.stringifies them)
 * @param {string} [a.payloadB64]   - or a precomputed base64url(JSON) directly
 * @returns {Promise<string>} the compact JWS (header.payload.sig)
 */
export async function brokerSignAgentRecord({
  scope = 'main',
  claims,
  payloadB64,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const payload =
    payloadB64 ?? Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'sign_agent_record',
    fields: { payload_b64: payload },
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`sign_agent_record failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const jws = resp.body?.jws;
  if (typeof jws !== 'string' || jws.split('.').length !== 3) {
    throw new Error(`sign_agent_record: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return jws;
}

/**
 * Sign an AUDIT-CHAIN record core via the signed broker (MLS-custody). The broker
 * holds the agent identity key and returns the raw ES256 (SHA-256, r||s, standard
 * base64) signature over the canonical core bytes — byte-identical to node
 * `memory-audit.js`'s `ecSign(...).toString('base64')`, so the IdP
 * `agent-audit-verify.ts` accepts it. The broker validates the payload is a
 * well-formed audit-record core first (scoped oracle). A broker-native agent's
 * audit chain stays fully signed without the seed reaching node.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {Buffer|Uint8Array} a.coreBytes  - the canonical JSON audit-record core
 * @returns {Promise<string>} the standard-base64 signature (matches record.signature)
 */
export async function brokerSignAuditRecord({
  scope = 'main',
  coreBytes,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'sign_audit_record',
    fields: { core_b64: Buffer.from(coreBytes).toString('base64') },
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`sign_audit_record failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const sig = resp.body?.signature_b64;
  if (typeof sig !== 'string' || sig.length === 0) {
    throw new Error(`sign_audit_record: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return sig;
}

/**
 * Decrypt an operator-distributed rule/memory envelope via the signed broker
 * (FORK1 Phase 3). The broker holds the slot_seed (+ project_root_seed) and
 * returns the PLAINTEXT — byte-identical to JS `agent-content-crypto.js
 * decryptContent` / `project-crypto.js decryptProjectContent` (same SDK crypto),
 * but the seeds never reach node.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} a.envelopeB64    - standard base64 of the packed LIDE envelope
 * @param {string|null} [a.routingId] - the record's wire routing_id for project-tier
 *   content; absent → slot-seed (agent/global). The consumer holds routing_id, not
 *   the repo name (which is inside the ciphertext).
 * @returns {Promise<Buffer>} the decrypted plaintext bytes
 */
export async function brokerDecryptContent({
  scope = 'main',
  envelopeB64,
  routingId,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const fields = { envelope_b64: envelopeB64 };
  if (routingId != null) fields.routing_id = routingId;
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'decrypt_agent_content',
    fields,
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`decrypt_agent_content failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b64 = resp.body?.plaintext_b64;
  if (typeof b64 !== 'string') {
    throw new Error(`decrypt_agent_content: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return Buffer.from(b64, 'base64');
}

/**
 * Encrypt authored content via the signed broker (MLS-custody) — the inverse of
 * {@link brokerDecryptContent} and the last node authoring path that derived a
 * content key from the slot seed (`agent-content-crypto.js encryptContent`). The
 * broker holds the seed(s) and returns the packed LIDE envelope; a recipient (JS
 * decryptContent or the broker's own decrypt op) opens it under the same seed.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {Buffer|Uint8Array} a.plaintext  - the content bytes to seal
 * @param {string|null} [a.routingId]      - project tier routing id; absent → slot/global
 * @returns {Promise<Buffer>} the packed LIDE envelope bytes
 */
export async function brokerEncryptContent({
  scope = 'main',
  plaintext,
  routingId,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const fields = { plaintext_b64: Buffer.from(plaintext).toString('base64') };
  if (routingId != null) fields.routing_id = routingId;
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'encrypt_agent_content',
    fields,
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`encrypt_agent_content failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b64 = resp.body?.envelope_b64;
  if (typeof b64 !== 'string') {
    throw new Error(`encrypt_agent_content: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return Buffer.from(b64, 'base64');
}

/**
 * Derive a sub-agent's 32-byte seed via the signed broker (FORK1 Phase 3 op 4).
 * The PARENT slot seed stays in the broker; only the derived sub-seed (the new
 * sub-agent's own credential) comes back. Byte-identical to the SDK
 * `deriveSubAgentSeed` (same HKDF, KAT-pinned).
 *
 * @returns {Promise<Buffer>} the 32-byte sub-agent seed
 */
export async function brokerDeriveSubAgentSeed({
  scope = 'main',
  classSlug,
  index,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'derive_sub_agent_seed',
    fields: { class_slug: classSlug, index },
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`derive_sub_agent_seed failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b64 = resp.body?.sub_seed_b64;
  const seed = typeof b64 === 'string' ? Buffer.from(b64, 'base64') : null;
  if (!seed || seed.length !== 32) {
    throw new Error(`derive_sub_agent_seed: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return seed;
}

/**
 * Sign a sub-agent parent-authorization JWS via the broker (FORK1 Phase 3 op 4)
 * with the PARENT's identity key. Byte-identical to JS `signParentAuthorization`
 * for a P-256 parent (node owns the claims canonicalization). Broker is
 * P-256-only, so this path is for P-256 (`zDn…`) parents.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} [a.claimsJson]   - the pre-stringified parent-auth claims
 * @param {string} [a.payloadB64]   - or a precomputed base64url(claimsJson)
 * @returns {Promise<string>} the compact JWS
 */
export async function brokerSignParentAuthorization({
  scope = 'main',
  claimsJson,
  payloadB64,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const payload = payloadB64 ?? Buffer.from(claimsJson, 'utf8').toString('base64url');
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'sign_parent_authorization',
    fields: { payload_b64: payload },
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`sign_parent_authorization failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const jws = resp.body?.jws;
  if (typeof jws !== 'string' || jws.split('.').length !== 3) {
    throw new Error(`sign_parent_authorization: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return jws;
}

/**
 * Derive the agent's MLS state-blob wrap key via the signed broker (MLS-custody).
 * The broker holds the slot seed and returns the 32-byte AES-256-GCM key node
 * uses to seal/open its local MLS keystore — byte-identical to
 * `mls-state-store.js deriveWrapKey` (same HKDF-SHA256 salt+info). A broker-native
 * agent fetches this ONCE per listener session and caches it, so the raw seed
 * never reaches node.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @returns {Promise<Buffer>} the 32-byte wrap key
 */
export async function brokerDeriveMlsStateKey({
  scope = 'main',
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'derive_mls_state_key',
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`derive_mls_state_key failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b64 = resp.body?.key_b64;
  const key = typeof b64 === 'string' ? Buffer.from(b64, 'base64') : null;
  if (!key || key.length !== 32) {
    throw new Error(`derive_mls_state_key: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return key;
}

/**
 * Generic MLS-op IPC call through the signed broker (MLS-into-broker, unit B3).
 * The broker now SERVES the openmls primitives for a broker-native (P-256 zDn…)
 * agent — no MLS key material ever enters node. Each MLS op is a single
 * {kind, ...fields} request whose success body this helper RETURNS verbatim (the
 * broker replies `Response::http(200, body)` → brokerIpcCall RESOLVES; a
 * `Response::err` → brokerIpcCall RESOLVES a `{ok:false,error}` we re-throw, OR
 * a transport failure REJECTS and propagates as-is). The per-op shapes are owned
 * by the caller (lib/mls-broker-client.js), which is duck-typed to MlsClient.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} a.kind          - the broker MLS op kind, e.g. `mls_generate_key_package`
 * @param {object} [a.fields]      - op-specific request fields merged into the request
 * @param {string} [a.socketPath]  - test override
 * @param {string} [a.token]       - test override (skips token file read)
 * @param {typeof net.createConnection} [a.connect] - test override
 * @param {number} [a.timeoutMs]
 * @returns {Promise<object>} the broker success body
 */
export async function brokerMlsCall({
  scope = 'main',
  kind,
  fields,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  if (typeof kind !== 'string' || !kind.startsWith('mls_')) {
    throw new Error(`brokerMlsCall: invalid kind ${JSON.stringify(kind)}`);
  }
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind,
    fields: fields && typeof fields === 'object' ? fields : undefined,
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`${kind} failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  // The broker may legitimately return an empty body for void ops
  // (forget/rollback/bind) — normalize to `{}` so callers can read it freely.
  return resp.body ?? {};
}

/**
 * Derive the agent's operator-store MAC key via the signed broker (MLS-custody).
 * The broker holds the slot seed and returns the 32-byte HKDF key node uses to
 * integrity-MAC its at-rest operator-store (rules/memories) — byte-identical to
 * `operator-store.js deriveOperatorStateMacKey`. A broker-native agent fetches it
 * once per session so the raw seed never reaches node yet the MAC still verifies.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @returns {Promise<Buffer>} the 32-byte MAC key
 */
export async function brokerDeriveOperatorStoreMacKey({
  scope = 'main',
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'derive_operator_store_mac_key',
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`derive_operator_store_mac_key failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b64 = resp.body?.key_b64;
  const key = typeof b64 === 'string' ? Buffer.from(b64, 'base64') : null;
  if (!key || key.length !== 32) {
    throw new Error(`derive_operator_store_mac_key: unexpected broker response ${JSON.stringify(resp.body)}`);
  }
  return key;
}

/**
 * Begin provisioning a NEW agent THROUGH the signed broker (FORK1 Phase 4). The
 * broker generates the ephemeral ECDH envelope keypair + presents its machine SE
 * pubkey to `/agent-provision/initiate`; node only relays the operator-facing
 * `user_code` and the `provision_id` handle. The slot seed is BORN in the broker
 * — it never enters this process even at provisioning time.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} [a.runtimeName]
 * @param {string} [a.projectHint]
 * @param {string} [a.parentHumanDid]
 * @returns {Promise<{provisionId:string, userCode:string, expiresIn:number|null, verificationUri:string|null}>}
 */
export async function brokerProvisionInitiate({
  scope = 'main',
  runtimeName,
  projectHint,
  parentHumanDid,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const fields = {};
  if (runtimeName != null) fields.runtime_name = runtimeName;
  if (projectHint != null) fields.project_hint = projectHint;
  if (parentHumanDid != null) fields.parent_human_did = parentHumanDid;
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'provision_initiate',
    fields,
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`provision_initiate failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b = resp.body ?? {};
  if (typeof b.provision_id !== 'string' || typeof b.user_code !== 'string') {
    throw new Error(`provision_initiate: unexpected broker response ${JSON.stringify(b)}`);
  }
  return {
    provisionId: b.provision_id,
    userCode: b.user_code,
    expiresIn: typeof b.expires_in === 'number' ? b.expires_in : null,
    verificationUri: typeof b.verification_uri === 'string' ? b.verification_uri : null,
  };
}

/**
 * Poll a provisioning handle (FORK1 Phase 4). While the wallet hasn't decided,
 * returns `{status:'pending'}`. On approval the broker has already unsealed the
 * slot seed, claimed the VC, and PERSISTED everything to the keychain; it returns
 * `{status:'complete', agentDid, slotIndex, deviceId}` — after which the broker
 * exits so the supervisor relaunches it in agent mode. A wallet rejection throws.
 *
 * @param {object} a
 * @param {string} [a.scope]
 * @param {string} a.provisionId
 * @returns {Promise<{status:'pending'}|{status:'complete', agentDid:string, slotIndex:number|null, deviceId:string|null}>}
 */
export async function brokerProvisionPoll({
  scope = 'main',
  provisionId,
  socketPath,
  token,
  connect,
  timeoutMs,
} = {}) {
  const sp = socketPath ?? brokerSocketPath(scope);
  const tok = token ?? (await readBrokerToken(scope));
  const resp = await brokerIpcCall({
    socketPath: sp,
    token: tok,
    kind: 'provision_poll',
    fields: { provision_id: provisionId },
    connect,
    timeoutMs,
  });
  if (resp.error) {
    const code = resp.error.code ?? 'broker_error';
    throw new Error(`provision_poll failed: broker ${code}: ${resp.error.message ?? ''}`);
  }
  const b = resp.body ?? {};
  if (b.status === 'pending') return { status: 'pending' };
  if (b.status === 'complete' && typeof b.agent_did === 'string') {
    return {
      status: 'complete',
      agentDid: b.agent_did,
      slotIndex: typeof b.slot_index === 'number' ? b.slot_index : null,
      deviceId: typeof b.device_id === 'string' ? b.device_id : null,
    };
  }
  throw new Error(`provision_poll: unexpected broker response ${JSON.stringify(b)}`);
}

/**
 * Synchronous "is a broker up for this scope?" — both the socket AND the
 * per-launch token must exist. The async {@link brokerAvailable} is the
 * authority, but the WS client's `#openSocket` is synchronous (it mirrors
 * `new WebSocket()`), so it uses this cheap stat to decide PER CONNECT whether
 * to take the broker transport or fall back to the legacy direct WS. That
 * per-attempt check means a broker that dies mid-session degrades to the legacy
 * path on the next reconnect instead of looping on a dead socket.
 */
export function brokerSocketExistsSync(scope = 'main') {
  try {
    return existsSync(brokerSocketPath(scope)) && existsSync(brokerTokenPath(scope));
  } catch {
    return false;
  }
}

/**
 * A WebSocket-shaped transport whose channel is actually the signed broker's
 * `/v1/ws` connection (broker-credential-custody Phase 3 op 3). The broker owns
 * the wss upgrade (Bearer agent-VC + DPoP) and proxies frames over the local
 * IPC socket as NDJSON `ws_frame`/`ws_close` lines; this class presents the
 * SUBSET of the `ws` package's `WebSocket` interface that {@link LastIdWsClient}
 * uses, so it's a drop-in there with no change to that client's event logic:
 *
 *   - events: `open`, `message`(Buffer), `close`(code, reason), `error`(Error),
 *     and — crucially — `unexpected-response`(req, res) synthesized from a
 *     broker `ws_error` carrying the upgrade HTTP status + body, so the client's
 *     revocation classifier (401 + "credential has been revoked") still fires
 *     through the broker.
 *   - `readyState` using the same numeric constants as `ws`
 *     (0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED).
 *   - `send(data)` (text frames; the client only ever sends JSON strings),
 *     `close(code, reason)`, and a no-op `ping()` (node↔broker is a local unix
 *     socket; the broker↔IdP TCP is kept warm server-side).
 *
 * The agent VC + P-256 key never transit node for the channel. Broker is
 * P-256-only, so the caller gates this to P-256 (`zDn…`) agents.
 */
export class BrokerWsTransport extends EventEmitter {
  // ws-compatible readyState constants.
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  /** @type {0|1|2|3} */
  readyState = 0;
  #sock;
  #buf = '';
  #scope;
  #socketPath;
  #token;
  #connect;
  #closeEmitted = false;

  /**
   * @param {object} a
   * @param {string} [a.scope]
   * @param {string} [a.socketPath]   - test override
   * @param {string} [a.token]        - test override (skips token file read)
   * @param {typeof net.createConnection} [a.connect] - test override
   */
  constructor({ scope = 'main', socketPath, token, connect = net.createConnection } = {}) {
    super();
    this.#scope = scope;
    this.#socketPath = socketPath ?? brokerSocketPath(scope);
    this.#token = token;
    this.#connect = connect;
    // Async setup, but return immediately — mirrors `new WebSocket()` emitting
    // `open` on a later tick. Any setup failure routes to the same error→close
    // path the legacy socket uses, so the client's reconnect logic is unchanged.
    this.#begin().catch((err) => this.#fatal(err));
  }

  async #begin() {
    const token = this.#token ?? (await readBrokerToken(this.#scope));
    let sock;
    try {
      sock = this.#connect(this.#socketPath);
    } catch (err) {
      this.#fatal(new Error(`broker ws connect threw: ${err?.message ?? err}`));
      return;
    }
    this.#sock = sock;
    sock.on('error', (e) => this.#fatal(new Error(`broker ws socket error: ${e.message}`)));
    sock.on('connect', () => {
      const req = { id: nextRequestId(), auth_token: token, kind: 'ws_open' };
      try {
        sock.write(`${JSON.stringify(req)}\n`);
      } catch (err) {
        this.#fatal(new Error(`broker ws open write failed: ${err?.message ?? err}`));
      }
    });
    sock.on('data', (chunk) => this.#onData(chunk));
    sock.on('close', () => this.#finishClose(1006, 'broker ipc closed'));
  }

  #onData(chunk) {
    this.#buf += chunk.toString('utf8');
    let nl;
    // NDJSON: drain every complete line; a frame can arrive split or batched.
    while ((nl = this.#buf.indexOf('\n')) !== -1) {
      const line = this.#buf.slice(0, nl).trim();
      this.#buf = this.#buf.slice(nl + 1);
      if (line) this.#onLine(line);
    }
  }

  #onLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return; // ignore a garbled line rather than tear down the channel
    }
    switch (msg?.kind) {
      case 'ws_open_ok':
        this.readyState = 1;
        this.emit('open');
        return;
      case 'ws_frame': {
        // Broker relays both text + binary as base64; the client treats the
        // payload as bytes (it JSON.parses the utf-8), so binary-ness is moot.
        const data = Buffer.from(typeof msg.data === 'string' ? msg.data : '', 'base64');
        this.emit('message', data);
        return;
      }
      case 'ws_error': {
        // If the broker relayed an upgrade HTTP status + body, replay it as an
        // `unexpected-response` so LastIdWsClient's revocation classifier runs
        // exactly as on a direct connection. Then error→close drives reconnect
        // (the classifier flips the client to 'stopped' first if it's a revoke).
        if (typeof msg.http_status === 'number') {
          const res = makeFakeUpgradeResponse(
            msg.http_status,
            typeof msg.body === 'string' ? msg.body : '',
          );
          this.emit('unexpected-response', {}, res);
        }
        this.emit('error', new Error(typeof msg.message === 'string' ? msg.message : 'broker ws error'));
        this.#finishClose(1006, typeof msg.message === 'string' ? msg.message : '');
        return;
      }
      case 'ws_close':
        this.#finishClose(
          typeof msg.code === 'number' ? msg.code : 1000,
          typeof msg.reason === 'string' ? msg.reason : '',
        );
        return;
      default:
        return; // forward-compatible: ignore unknown control lines
    }
  }

  /** Send a text frame (the client only sends JSON strings). No-op unless open. */
  send(data) {
    if (this.readyState !== 1 || !this.#sock) return;
    const str = typeof data === 'string' ? data : Buffer.from(data).toString('utf8');
    const frame = {
      kind: 'ws_frame',
      data: Buffer.from(str, 'utf8').toString('base64'),
      binary: false,
    };
    try {
      this.#sock.write(`${JSON.stringify(frame)}\n`);
    } catch (err) {
      this.#fatal(new Error(`broker ws send failed: ${err?.message ?? err}`));
    }
  }

  /** Begin a clean close: tell the broker to close its WS, then end the IPC. */
  close(code = 1000, reason = '') {
    if (this.readyState === 3 || this.#closeEmitted) return;
    this.readyState = 2;
    try {
      this.#sock?.write(`${JSON.stringify({ kind: 'ws_close', code, reason })}\n`);
    } catch {
      /* ignore — we're tearing down anyway */
    }
    try {
      this.#sock?.end();
    } catch {
      /* ignore */
    }
    // The socket 'close' (or a broker ws_close line) drives #finishClose.
  }

  /** No-op: the keep-warm ping belongs on the broker↔IdP TCP, not the local IPC. */
  ping() {}

  #fatal(err) {
    try {
      this.emit('error', err);
    } catch {
      /* a thrown error handler must not mask the close */
    }
    this.#finishClose(1006, err?.message ?? 'broker ws fatal');
  }

  #finishClose(code, reason) {
    if (this.#closeEmitted) return;
    this.#closeEmitted = true;
    this.readyState = 3;
    try {
      this.#sock?.destroy();
    } catch {
      /* ignore */
    }
    this.#sock = undefined;
    this.emit('close', code, reason);
  }
}

/**
 * Build the minimal `http.IncomingMessage`-shaped object LastIdWsClient's
 * `unexpected-response` handler reads: a `statusCode` plus a readable that
 * emits the body once via `data` then `end`. We schedule the emits on a
 * microtask so listeners attached synchronously in the handler are wired first.
 */
function makeFakeUpgradeResponse(statusCode, body) {
  const res = new EventEmitter();
  res.statusCode = statusCode;
  queueMicrotask(() => {
    if (body) res.emit('data', Buffer.from(body, 'utf8'));
    res.emit('end');
  });
  return res;
}
