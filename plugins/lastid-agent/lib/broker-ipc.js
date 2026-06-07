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
 * per-launch token exist. The dispatch in authedIdpFetch checks this so that,
 * even with LASTID_BROKER_IDP on, a call falls back to the legacy node path
 * whenever no broker is up (no-flag-day safety).
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
