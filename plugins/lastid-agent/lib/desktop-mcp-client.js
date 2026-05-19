/**
 * Desktop MCP client.
 *
 * Optional sidecar the plugin talks to when the operator runs the
 * LastID Desktop wallet on the same host. The wallet exposes a
 * localhost HTTP+JSON-RPC MCP at a random ephemeral port and writes
 * `~/Library/Application Support/LastID/agent-mcp.json` (or the
 * platform equivalent) so we can discover it without configuration.
 *
 * From the agent runtime's point of view, none of this exists. The
 * plugin MCP merges desktop-published tools into its own
 * `tools/list` and forwards `tools/call` for those tools
 * transparently. When the desktop isn't running, the plugin still
 * works — it just doesn't surface vault/CASB tools.
 *
 * Auth flow:
 *   1. Read discovery file → {port, server_fingerprint}.
 *   2. GET /health, confirm fingerprint matches.
 *   3. POST /session with our VC + a fresh DPoP. Get bearer token
 *      bound to (agent_did, capabilities, cnf-pubkey, expiry).
 *   4. POST /mcp with `initialize`, cache the discovered tool set.
 *   5. For each agent call → proxy /mcp tools/call. Fresh DPoP per
 *      call. Re-handshake on 401 or session expiry.
 */
import { readFile } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { mintDpopJwt } from './dpop.js';
import { buildUnsignedSessionFingerprint } from './session-fingerprint.js';
import { initializeSdkBindings } from './sdk-bindings.js';

const HEALTH_TIMEOUT_MS = 1500;
const SESSION_TIMEOUT_MS = 8000;
const MCP_TIMEOUT_MS = 30000;
const REHANDSHAKE_BEFORE_EXPIRY_SEC = 60;

/**
 * Bundle id of the LastID Desktop wallet on macOS. Used to read the
 * discovery file the (sandboxed) wallet drops into its container.
 * Stable identifier — bumped to match the wallet's CFBundleIdentifier.
 */
const MAC_BUNDLE_ID = 'co.lastid.lastidDesktop';

/**
 * Resolve the platform-appropriate discovery-file paths. Returns an
 * ordered list — the plugin tries each until one parses. On macOS
 * the sandboxed wallet writes into its own container path, which is
 * readable by any user-account process. We also keep the
 * non-sandboxed `~/Library/Application Support/LastID/` location as
 * a fallback for dev builds.
 */
function resolveDiscoveryPaths() {
  switch (platform()) {
    case 'darwin':
      return [
        join(
          homedir(),
          'Library',
          'Containers',
          MAC_BUNDLE_ID,
          'Data',
          'Library',
          'Application Support',
          MAC_BUNDLE_ID,
          'LastID',
          'agent-mcp.json',
        ),
        join(
          homedir(),
          'Library',
          'Application Support',
          'LastID',
          'agent-mcp.json',
        ),
      ];
    case 'linux':
      return [
        join(
          process.env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share'),
          'LastID',
          'agent-mcp.json',
        ),
      ];
    case 'win32':
      return [
        join(
          process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'),
          'LastID',
          'agent-mcp.json',
        ),
      ];
    default:
      return [join(homedir(), '.lastid', 'agent-mcp.json')];
  }
}

async function readDiscovery() {
  for (const path of resolveDiscoveryPaths()) {
    try {
      const text = await readFile(path, 'utf-8');
      const json = JSON.parse(text);
      if (
        typeof json.port !== 'number' ||
        typeof json.server_fingerprint !== 'string'
      ) {
        continue;
      }
      return {
        port: json.port,
        fingerprint: json.server_fingerprint,
        protocolVersion: json.protocol_version ?? null,
        pid: json.pid ?? null,
        sourcePath: path,
      };
    } catch {
      // Try the next candidate path.
    }
  }
  return null;
}

async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

/**
 * Client state. One instance per scope. Holds the active session +
 * cached remote tool descriptors. Re-handshakes lazily on demand.
 */
export class DesktopMcpClient {
  constructor({ agentDid, vcCompact, signingKey, signingSeed = null, cwd = process.cwd() }) {
    this.agentDid = agentDid;
    this.vcCompact = vcCompact;
    this.signingKey = signingKey;
    // Raw 32-byte Ed25519 seed for the wasm side. Optional — when
    // absent the SessionFingerprint step is skipped (desktop will
    // accept the session but scope-bound shares will deny on use).
    this.signingSeed = signingSeed;
    this.cwd = cwd;
    this._discovery = null;
    this._session = null;
    this._remoteTools = [];
    this._rpcId = 0;
  }

  baseUrl() {
    if (!this._discovery) return null;
    return `http://127.0.0.1:${this._discovery.port}`;
  }

  /**
   * Probe for a live desktop MCP and complete a session handshake.
   * Returns true on success, false (silently) on any failure — the
   * plugin treats absence as "desktop tools just unavailable now."
   */
  async connect() {
    const disc = await readDiscovery();
    if (!disc) return false;
    this._discovery = disc;
    try {
      const healthRes = await fetchWithTimeout(
        `${this.baseUrl()}/health`,
        { method: 'GET' },
        HEALTH_TIMEOUT_MS,
      );
      if (!healthRes.ok) return this._teardown();
      const health = await healthRes.json();
      if (health.server_fingerprint !== disc.fingerprint) {
        // Discovery file points at a port the wallet no longer owns
        // — likely the file is stale from a previous launch. Treat
        // as unavailable.
        return this._teardown();
      }
    } catch {
      return this._teardown();
    }
    return this._handshake();
  }

  async _handshake() {
    const url = `${this.baseUrl()}/session`;
    const dpop = mintDpopJwt({
      agentDid: this.agentDid,
      httpMethod: 'POST',
      httpUri: url,
      signingKey: this.signingKey,
    });
    const body = { vc: this.vcCompact };
    // SessionFingerprint is best-effort. When we can't sign one (no
    // raw seed available, or the wasm call throws on some platform),
    // we still hand-shake — the desktop accepts a missing fingerprint
    // and any scope-bound shares simply deny on use. That's the
    // correct fail-safe: it never opens access wider than the
    // operator authorized.
    if (this.signingSeed) {
      try {
        const unsigned = buildUnsignedSessionFingerprint({
          agentDid: this.agentDid,
          cwd: this.cwd,
        });
        const sdk = await initializeSdkBindings();
        const signed = sdk.signSessionFingerprint(this.signingSeed, unsigned);
        body.session_fingerprint = signed;
      } catch (err) {
        process.stderr.write(
          `[lastid-agent] session_fingerprint sign failed (continuing without): ${err.message}\n`,
        );
      }
    }
    try {
      const res = await fetchWithTimeout(
        url,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'DPoP': dpop,
          },
          body: JSON.stringify(body),
        },
        SESSION_TIMEOUT_MS,
      );
      if (!res.ok) return this._teardown();
      const body = await res.json();
      if (typeof body.session_token !== 'string') return this._teardown();
      this._session = {
        token: body.session_token,
        expiresAtEpochSec: body.expires_at_epoch_sec ?? 0,
        agentDid: body.agent_did ?? this.agentDid,
        mayDelegate: body.may_delegate === true,
      };
    } catch {
      return this._teardown();
    }
    // Discover remote tools.
    try {
      const initRes = await this._rpc('initialize', {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo: { name: 'lastid-agent-plugin', version: '0.1.0' },
      });
      if (initRes?.error) return this._teardown();
      const listRes = await this._rpc('tools/list', {});
      const tools = listRes?.result?.tools;
      if (!Array.isArray(tools)) return this._teardown();
      this._remoteTools = tools;
    } catch {
      return this._teardown();
    }
    return true;
  }

  _teardown() {
    this._session = null;
    this._remoteTools = [];
    return false;
  }

  /**
   * Descriptors of tools the desktop currently exposes. Empty when
   * disconnected. Renamed with the `desktop_` prefix is intentionally
   * NOT done — the agent sees the desktop tool names verbatim.
   */
  remoteTools() {
    return this._remoteTools;
  }

  /**
   * Whether `name` is a remote tool the desktop owns. Used by the
   * plugin's tools/call dispatcher.
   */
  ownsTool(name) {
    return this._remoteTools.some((t) => t.name === name);
  }

  /**
   * Proxy a tools/call to the desktop. Re-handshakes once on session
   * expiry; bubbles up any error to the caller.
   */
  async callTool(name, args) {
    if (!this._session) {
      const ok = await this.connect();
      if (!ok) {
        throw new Error('desktop MCP unavailable');
      }
    }
    if (this._sessionNearExpiry()) {
      const ok = await this._handshake();
      if (!ok) throw new Error('desktop MCP re-handshake failed');
    }
    const res = await this._rpc('tools/call', { name, arguments: args ?? {} });
    if (res?.error) {
      throw new Error(
        `desktop tool error ${res.error.code}: ${res.error.message}`,
      );
    }
    return res?.result;
  }

  _sessionNearExpiry() {
    if (!this._session) return true;
    const nowSec = Math.floor(Date.now() / 1000);
    return this._session.expiresAtEpochSec - nowSec < REHANDSHAKE_BEFORE_EXPIRY_SEC;
  }

  async _rpc(method, params) {
    const url = `${this.baseUrl()}/mcp`;
    const dpop = mintDpopJwt({
      agentDid: this.agentDid,
      httpMethod: 'POST',
      httpUri: url,
      signingKey: this.signingKey,
    });
    this._rpcId += 1;
    const body = {
      jsonrpc: '2.0',
      id: this._rpcId,
      method,
      params,
    };
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'authorization': `Bearer ${this._session?.token ?? ''}`,
          'DPoP': dpop,
        },
        body: JSON.stringify(body),
      },
      MCP_TIMEOUT_MS,
    );
    if (res.status === 401) {
      // Bearer or DPoP rejected — drop the cached session so the
      // next call re-handshakes. Surface a structured error so the
      // proxy can decide whether to retry.
      this._teardown();
      const text = await res.text().catch(() => '');
      throw new Error(`desktop MCP auth rejected: ${text}`);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`desktop MCP HTTP ${res.status}: ${text}`);
    }
    return res.json();
  }
}
