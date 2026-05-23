/**
 * Agent-side `/v1/ws` client (Node).
 *
 * Holds a persistent WebSocket to the LastID IdP so the agent
 * receives MLS Welcomes + group_chat.message events without
 * polling. Authenticates with the agent's `LastID.Agent.Base` VC
 * carried as a DPoP-bound bearer; DPoP proof signed by the agent's
 * Ed25519 slot key (the same key that backs `did:lastid:agent:<pub>`).
 *
 * Auth shape (mirrors what `lastid-api::build_v2_rest_headers`
 * produces for native tungstenite consumers — see the IdP-side
 * `WebSocket Authentication Handler` in
 * `src/api/websocket/handlers/auth.ts`):
 *
 *   Authorization: DPoP <agent VC SD-JWT compact string>
 *   DPoP:          <fresh DPoP proof JWT, htu=https://idp/v1/ws, htm=GET>
 *
 * vc-auth middleware was extended in task #193 to accept
 * `LastID.Agent.Base` (`allowAgentCredential: true` on the WS
 * upgrade handler), so this is the canonical native-client path —
 * no subprotocol smuggle, no `/v1/auth/resource-token` round-trip.
 *
 * Lifecycle.
 *
 *   - `start()` opens the socket and arms reconnect.
 *   - On `open`: fire `handlers.onOpen()`. The caller publishes
 *     its KeyPackage via REST then sits waiting for events.
 *   - On every inbound JSON message: parse, dispatch by event.type.
 *     `group_chat.welcome` and `group_chat.message` are the two
 *     agent-relevant types; anything else is logged and ignored.
 *   - On `close` / `error`: schedule reconnect with exponential
 *     backoff + jitter (up to 30s). Reconnect re-mints a fresh
 *     DPoP proof — the IdP tracks `jti` so the prior proof can't
 *     replay.
 *   - `stop()` closes the socket cleanly and disables reconnect.
 */

import { createRequire } from 'node:module';
import { mintDpopJwt } from './dpop.js';

const localRequire = createRequire(import.meta.url);
const { WebSocket } = localRequire('ws');

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 30_000;

/**
 * @typedef {Object} WsClientOptions
 * @property {string} idpUrl - `https://human.lastid.co` (no trailing /v1/ws).
 * @property {string} agentDid - `did:lastid:agent:z…`.
 * @property {string} vcCompact - Agent VC SD-JWT compact string.
 * @property {import('node:crypto').KeyObject} signingKey - Ed25519 KeyObject.
 * @property {(evt: any) => void} onOpen
 * @property {(evt: any) => void} onWelcome   group_chat.welcome
 * @property {(evt: any) => void} onMessage   group_chat.message
 * @property {(err: Error) => void} [onError]
 */

export class LastIdWsClient {
  #opts;
  #socket;
  /** @type {'idle' | 'connecting' | 'open' | 'reconnecting' | 'stopped'} */
  #state = 'idle';
  #attempt = 0;
  #reconnectTimer;

  /** @param {WsClientOptions} opts */
  constructor(opts) {
    this.#opts = opts;
  }

  start() {
    if (this.#state === 'open' || this.#state === 'connecting') return;
    this.#state = 'connecting';
    this.#openSocket();
  }

  stop() {
    this.#state = 'stopped';
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }
    if (this.#socket) {
      try {
        this.#socket.close(1000, 'agent shutting down');
      } catch {
        // ignore
      }
      this.#socket = undefined;
    }
  }

  /**
   * Mint headers + open the socket. Each call re-mints a fresh DPoP
   * proof — the IdP tracks `jti` against replay so a stale proof
   * (from a prior connect attempt that was abandoned mid-reconnect)
   * would 401 anyway.
   */
  #openSocket() {
    const { idpUrl, agentDid, vcCompact, signingKey } = this.#opts;
    const trimmed = idpUrl.replace(/\/$/, '');
    const wsUrl = trimmed.replace(/^https/i, 'wss').replace(/^http/i, 'ws') + '/v1/ws';
    const proofHtu = `${trimmed.replace(/^ws/i, 'http')}/v1/ws`;
    const dpopProof = mintDpopJwt({
      agentDid,
      httpMethod: 'GET',
      httpUri: proofHtu,
      signingKey,
    });

    const ws = new WebSocket(wsUrl, {
      headers: {
        Authorization: `DPoP ${vcCompact}`,
        DPoP: dpopProof,
      },
    });
    this.#socket = ws;

    ws.on('open', () => {
      this.#state = 'open';
      this.#attempt = 0;
      try {
        this.#opts.onOpen?.({ ws_url: wsUrl });
      } catch (err) {
        process.stderr.write(`[lastid-agent] ws onOpen handler threw: ${err.message}\n`);
      }
    });

    ws.on('message', (data) => {
      let parsed;
      try {
        parsed = JSON.parse(data.toString('utf-8'));
      } catch (err) {
        process.stderr.write(`[lastid-agent] ws: non-JSON frame, ignoring: ${err.message}\n`);
        return;
      }
      const type = typeof parsed?.type === 'string' ? parsed.type : '';
      try {
        if (type === 'group_chat.welcome') {
          this.#opts.onWelcome?.(parsed);
        } else if (type === 'group_chat.message') {
          this.#opts.onMessage?.(parsed);
        }
        // Other event types are ignored at the WS layer. Application-
        // message event types (operator.memory.write etc.) ride INSIDE
        // group_chat.message payloads, after MLS decryption — they're
        // dispatched by `mls-dispatch.js`, not here.
      } catch (err) {
        process.stderr.write(
          `[lastid-agent] ws inbound handler threw on ${type}: ${err.message}\n`,
        );
      }
    });

    ws.on('close', (code, reason) => {
      this.#socket = undefined;
      if (this.#state === 'stopped') return;
      process.stderr.write(
        `[lastid-agent] ws closed code=${code} reason=${reason?.toString() || '(none)'}\n`,
      );
      this.#scheduleReconnect();
    });

    ws.on('error', (err) => {
      try {
        this.#opts.onError?.(err);
      } catch {
        // ignore handler throw
      }
      // `close` will fire after `error`; reconnect logic lives there.
    });
  }

  #scheduleReconnect() {
    if (this.#state === 'stopped') return;
    this.#state = 'reconnecting';
    this.#attempt += 1;
    // Exponential backoff with full jitter, capped.
    const base = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** (this.#attempt - 1));
    const delay = Math.floor(Math.random() * base);
    process.stderr.write(
      `[lastid-agent] ws reconnect in ${delay}ms (attempt #${this.#attempt})\n`,
    );
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (this.#state === 'stopped') return;
      this.#state = 'connecting';
      this.#openSocket();
    }, delay);
  }
}
