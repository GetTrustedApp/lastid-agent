/**
 * Agent-side `/v1/ws` client (Node) — parity with the bot
 * subscriber's transport posture at
 * `lastid-idp/packages/credential-service/src/mls/bot-mls-subscriber.ts`.
 *
 * Holds a persistent WebSocket to the LastID IdP so the agent
 * receives MLS Welcomes, application messages, commits, proposals,
 * membership changes, committer reassignments, and dissolves
 * without polling. Authenticates with the agent's
 * `LastID.Agent.Base` VC carried as a DPoP-bound bearer; DPoP
 * proof signed by the agent's Ed25519 slot key (the same key that
 * backs `did:lastid:agent:<pub>`).
 *
 * Auth shape (matches the working REST path in mls-publish.js):
 *
 *   Authorization: Bearer <agent VC SD-JWT compact string>
 *   DPoP:          <fresh DPoP proof JWT, htu=https://idp/v1/ws, htm=GET>
 *
 * IMPORTANT — scheme is `Bearer`, NOT `DPoP`. On the IdP's vc-auth
 * middleware, a `DPoP`-scheme Authorization is parsed as a *resource
 * access token* (verifyResourceAccessToken → ML-DSA verify), which a
 * raw VC is not — that path fails with "Resource token validation
 * failed: ML-DSA signature verification failed". `Bearer <vc>` routes
 * to the SD-JWT VC path, which for `LastID.Agent.Base` verifies the
 * VC + requires this DPoP proof header as holder PoP (verifyAgentPopJwt,
 * Ed25519 cnf.jwk, htu/htm-bound). vc-auth accepts `LastID.Agent.Base`
 * on the WS upgrade via `allowAgentCredential: true`.
 *
 * Lifecycle / invariants:
 *
 *   - `start()` opens the socket and arms reconnect.
 *   - On `open`:
 *       - fire `handlers.onOpen()` (caller publishes its KeyPackage
 *         via REST then sits waiting).
 *       - send `group_chat.fetch_queue` (no group_id) so the IdP
 *         drains anything queued while we were offline. Without
 *         this, commits / messages that arrived during a reconnect
 *         window stay queued until the next per-event-type
 *         trigger, by which point our MLS epoch is behind.
 *       - start the 25s heartbeat. NLB / ECS idle-timeout is ~350s;
 *         we beat well below that. Mirrors HEARTBEAT_MS in
 *         bot-mls-subscriber.ts:128.
 *   - On every inbound JSON message:
 *       - parse, then chain onto an inbound Promise queue so
 *         handlers run in arrival order. Same bug as
 *         bot-mls-subscriber.ts:284-292 — without serialization,
 *         a welcome + application message back-to-back race and
 *         the decrypt loses to the welcome's group-join.
 *       - dispatch every event type through a single `onEvent`
 *         callback (the dispatcher decides what to do with each).
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
const HEARTBEAT_MS = 25_000;

/**
 * Event types the dispatcher cares about. Unknown event types are
 * still forwarded to `onEvent` so the dispatcher's defensive
 * routing can probe for embedded mls_* fields — but the *known*
 * set is logged at info so we can correlate WS-layer arrival with
 * dispatcher behaviour without grovelling through full event
 * bodies.
 */
const KNOWN_EVENT_TYPES = new Set([
  'group_chat.welcome',
  'group_chat.message',
  'group_chat.commit',
  'group_chat.proposal',
  'group_chat.membership_change',
  'group_chat.proposal_reassigned',
  'group_chat.proposal_ack_confirmed',
  'group_chat.dissolved',
]);

/**
 * @typedef {Object} WsClientOptions
 * @property {string} idpUrl - `https://human.lastid.co` (no trailing /v1/ws).
 * @property {string} agentDid - `did:lastid:agent:z…`.
 * @property {string} vcCompact - Agent VC SD-JWT compact string.
 * @property {import('node:crypto').KeyObject} signingKey - Ed25519 KeyObject.
 * @property {(evt: any) => void} [onOpen]
 * @property {(evt: any) => Promise<void> | void} onEvent
 *   Called for every inbound `group_chat.*` event in arrival order.
 *   Returning a Promise serializes the next event behind it (this
 *   client awaits the promise before consuming the next frame).
 * @property {(err: Error) => void} [onError]
 */

export class LastIdWsClient {
  #opts;
  #socket;
  /** @type {'idle' | 'connecting' | 'open' | 'reconnecting' | 'stopped'} */
  #state = 'idle';
  #attempt = 0;
  #reconnectTimer;
  #heartbeatTimer;
  /** Serializes inbound event handling (welcome → message → commit). */
  #inboundQueue = Promise.resolve();

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
    this.#stopHeartbeat();
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
   * Send an outbound event frame. The dispatcher uses this for
   * - per-group fetch_queue after a welcome (drain commits queued
   *   pre-join)
   * - broadcasting commits the agent authored after a committer
   *   reassignment.
   *
   * No-op when the socket isn't open. Frames sent while we're
   * mid-reconnect would be DPoP-bound to the old session anyway —
   * the dispatcher can re-emit on the next `open` if it cares.
   */
  send(event) {
    if (!this.#socket || this.#socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    try {
      this.#socket.send(JSON.stringify(event));
      return true;
    } catch (err) {
      process.stderr.write(`[lastid-agent] ws send failed: ${err.message}\n`);
      return false;
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
        // Bearer (NOT DPoP) — see the auth-shape note at the top of
        // this file. DPoP scheme ⇒ resource-token path ⇒ ML-DSA
        // failure for a raw VC. Bearer ⇒ SD-JWT path + the DPoP
        // header below as agent holder PoP.
        Authorization: `Bearer ${vcCompact}`,
        DPoP: dpopProof,
      },
    });
    this.#socket = ws;

    ws.on('open', () => {
      this.#state = 'open';
      this.#attempt = 0;
      // The caller's onOpen drives replay-on-connect (a per-group
      // `group_chat.fetch_queue` via the dispatcher). We do NOT send a
      // group_id-less fetch here — the IdP requires a group_id per
      // queue (handleFetchQueue warns + no-ops without one), so the old
      // payload-less fetch never drained anything. sender_did is
      // injected server-side from the authenticated connection.
      try {
        this.#opts.onOpen?.({ ws_url: wsUrl });
      } catch (err) {
        process.stderr.write(`[lastid-agent] ws onOpen handler threw: ${err.message}\n`);
      }
      this.#startHeartbeat();
    });

    ws.on('message', (data) => this.#enqueueInbound(data));

    ws.on('close', (code, reason) => {
      this.#stopHeartbeat();
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

  /**
   * Push an inbound frame onto the serialization queue. Each frame
   * waits for the prior one's handler to settle before its own
   * dispatch begins. Failures in one handler don't break the
   * chain — every link is wrapped so a thrown handler can't poison
   * subsequent frames.
   */
  #enqueueInbound(data) {
    this.#inboundQueue = this.#inboundQueue.then(() => this.#consumeInbound(data));
    // Swallow any rejection in the chain — they're already logged
    // inside #consumeInbound; we just don't want an unhandled
    // promise rejection if a handler throws synchronously.
    this.#inboundQueue.catch(() => {});
  }

  async #consumeInbound(data) {
    let parsed;
    try {
      parsed = JSON.parse(data.toString('utf-8'));
    } catch (err) {
      process.stderr.write(`[lastid-agent] ws: non-JSON frame, ignoring: ${err.message}\n`);
      return;
    }
    const type = typeof parsed?.type === 'string' ? parsed.type : '(missing)';
    // Opt-in frame trace: set LASTID_WS_TRACE=1 to log EVERY inbound frame
    // type (used to confirm doorbell events reach the agent). Off by default
    // so the listener log stays lean.
    if (process.env.LASTID_WS_TRACE === '1') {
      process.stderr.write(`[lastid-agent] ws RAW type=${type}\n`);
    }
    if (KNOWN_EVENT_TYPES.has(type)) {
      // Known type — info log so timing is correlatable with
      // dispatcher behaviour.
      process.stderr.write(`[lastid-agent] ws inbound ${type}\n`);
    }
    // Heartbeat ack and similar frames have no useful behaviour for
    // the dispatcher; drop them at the WS layer so the dispatch
    // queue stays lean.
    if (type === 'heartbeat' || type === 'pong' || type === 'connection.established') {
      return;
    }
    try {
      await this.#opts.onEvent?.(parsed);
    } catch (err) {
      process.stderr.write(
        `[lastid-agent] ws onEvent threw on ${type}: ${err?.message ?? err}\n`,
      );
    }
  }

  #startHeartbeat() {
    this.#stopHeartbeat();
    this.#heartbeatTimer = setInterval(() => {
      if (!this.#socket || this.#socket.readyState !== WebSocket.OPEN) return;
      // Native WS ping frame — NOT an app-level `{type:'heartbeat'}`
      // event. The IdP's router rejects non-`domain.action` event
      // types ("Invalid event type: heartbeat"), and it already pings
      // clients itself (server.ts) + tracks liveness via pong. A
      // client-side native ping just keeps NAT/proxy state warm from
      // our end; the server auto-pongs. The `ws` package exposes
      // `.ping()`; it's a no-op-safe protocol frame.
      try {
        this.#socket.ping();
      } catch {
        // socket race — next tick (or reconnect) handles it.
      }
    }, HEARTBEAT_MS);
    // Don't keep the event loop alive solely for the heartbeat —
    // the WS itself is the keep-alive anchor.
    if (typeof this.#heartbeatTimer.unref === 'function') {
      this.#heartbeatTimer.unref();
    }
  }

  #stopHeartbeat() {
    if (this.#heartbeatTimer) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = undefined;
    }
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
