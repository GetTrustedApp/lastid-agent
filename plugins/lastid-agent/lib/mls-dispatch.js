/**
 * Application-message dispatch — parity with the bot subscriber at
 * `lastid-idp/packages/credential-service/src/mls/bot-mls-subscriber.ts`.
 *
 * The WS client (`ws-client.js`) hands us raw inbound events; this
 * module owns:
 *
 *   - The full set of `group_chat.*` event handlers (welcome,
 *     message, commit, proposal, membership_change,
 *     proposal_reassigned, proposal_ack_confirmed, dissolved).
 *   - Defensive routing for unknown event types that happen to
 *     carry an `mls_*` payload — we'd rather pay one extra
 *     processInbound than silently lose an epoch-advancing commit
 *     to a future IdP event type the plugin doesn't know yet.
 *   - Persistence after every state-mutating op. Skipping a
 *     persist drops the bot's pending KeyPackage credentials,
 *     commits, or proposal store on the next restart.
 *   - Application-envelope inbox: decrypted `operator.*` messages
 *     land in `~/.lastid-agent/<scope>/operator-inbox.jsonl` for
 *     hooks (PreToolUse, UserPromptSubmit) to read.
 *
 * Inbound serialization is enforced by `ws-client.js` — each
 * inbound event chains onto the previous, so welcome + commit
 * arriving back-to-back are processed in order. Without that,
 * the bot hit a prod race at 2026-05-20T03:00 where a message's
 * decrypt raced the welcome's group-join. Same bug shape applies
 * here; same fix.
 *
 * Inner envelope shape (matches IdP's `MLS_APPLICATION_EVENT_TYPE`
 * vocabulary in `models/websocket/mls-application-event-types.ts`):
 *
 *   {
 *     "version": 1,
 *     "type": "operator.memory.write" | "operator.rule.publish" | …,
 *     "issued_at": <ISO-8601>,
 *     "payload": { … type-specific … }
 *   }
 *
 * Persistence:
 *   ~/.lastid-agent/<scope>/operator-inbox.jsonl
 *
 * One JSON object per line, appended. Shape:
 *
 *   {
 *     "received_at": <ISO-8601 from local clock>,
 *     "group_id_b64": <group_id from the wrapper>,
 *     "envelope": { … the decrypted inner JSON … }
 *   }
 *
 * Rotated when > 1 MB; the prior roll is kept as
 * `operator-inbox.jsonl.1`. MLS group state remains authoritative
 * on the IdP and is replayable, so we trade deep history for
 * predictable disk usage.
 */

import { Buffer } from 'node:buffer';
import { mkdir, appendFile, stat, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { recordGroup, listGroups } from './agent-groups.js';

/**
 * Known application-message types. Mirrors
 * `MLS_APPLICATION_EVENT_TYPE` in lastid-idp. Kept inline so the
 * plugin can dispatch without a shared package dependency; the IdP
 * is the canonical source of truth and rejects unknown types at
 * intake. Unknown types are still persisted to the inbox — we'd
 * rather keep the message than drop it because the plugin is one
 * rev behind the IdP's vocabulary.
 */
export const APP_MESSAGE_TYPES = Object.freeze({
  OPERATOR_MEMORY_WRITE: 'operator.memory.write',
  OPERATOR_MEMORY_FORGET: 'operator.memory.forget',
  OPERATOR_RULE_PUBLISH: 'operator.rule.publish',
  OPERATOR_RULE_REVOKE: 'operator.rule.revoke',
  OPERATOR_VAULT_SHARE: 'operator.vault.share',
  OPERATOR_USE_APPROVAL: 'operator.use_approval',
});

const INBOX_MAX_BYTES = 1024 * 1024;

function inboxPath(scope) {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'operator-inbox.jsonl');
}

/**
 * String fields we accept as the MLS wire payload on each event.
 * The IdP's canonical names are `mls_welcome` / `mls_message` /
 * `mls_commit` (see lastid-idp/src/api/websocket/handlers/group-chat-handler.ts).
 * We accept the legacy variants too in case an older IdP / test
 * fixture is in play; the handler doesn't care which key the
 * sender used.
 */
const FIELD_ALIASES = Object.freeze({
  welcome: ['mls_welcome', 'welcome_b64'],
  message: ['mls_message', 'mls_b64'],
  commit: ['mls_commit', 'commit_b64'],
  proposal: ['mls_proposal', 'proposal_b64'],
});

function pickPayloadString(payload, aliases) {
  if (!payload || typeof payload !== 'object') return null;
  for (const key of aliases) {
    const v = payload[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

/**
 * Best-effort message from any thrown value. The MLS wasm rejects with a
 * JsValue / string (NOT a JS Error), so `err.message` is `undefined` — which
 * is exactly why `processWelcome failed: undefined` / `processInbound failed:
 * undefined` told us nothing. Pull the most informative text we can: a real
 * Error's message+stack, a thrown string, else a JSON/String fallback. Never
 * throws (a circular value falls back to String()).
 */
export function errText(err) {
  if (err == null) return String(err);
  if (typeof err === 'string') return err;
  if (err instanceof Error) {
    return err.stack ? `${err.message}\n${err.stack}` : err.message || String(err);
  }
  if (typeof err.message === 'string' && err.message.length > 0) return err.message;
  try {
    const json = JSON.stringify(err);
    if (json && json !== '{}') return json;
  } catch {
    /* circular / non-serializable — fall through */
  }
  return String(err);
}

/**
 * @typedef {Object} DispatcherOptions
 * @property {import('./mls-client.js').MlsClient} mls
 * @property {string} [scope]   Defaults to 'main'.
 * @property {(line: string) => void} [log]   Defaults to stderr.
 * @property {(event: object) => void} [requestSend]
 *   Optional callback the dispatcher uses to ask the WS layer to
 *   send a frame on its behalf — currently used to request a
 *   per-group `group_chat.fetch_queue` right after a welcome so
 *   any commits the IdP queued before we joined drain before the
 *   next inbound message arrives. Without this the customer's
 *   next message at epoch N+1 trips WrongEpoch (the exact race the
 *   bot hit in prod — see bot-mls-subscriber.ts handleWelcome).
 */

export class MlsDispatcher {
  #mls;
  #scope;
  #log;
  #requestSend;
  #onOperatorMessage;

  /** @param {DispatcherOptions} opts */
  constructor({ mls, scope = 'main', log, requestSend, onOperatorMessage }) {
    this.#mls = mls;
    this.#scope = scope;
    this.#log = log ?? ((line) => process.stderr.write(`${line}\n`));
    this.#requestSend = requestSend;
    // Optional: called with the IdP group id when an inbound OPERATOR CHAT
    // message (operator.message.text) is decrypted, so the listener can drive
    // the received + typing presence. Only chat messages fire it — other
    // operator.* envelopes (memory write, rule publish) are not "a chat turn".
    this.#onOperatorMessage = typeof onOperatorMessage === 'function' ? onOperatorMessage : null;
  }

  /**
   * Entry point the WS layer calls for every inbound event. Inbound
   * serialization (welcome-then-message ordering) is enforced by
   * the caller via a Promise chain; this method only needs to be
   * async — concurrent calls remain a programmer error.
   */
  async onEvent(event) {
    const type = typeof event?.type === 'string' ? event.type : null;
    if (!type) {
      this.#log('[lastid-agent] inbound event missing type; ignoring');
      return;
    }
    try {
      switch (type) {
        case 'group_chat.welcome':
          await this.#handleWelcome(event);
          return;
        case 'group_chat.message':
          await this.#handleMessage(event);
          return;
        case 'group_chat.commit':
          await this.#handleCommit(event);
          return;
        case 'group_chat.proposal':
          await this.#handleProposal(event);
          return;
        case 'group_chat.membership_change':
          await this.#handleMembershipChange(event);
          return;
        case 'group_chat.proposal_reassigned':
          await this.#handleProposalReassigned(event);
          return;
        case 'group_chat.proposal_ack_confirmed':
          this.#handleProposalAckConfirmed(event);
          return;
        case 'group_chat.dissolved':
          await this.#handleDissolved(event);
          return;
        case 'group_chat.queue_batch':
          await this.#handleQueueBatch(event);
          return;
        case 'group_chat.ack':
          // Sender-side delivery confirmation. The agent doesn't render
          // outbound "Delivered" badges in real time (its outbox tracking
          // is internal), so for now this is a no-op classification —
          // routing it explicitly stops the default branch from passing
          // an ack through `#defensiveMlsRoute` (which sniffs payloads
          // for stray mls_* fields and logs a soft warning). Mirrors the
          // console handler at mls-dispatch.ts which just routes the
          // (group_id, message_id) pair to its onAck callback.
          return;
        default:
          await this.#defensiveMlsRoute(event);
      }
    } catch (err) {
      this.#log(`[lastid-agent] dispatch ${type} threw: ${err?.message ?? err}`);
    }
  }

  /**
   * Replay-on-connect. For every group we've recorded (groups.json),
   * ask the IdP for the messages it queued while this listener was
   * offline (`group_chat.fetch_queue` → `group_chat.queue_batch`,
   * handled below). The frame carries only the group_id — the IdP
   * injects the authenticated sender_did from the connection, so no
   * DID goes on the wire. Call from the WS `onOpen`.
   */
  async fetchQueues() {
    if (!this.#requestSend) return;
    let groups = [];
    try {
      groups = await listGroups({ scope: this.#scope });
    } catch (err) {
      this.#log(`[lastid-agent] fetchQueues listGroups failed: ${err?.message ?? err}`);
      return;
    }
    this.#log(
      `[lastid-agent] fetch_queue on connect for ${groups.length} group(s)`,
    );
    for (const g of groups) {
      if (!g || typeof g.idpGroupId !== 'string') continue;
      this.#requestSend({
        type: 'group_chat.fetch_queue',
        payload: { group_id: g.idpGroupId, limit: 200 },
      });
    }
  }

  /**
   * Process a `group_chat.queue_batch` — the offline messages the IdP
   * held for us. Each entry is a queued group_chat.* event; replay it
   * through `onEvent` as if it just arrived live (commits advance the
   * ratchet before messages encrypted at that epoch; application
   * messages land in the inbox), then ACK the group so the IdP clears
   * the queue and doesn't replay on the next connect.
   */
  async #handleQueueBatch(event) {
    const payload = event?.payload ?? {};
    const groupId = typeof payload.group_id === 'string' ? payload.group_id : null;
    const messages = Array.isArray(payload.messages) ? payload.messages : [];
    this.#log(
      `[lastid-agent] queue_batch group=${groupId ?? '?'} ` +
        `count=${messages.length} total=${payload.total_queued ?? '?'} ` +
        `has_more=${payload.has_more === true}`,
    );
    let handled = 0;
    for (const m of messages) {
      if (!m || typeof m !== 'object') continue;
      const mtype = typeof m.type === 'string' ? m.type : null;
      if (!mtype) continue;
      // Queued events may nest fields under `payload` or carry them
      // flat at top level — accept both.
      const inner = m.payload && typeof m.payload === 'object' ? m.payload : m;
      try {
        await this.onEvent({ type: mtype, payload: inner });
        handled += 1;
      } catch (err) {
        this.#log(
          `[lastid-agent] queue_batch replay of ${mtype} threw: ${err?.message ?? err}`,
        );
      }
    }
    if (groupId && this.#requestSend) {
      this.#requestSend({
        type: 'group_chat.ack_queue',
        payload: { group_id: groupId, all: true },
      });
      this.#log(`[lastid-agent] queue_batch acked group=${groupId} replayed=${handled}`);
    }
    // If the IdP capped the batch, immediately page the rest.
    if (payload.has_more === true && groupId && this.#requestSend) {
      this.#requestSend({
        type: 'group_chat.fetch_queue',
        payload: { group_id: groupId, limit: 200 },
      });
    }
  }

  // --- Welcome ------------------------------------------------------------

  async #handleWelcome(event) {
    const welcomeB64 = pickPayloadString(event?.payload, FIELD_ALIASES.welcome);
    if (!welcomeB64) {
      this.#log('[lastid-agent] welcome event missing mls_welcome; ignoring');
      return;
    }
    try {
      const info = await this.#mls.processWelcome(welcomeB64);
      await this.#mls.persist();
      this.#log(
        `[lastid-agent] joined MLS group ${info.group_id_b64} (members=${info.member_count})`,
      );

      // Record the IdP-UUID ↔ openmls-id link + the operator (peer)
      // DID so the outbound send path can resolve "reply to this
      // group" later. This is the only place we observe both ids
      // together — the welcome event carries the IdP UUID, the join
      // gave us the openmls id.
      const idpGroupId =
        typeof event?.payload?.group_id === 'string'
          ? event.payload.group_id
          : null;
      if (idpGroupId) {
        await recordGroup({
          scope: this.#scope,
          idpGroupId,
          groupIdB64: info.group_id_b64,
          operatorDid:
            typeof event?.payload?.inviter_did === 'string'
              ? event.payload.inviter_did
              : null,
        }).catch((err) =>
          this.#log(`[lastid-agent] recordGroup (welcome) failed: ${errText(err)}`),
        );
      }

      // Drain any commits the IdP queued for this specific group
      // BEFORE we joined via the deferred-welcome path. Without this,
      // a customer/operator self-update at epoch N+1 that arrived
      // while we were not yet a member sits in the per-group queue
      // forever, and the next live message at epoch N+1 trips
      // WrongEpoch. Mirrors bot-mls-subscriber.ts:765-779.
      const groupIdRaw = event?.payload?.group_id;
      if (typeof groupIdRaw === 'string' && groupIdRaw.length > 0 && this.#requestSend) {
        this.#requestSend({
          type: 'group_chat.fetch_queue',
          payload: { group_id: groupIdRaw },
        });
      }
    } catch (err) {
      this.#log(`[lastid-agent] processWelcome failed: ${errText(err)}`);
    }
  }

  // --- Application message ------------------------------------------------

  async #handleMessage(event) {
    // Skip our own messages echoed back. The IdP normally excludes the
    // sending connection from fan-out, but a second connection or a
    // queue replay can still hand us a message we authored — openmls
    // can't decrypt its own ciphertext (CannotDecryptOwnMessage, which
    // surfaced as the `processInbound failed: undefined` noise), and
    // attempting it could disturb the ratchet. Drop it cleanly.
    const senderDid =
      typeof event?.payload?.sender_did === 'string' ? event.payload.sender_did : null;
    if (
      senderDid &&
      typeof this.#mls.agentDid === 'string' &&
      senderDid === this.#mls.agentDid
    ) {
      return;
    }
    const mlsMessageB64 = pickPayloadString(event?.payload, FIELD_ALIASES.message);
    if (!mlsMessageB64) {
      this.#log('[lastid-agent] message event missing mls_message; ignoring');
      return;
    }

    let inbound;
    try {
      inbound = await this.#mls.processInbound(mlsMessageB64);
    } catch (err) {
      const msg = err?.message ?? String(err);
      // Same race-tolerant classification as #handleCommit / #handleProposal:
      // a peer message at an epoch we've already advanced past beyond
      // max_past_epochs surfaces as WrongEpoch or TooDistantInThePast.
      // GroupNotFound = dissolved. All three are expected MLS conditions
      // in a multi-device flow; drop silently.
      if (
        msg.includes('GroupNotFound') ||
        msg.includes('group_not_found') ||
        msg.includes('WrongEpoch') ||
        msg.includes('wrong_epoch') ||
        msg.includes('TooDistantInThePast') ||
        msg.includes('too_distant_in_the_past')
      ) {
        return;
      }
      this.#log(`[lastid-agent] processInbound failed: ${msg}`);
      return;
    }

    try {
      await this.#mls.persist();
    } catch (err) {
      this.#log(`[lastid-agent] mls persist after inbound failed: ${errText(err)}`);
    }

    // Non-application inbound (commit, proposal, external) only
    // mutated MLS group state — already captured by the persist
    // above. No envelope to write to the inbox.
    if (inbound?.kind !== 'application') return;

    // Wasm returns `plaintext_b64`. (The previous version of this
    // file read `application_b64`, which never matched — so all
    // operator messages were silently dropped before this fix.)
    const plaintextB64 = inbound?.plaintext_b64;
    if (typeof plaintextB64 !== 'string') return;

    let envelope;
    try {
      envelope = JSON.parse(Buffer.from(plaintextB64, 'base64').toString('utf-8'));
    } catch (err) {
      this.#log(`[lastid-agent] application payload not JSON: ${errText(err)}`);
      return;
    }

    const type = typeof envelope?.type === 'string' ? envelope.type : '(missing)';
    const groupId = event?.payload?.group_id_b64 ?? event?.payload?.group_id ?? '?';
    await this.#appendInbox({
      received_at: new Date().toISOString(),
      group_id_b64: groupId,
      envelope,
    });
    this.#log(`[lastid-agent] inbox: ${type} (group=${groupId})`);

    // Presence: a decrypted OPERATOR CHAT message opens a received + typing
    // window for the operator. Use the IdP group id (the UUID the typing event
    // fans out on), not the openmls group_id_b64. Only chat messages count —
    // a memory/rule envelope isn't the operator chatting. Best-effort.
    if (type === 'operator.message.text' && this.#onOperatorMessage) {
      const idpGroupId =
        typeof event?.payload?.group_id === 'string' ? event.payload.group_id : null;
      // For the read receipt: the operator message's id (which message was
      // read) and its sender_did (the operator — the receipt's recipient, i.e.
      // the original sender the IdP proxies the status back to). message_id
      // mirrors what the console set on send; correlation_id is the fallback.
      const messageId =
        (typeof event?.payload?.message_id === 'string' && event.payload.message_id) ||
        (typeof event?.payload?.correlation_id === 'string' && event.payload.correlation_id) ||
        null;
      const senderDid =
        typeof event?.payload?.sender_did === 'string' ? event.payload.sender_did : null;
      if (idpGroupId) {
        try {
          this.#onOperatorMessage(idpGroupId, { messageId, senderDid });
        } catch (err) {
          this.#log(`[lastid-agent] presence onOperatorMessage failed: ${errText(err)}`);
        }
      }
    }
  }

  // --- Commit -------------------------------------------------------------

  async #handleCommit(event) {
    const mlsCommitB64 = pickPayloadString(event?.payload, FIELD_ALIASES.commit);
    if (!mlsCommitB64) {
      this.#log('[lastid-agent] commit event missing mls_commit; ignoring');
      return;
    }
    try {
      await this.#mls.processInbound(mlsCommitB64);
      await this.#mls.persist();
    } catch (err) {
      const msg = err?.message ?? String(err);
      // A commit referencing a group we already forgot (dissolved
      // path, or membership removal that wiped us) surfaces as
      // GroupNotFound. Same posture the bot takes — silent drop.
      if (msg.includes('GroupNotFound') || msg.includes('group_not_found')) {
        return;
      }
      // WrongEpoch: a concurrent committer raced us and the IdP picked a
      // different winner. The losing commit shows up here with epoch
      // BEHIND local. Same status as native — drop silently and let the
      // IdP's `group_chat.proposal_reassigned` recovery path catch up.
      // Logging it as a hard failure spams what's expected MLS behavior
      // in any multi-device flow (mirror of the console-side fix).
      if (msg.includes('WrongEpoch') || msg.includes('wrong_epoch')) {
        return;
      }
      this.#log(`[lastid-agent] commit processing failed: ${msg}`);
    }
  }

  // --- Proposal -----------------------------------------------------------

  async #handleProposal(event) {
    const mlsProposalB64 = pickPayloadString(event?.payload, FIELD_ALIASES.proposal);
    if (!mlsProposalB64) {
      this.#log('[lastid-agent] proposal event missing mls_proposal; ignoring');
      return;
    }
    try {
      await this.#mls.processInbound(mlsProposalB64);
      await this.#mls.persist();
    } catch (err) {
      const msg = err?.message ?? String(err);
      // Same race-tolerant classification as #handleCommit: GroupNotFound
      // (we forgot it) and WrongEpoch (a commit already superseded this
      // proposal) are both expected in a multi-committer multi-device
      // setup. Drop silently.
      if (
        msg.includes('GroupNotFound') ||
        msg.includes('group_not_found') ||
        msg.includes('WrongEpoch') ||
        msg.includes('wrong_epoch')
      ) {
        return;
      }
      this.#log(`[lastid-agent] proposal processing failed: ${errText(err)}`);
    }
  }

  // --- Membership change --------------------------------------------------

  /**
   * The IdP emits this when a member is added or removed; the
   * underlying MLS commit that carried the change already arrived
   * separately as `group_chat.commit` and mutated our state. This
   * event is purely informational — log it so audits can correlate
   * the public membership view with the in-band commit, but don't
   * try to re-apply.
   */
  async #handleMembershipChange(event) {
    const payload = event?.payload ?? {};
    this.#log(
      `[lastid-agent] membership change group=${payload.group_id ?? '?'} ` +
        `kind=${payload.change_kind ?? '?'} member=${payload.member_did ?? '?'}`,
    );
  }

  // --- Proposal reassigned (we are / are not the new committer) -----------

  /**
   * IdP designates a new committer after the prior one went away
   * without committing. If the new committer is us, drain every
   * pending proposal openmls has queued for the group into a single
   * commit and broadcast it. Otherwise we are no longer authorized
   * to commit — discard our locally-prepared pending commit so it
   * doesn't sit in storage forever and shadow the real one.
   *
   * Mirrors bot-mls-subscriber.ts:1505-1565.
   */
  async #handleProposalReassigned(event) {
    const payload = event?.payload ?? {};
    const groupIdB64 = payload.group_id_b64 ?? payload.group_id;
    const newCommitterDid = payload.new_committer_did;
    const meIsCommitter =
      typeof newCommitterDid === 'string' &&
      typeof this.#mls.agentDid === 'string' &&
      newCommitterDid === this.#mls.agentDid;

    if (!groupIdB64) {
      this.#log('[lastid-agent] proposal_reassigned missing group_id; ignoring');
      return;
    }

    try {
      if (meIsCommitter) {
        const result = await this.#mls.commitPendingProposals(groupIdB64);
        await this.#mls.persist();
        this.#log(
          `[lastid-agent] committed pending proposals group=${groupIdB64} ` +
            `new_epoch=${result?.new_epoch ?? '?'}`,
        );
        if (this.#requestSend && typeof result?.commit_b64 === 'string') {
          this.#requestSend({
            type: 'group_chat.commit',
            payload: {
              group_id: groupIdB64,
              mls_commit: result.commit_b64,
              epoch: result.new_epoch,
            },
          });
        }
      } else {
        await this.#mls.rollbackPendingCommit(groupIdB64);
        await this.#mls.persist();
        this.#log(
          `[lastid-agent] rolled back pending commit group=${groupIdB64} ` +
            `new_committer=${newCommitterDid ?? '?'}`,
        );
      }
    } catch (err) {
      this.#log(`[lastid-agent] proposal_reassigned handler failed: ${errText(err)}`);
    }
  }

  // --- Proposal ack confirmed (UI-only) -----------------------------------

  #handleProposalAckConfirmed(event) {
    const payload = event?.payload ?? {};
    this.#log(
      `[lastid-agent] proposal_ack_confirmed group=${payload.group_id ?? '?'} ` +
        `proposal=${payload.proposal_id ?? '?'} status=${payload.status ?? '?'}`,
    );
  }

  // --- Group dissolved ----------------------------------------------------

  async #handleDissolved(event) {
    const payload = event?.payload ?? {};
    const groupIdB64 = payload.group_id_b64 ?? payload.group_id;
    if (!groupIdB64) {
      this.#log('[lastid-agent] dissolved event missing group_id; ignoring');
      return;
    }
    try {
      await this.#mls.forgetGroup(groupIdB64);
      await this.#mls.persist();
      this.#log(`[lastid-agent] forgot dissolved group ${groupIdB64}`);
    } catch (err) {
      this.#log(`[lastid-agent] forgetGroup failed: ${errText(err)}`);
    }
  }

  // --- Defensive routing for unknown events with mls_* bytes -------------

  /**
   * Defensive routing for unknown event types that carry an
   * `mls_*` byte field. The IdP can introduce new event vocabulary
   * (reactions, typing, etc.) and an older plugin would silently
   * drop them. If the event happens to embed a commit / proposal,
   * dropping the bytes drifts our local MLS state out of epoch
   * with the rest of the group. Sniff for a likely candidate field
   * and route it through processInbound; openmls's own classifier
   * decides what to do with the bytes. Pure-metadata events fall
   * through here and are no-ops.
   */
  async #defensiveMlsRoute(event) {
    const payload = event?.payload;
    if (!payload || typeof payload !== 'object') return;
    let mlsBytes = null;
    for (const [k, v] of Object.entries(payload)) {
      if (typeof v !== 'string' || v.length === 0) continue;
      if (k.startsWith('mls_') || k.endsWith('_b64')) {
        mlsBytes = v;
        break;
      }
    }
    if (!mlsBytes) return;
    try {
      // processInbound is async on PersistentBotMlsClient — missing
      // await was masking real failures into uncaught Promise rejections
      // that the catch block below couldn't see.
      await this.#mls.processInbound(mlsBytes);
      await this.#mls.persist();
      this.#log(
        `[lastid-agent] defensive mls route ok for unknown event type=${event?.type ?? '?'}`,
      );
    } catch (err) {
      // Don't treat this as fatal — many candidate fields will not
      // be MLS bytes at all. Logged at debug-equivalent only. Also
      // swallow the same race-tolerant set the dispatcher's other
      // branches drop silently — defensive routing should be silent
      // on those too.
      const msg = err?.message ?? String(err);
      if (
        msg.includes('WrongEpoch') ||
        msg.includes('wrong_epoch') ||
        msg.includes('TooDistantInThePast') ||
        msg.includes('too_distant_in_the_past')
      ) {
        return;
      }
      if (!msg.includes('GroupNotFound') && !msg.includes('group_not_found')) {
        this.#log(
          `[lastid-agent] defensive route did not parse as mls bytes ` +
            `(type=${event?.type ?? '?'}): ${msg}`,
        );
      }
    }
  }

  // --- Inbox append -------------------------------------------------------

  async #appendInbox(record) {
    const path = inboxPath(this.#scope);
    try {
      await mkdir(dirname(path), { recursive: true });
      await this.#rotateIfNeeded(path);
      await appendFile(path, `${JSON.stringify(record)}\n`, 'utf-8');
    } catch (err) {
      this.#log(`[lastid-agent] inbox append failed: ${errText(err)}`);
    }
  }

  async #rotateIfNeeded(path) {
    try {
      const s = await stat(path);
      if (s.size < INBOX_MAX_BYTES) return;
      await rename(path, `${path}.1`);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        this.#log(`[lastid-agent] inbox rotate failed: ${errText(err)}`);
      }
    }
  }
}

/** Path-only export so other modules (hooks, status, tests) can read the inbox. */
export function operatorInboxPath(scope) {
  return inboxPath(scope);
}
