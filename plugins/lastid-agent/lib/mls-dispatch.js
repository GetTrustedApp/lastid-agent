/**
 * Application-message dispatch.
 *
 * The WS client (`ws-client.js`) hands us raw inbound events. For
 * `group_chat.welcome` we feed the wrapped MLS Welcome into the
 * MlsClient and persist. For `group_chat.message` we decrypt via MLS
 * and write the inner application envelope to a local inbox JSONL
 * file the agent owns. Hooks (PreToolUse, UserPromptSubmit) read
 * from the inbox when they want recent operator state; nothing else
 * is required to be running.
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
 * One JSON object per line, appended. The line shape is:
 *
 *   {
 *     "received_at": <ISO-8601 from local clock>,
 *     "group_id_b64": <group_id from the wrapper>,
 *     "envelope": { … the decrypted inner JSON … }
 *   }
 *
 * The file is rotated when it crosses 1 MB — the old file is renamed
 * to `operator-inbox.jsonl.1`; older rolls are not kept (we trade
 * deep history for predictable disk usage; MLS group state remains
 * authoritative on the IdP and is replayable). Rotation is best-
 * effort; a failure to rotate is logged and we keep appending.
 *
 * Why a local file rather than the desktop MCP:
 *
 *   The desktop wallet is an *optional* sidecar. Many operators will
 *   run the agent on a headless host (CI, server, container) where
 *   no desktop wallet is present. The agent has to be able to
 *   receive + retain operator state on its own. The desktop, when it
 *   IS running, has its own MLS connection to the same group — it
 *   does not need the plugin to forward.
 */

import { Buffer } from 'node:buffer';
import { mkdir, appendFile, stat, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

/**
 * Known application-message types. Mirrors
 * `MLS_APPLICATION_EVENT_TYPE` in lastid-idp. Kept inline so the
 * plugin can dispatch without a shared package dependency; the IdP
 * is the canonical source of truth and rejects unknown types at
 * intake. Unknown types are still persisted — we'd rather keep the
 * message than drop it because the plugin is one rev behind the
 * IdP's vocabulary.
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
 * @typedef {Object} DispatcherOptions
 * @property {import('./mls-client.js').MlsClient} mls
 * @property {string} [scope]   Defaults to 'main'.
 * @property {(line: string) => void} [log]   Defaults to stderr.
 */

export class MlsDispatcher {
  #mls;
  #scope;
  #log;

  /** @param {DispatcherOptions} opts */
  constructor({ mls, scope = 'main', log }) {
    this.#mls = mls;
    this.#scope = scope;
    this.#log = log ?? ((line) => process.stderr.write(`${line}\n`));
  }

  /**
   * Handle a `group_chat.welcome` event. The MLS Welcome is in
   * `event.payload.welcome_b64`. Adds this agent to the group.
   */
  async onWelcome(event) {
    const welcomeB64 = event?.payload?.welcome_b64;
    if (typeof welcomeB64 !== 'string') {
      this.#log('[lastid-agent] welcome event missing payload.welcome_b64; ignoring');
      return;
    }
    try {
      const info = this.#mls.processWelcome(welcomeB64);
      await this.#mls.persist();
      this.#log(
        `[lastid-agent] joined MLS group ${info.group_id_b64} (members=${info.member_count} epoch=${info.epoch})`,
      );
    } catch (err) {
      this.#log(`[lastid-agent] processWelcome failed: ${err.message}`);
    }
  }

  /**
   * Handle a `group_chat.message` event. The MLS application message
   * is in `event.payload.mls_b64`. We decrypt, then write the inner
   * envelope to the agent's local inbox.
   */
  async onMessage(event) {
    const mlsB64 = event?.payload?.mls_b64;
    if (typeof mlsB64 !== 'string') {
      this.#log('[lastid-agent] message event missing payload.mls_b64; ignoring');
      return;
    }

    let inbound;
    try {
      inbound = this.#mls.processInbound(mlsB64);
    } catch (err) {
      this.#log(`[lastid-agent] processInbound failed: ${err.message}`);
      return;
    }

    try {
      await this.#mls.persist();
    } catch (err) {
      this.#log(`[lastid-agent] mls persist after inbound failed: ${err.message}`);
    }

    // Commits / proposals come back without an application payload —
    // they only mutate MLS group state, which the persist() above
    // already captured.
    const appB64 = inbound?.application_b64;
    if (typeof appB64 !== 'string') return;

    let envelope;
    try {
      envelope = JSON.parse(Buffer.from(appB64, 'base64').toString('utf-8'));
    } catch (err) {
      this.#log(`[lastid-agent] application payload not JSON: ${err.message}`);
      return;
    }

    const type = typeof envelope?.type === 'string' ? envelope.type : '(missing)';
    const groupId = event?.payload?.group_id_b64 ?? '?';
    await this.#appendInbox({
      received_at: new Date().toISOString(),
      group_id_b64: groupId,
      envelope,
    });
    this.#log(`[lastid-agent] inbox: ${type} (group=${groupId})`);
  }

  async #appendInbox(record) {
    const path = inboxPath(this.#scope);
    try {
      await mkdir(dirname(path), { recursive: true });
      await this.#rotateIfNeeded(path);
      await appendFile(path, `${JSON.stringify(record)}\n`, 'utf-8');
    } catch (err) {
      this.#log(`[lastid-agent] inbox append failed: ${err.message}`);
    }
  }

  async #rotateIfNeeded(path) {
    try {
      const s = await stat(path);
      if (s.size < INBOX_MAX_BYTES) return;
      await rename(path, `${path}.1`);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        this.#log(`[lastid-agent] inbox rotate failed: ${err.message}`);
      }
    }
  }
}

/** Path-only export so other modules (hooks, status, tests) can read the inbox. */
export function operatorInboxPath(scope) {
  return inboxPath(scope);
}
