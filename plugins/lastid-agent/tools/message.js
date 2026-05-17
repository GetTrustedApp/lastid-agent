/**
 * lastid_message_{send,receive} — MLS-encrypted messaging to other
 * LastID identities (humans or agents). Wraps the SDK's MLS subsystem.
 */

import { loadAgentVc } from '../lib/keychain.js';
import { initializeSdkBindings } from '../lib/sdk-bindings.js';
import { appendAuditEntry } from '../lib/audit-log.js';

export async function send({ recipient_did, content, conversation_id }) {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  const result = await sdk.mlsSendMessage({
    recipientDid: recipient_did,
    content,
    conversationId: conversation_id,
  });
  appendAuditEntry({
    action: 'message.send',
    recipient: recipient_did,
    message_id: result.messageId,
  });
  return { message_id: result.messageId };
}

export async function receive() {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  return sdk.mlsReceiveMessages();
}

async function requireAgent() {
  const agent = await loadAgentVc();
  if (!agent) throw new Error('agent is not provisioned');
}
