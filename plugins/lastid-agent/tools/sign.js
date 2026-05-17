/**
 * lastid_sign — sign an arbitrary payload under the agent's identity
 * for a named scope. Returns the Ed25519 signature plus a thumbprint
 * of the agent's VC so verifiers can correlate the signature to the
 * specific capability grant in effect at signing time.
 *
 * The scope string is intentionally opaque to the SDK — the consumer
 * (a banking partner, a calendar service, the operator's audit log)
 * decides what scopes are meaningful. Common scopes: 'audit',
 * 'transfer', 'attest', 'ibaa.ledger'.
 */

import { loadAgentVc } from '../lib/keychain.js';
import { initializeSdkBindings } from '../lib/sdk-bindings.js';
import { appendAuditEntry } from '../lib/audit-log.js';

export async function sign({ payload, scope }) {
  const agent = await loadAgentVc();
  if (!agent) throw new Error('agent is not provisioned');
  if (!scope) throw new Error('scope is required (consumer-defined)');

  const sdk = await initializeSdkBindings();
  const { signature, vcThumbprint } = await sdk.signUnderScope({
    payload,
    scope,
    keypair: agent.keypair,
    vcCompact: agent.vcCompact,
  });
  appendAuditEntry({ action: 'sign', scope, vc_thumbprint: vcThumbprint });
  return { signature, vc_thumbprint: vcThumbprint };
}
