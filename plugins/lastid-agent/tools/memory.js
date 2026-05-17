/**
 * lastid_memory_{set,get,list,delete} — agent-scoped persistent memory.
 *
 * Memory lives in the LastID vault keyed by the agent's identity. The
 * server sees only ciphertext: keys and values are encrypted under a
 * key derived from the agent's seed via HKDF (see
 * `lastid-vault::vault_key_for_agent`).
 *
 * Scopes:
 *   - 'global' — visible across all projects the agent runs in.
 *   - 'project:<hash>' — only visible in the project whose path hashes
 *     to <hash>. Default for `set` if no scope is supplied; matches the
 *     project the SessionStart hook captured.
 */

import { loadAgentVc } from '../lib/keychain.js';
import { initializeSdkBindings } from '../lib/sdk-bindings.js';
import { appendAuditEntry } from '../lib/audit-log.js';

export async function set({ key, value, scope = 'project', ttl }) {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  const id = await sdk.vaultMemorySet({ key, value, scope, ttl });
  appendAuditEntry({ action: 'memory.set', key, scope, id });
  return { id };
}

export async function get({ key, scope = 'project' }) {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  return sdk.vaultMemoryGet({ key, scope });
}

export async function list({ scope = 'project', prefix } = {}) {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  return sdk.vaultMemoryList({ scope, prefix });
}

async function _delete({ key, scope = 'project' }) {
  await requireAgent();
  const sdk = await initializeSdkBindings();
  const ok = await sdk.vaultMemoryDelete({ key, scope });
  appendAuditEntry({ action: 'memory.delete', key, scope });
  return { ok };
}

export { _delete as delete };

async function requireAgent() {
  const agent = await loadAgentVc();
  if (!agent) {
    throw new Error('agent is not provisioned — the SessionStart hook should have caught this');
  }
}
