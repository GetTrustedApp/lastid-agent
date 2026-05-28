/**
 * OS-keychain adapter.
 *
 * Persists the agent's identity bundle to the host's secure store:
 *   - macOS: Keychain (`security` CLI)
 *   - Linux: Secret Service (`secret-tool`)
 *   - Windows: DPAPI / Credential Manager (via PowerShell)
 *
 * Keys used (per scope):
 *   lastid.co/agent-slot-seed:<scope>  — 32-byte BIP85 slot seed (base64url)
 *   lastid.co/agent-slot-index:<scope> — decimal slot index (string)
 *   lastid.co/agent-did:<scope>        — `did:lastid:agent:z…`
 *   lastid.co/agent-vc:<scope>         — compact SD-JWT VC string
 *   lastid.co/sub-agent-slot-seed:<class>
 *   lastid.co/sub-agent-vc:<class>
 *
 * The slot_seed is the recoverable root for this agent's identity:
 * `AgentKeypair::from_seed(slot_seed)` deterministically reproduces the
 * Ed25519 signing key. The human's mnemonic can re-derive the same slot
 * seed via `derive_agent_slot_seed(ai_agent_seed, slot_index)` on a
 * fresh host, so even a full keychain wipe is recoverable.
 *
 * `<scope>` is "main" for the top-level agent. Each sub-agent class
 * gets its own bundle so it can be revoked / re-provisioned
 * independently.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SERVICE_SLOT_SEED = 'lastid.co/agent-slot-seed';
// Operator's project-memory root seed (base64url, 32 bytes). Shared across all
// the operator's agents; lets this agent read/write project-tier memories.
// Optional — absent for agents provisioned before project memories existed.
const SERVICE_PROJECT_ROOT_SEED = 'lastid.co/agent-project-root-seed';
const SERVICE_SLOT_INDEX = 'lastid.co/agent-slot-index';
const SERVICE_AGENT_DID = 'lastid.co/agent-did';
const SERVICE_VC = 'lastid.co/agent-vc';
const SERVICE_IDP_URL = 'lastid.co/agent-idp-url';
const SERVICE_SUB_SLOT_SEED = 'lastid.co/sub-agent-slot-seed';
const SERVICE_SUB_VC = 'lastid.co/sub-agent-vc';

/**
 * Load the top-level agent's identity bundle from keychain. Returns
 * null if any required piece is missing.
 */
export async function loadAgentVc(scope = 'main') {
  const seedB64 = await readSecret(`${SERVICE_SLOT_SEED}:${scope}`);
  const vcCompact = await readSecret(`${SERVICE_VC}:${scope}`);
  if (!seedB64 || !vcCompact) return null;
  const slotIndexStr = await readSecret(`${SERVICE_SLOT_INDEX}:${scope}`);
  const agentDid = await readSecret(`${SERVICE_AGENT_DID}:${scope}`);
  const idpUrl = await readSecret(`${SERVICE_IDP_URL}:${scope}`);
  const projectRootSeedB64 = await readSecret(`${SERVICE_PROJECT_ROOT_SEED}:${scope}`);
  return {
    slotSeed: Buffer.from(seedB64, 'base64url'),
    // Optional — null for agents provisioned before project memories existed
    // (they get global+agent memories only until re-provisioned).
    projectRootSeed: projectRootSeedB64
      ? Buffer.from(projectRootSeedB64, 'base64url')
      : null,
    slotIndex: slotIndexStr ? Number.parseInt(slotIndexStr, 10) : null,
    agentDid: agentDid ?? null,
    vcCompact,
    // Persisted IdP base URL for the env this agent was provisioned
    // against. Falls back to null when the entry is absent (older
    // installs that pre-date IdP persistence — those defer to the
    // ambient DEFAULT_IDP / LASTID_IDP_URL resolution path).
    idpUrl: idpUrl ?? null,
  };
}

/**
 * Persist a freshly-provisioned agent. `provisioned` is the shape
 * returned by `provisionAgent()` in agent-provisioning.js.
 */
export async function persistAgentVc(provisioned, scope = 'main') {
  const seedB64 = Buffer.from(provisioned.slotSeed).toString('base64url');
  await writeSecret(`${SERVICE_SLOT_SEED}:${scope}`, seedB64);
  // Persist the operator's project-memory root seed when the wallet delivered
  // one. Optional — older wallets omit it; the agent then has no project tier.
  if (provisioned.projectRootSeed) {
    await writeSecret(
      `${SERVICE_PROJECT_ROOT_SEED}:${scope}`,
      Buffer.from(provisioned.projectRootSeed).toString('base64url'),
    );
  }
  await writeSecret(
    `${SERVICE_SLOT_INDEX}:${scope}`,
    String(provisioned.slotIndex),
  );
  await writeSecret(`${SERVICE_AGENT_DID}:${scope}`, provisioned.agentDid);
  await writeSecret(`${SERVICE_VC}:${scope}`, provisioned.vcCompact);
  // Persist the IdP we bound this agent to so subsequent sessions
  // route to the same environment automatically — no need to keep
  // re-passing --idp / LASTID_IDP_URL. Optional: legacy provisioning
  // paths may not set this; loadAgentVc returns null in that case
  // and callers fall back to DEFAULT_IDP / env.
  if (provisioned.idpUrl) {
    await writeSecret(`${SERVICE_IDP_URL}:${scope}`, provisioned.idpUrl);
  }
}

/**
 * Persist (or update) the operator's project_root_seed for a scope.
 * Used by the sub-agent provisioning flow to backfill the seed into
 * a sub-scope's keychain so its listener can decrypt global-shared
 * rules + memories. Pure write helper — no side effects beyond the
 * single keychain entry.
 *
 * `projectRootSeedB64` is the operator's seed, base64url-encoded.
 */
export async function persistProjectRootSeed(scope, projectRootSeedB64) {
  if (typeof projectRootSeedB64 !== 'string' || projectRootSeedB64.length === 0) return;
  await writeSecret(`${SERVICE_PROJECT_ROOT_SEED}:${scope}`, projectRootSeedB64);
}

/**
 * Persist a sub-agent's identity bundle keyed by class slug.
 */
export async function persistSubAgentVc(classSlug, sub) {
  const seedB64 = Buffer.from(sub.slotSeed ?? sub.seed).toString('base64url');
  await writeSecret(`${SERVICE_SUB_SLOT_SEED}:${classSlug}`, seedB64);
  await writeSecret(`${SERVICE_SUB_VC}:${classSlug}`, sub.vcCompact);
}

/**
 * Delete an agent's stored material. Used on revocation.
 */
export async function deleteAgentVc(scope = 'main') {
  await deleteSecret(`${SERVICE_SLOT_SEED}:${scope}`);
  await deleteSecret(`${SERVICE_PROJECT_ROOT_SEED}:${scope}`);
  await deleteSecret(`${SERVICE_SLOT_INDEX}:${scope}`);
  await deleteSecret(`${SERVICE_AGENT_DID}:${scope}`);
  await deleteSecret(`${SERVICE_VC}:${scope}`);
  await deleteSecret(`${SERVICE_IDP_URL}:${scope}`);
}

// ---------------------------------------------------------------------
// Platform dispatch
// ---------------------------------------------------------------------

async function readSecret(service) {
  if (process.platform === 'darwin') return readMacOS(service);
  if (process.platform === 'linux') return readLinux(service);
  if (process.platform === 'win32') return readWindows(service);
  throw new Error(`unsupported platform: ${process.platform}`);
}

async function writeSecret(service, value) {
  if (process.platform === 'darwin') return writeMacOS(service, value);
  if (process.platform === 'linux') return writeLinux(service, value);
  if (process.platform === 'win32') return writeWindows(service, value);
  throw new Error(`unsupported platform: ${process.platform}`);
}

async function deleteSecret(service) {
  if (process.platform === 'darwin') return deleteMacOS(service);
  if (process.platform === 'linux') return deleteLinux(service);
  if (process.platform === 'win32') return deleteWindows(service);
  throw new Error(`unsupported platform: ${process.platform}`);
}

// macOS
async function readMacOS(service) {
  try {
    const { stdout } = await execFileAsync('security', [
      'find-generic-password',
      '-a',
      process.env.USER ?? '',
      '-s',
      service,
      '-w',
    ]);
    return stdout.trim();
  } catch {
    return null;
  }
}

async function writeMacOS(service, value) {
  await execFileAsync('security', [
    'add-generic-password',
    '-a',
    process.env.USER ?? '',
    '-s',
    service,
    '-w',
    value,
    '-U',
  ]);
}

async function deleteMacOS(service) {
  try {
    await execFileAsync('security', [
      'delete-generic-password',
      '-a',
      process.env.USER ?? '',
      '-s',
      service,
    ]);
  } catch {
    // Already gone — fine.
  }
}

// Linux (secret-tool from libsecret)
async function readLinux(service) {
  try {
    const { stdout } = await execFileAsync('secret-tool', [
      'lookup',
      'service',
      service,
    ]);
    return stdout.trim();
  } catch {
    return null;
  }
}

async function writeLinux(service, value) {
  await execFileAsync('secret-tool', ['store', '--label=' + service, 'service', service], {
    input: value,
  });
}

async function deleteLinux(service) {
  try {
    await execFileAsync('secret-tool', ['clear', 'service', service]);
  } catch {
    // Already gone — fine.
  }
}

// Windows (PowerShell wrapper around DPAPI / Credential Manager)
async function readWindows(service) {
  // PowerShell one-liner; throws if the credential is not present.
  try {
    const { stdout } = await execFileAsync('powershell', [
      '-NoProfile',
      '-Command',
      `(Get-StoredCredential -Target '${service}').GetNetworkCredential().Password`,
    ]);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function writeWindows(service, value) {
  await execFileAsync('powershell', [
    '-NoProfile',
    '-Command',
    `New-StoredCredential -Target '${service}' -Password '${value.replace(/'/g, "''")}' -Persist LocalMachine | Out-Null`,
  ]);
}

async function deleteWindows(service) {
  try {
    await execFileAsync('powershell', [
      '-NoProfile',
      '-Command',
      `Remove-StoredCredential -Target '${service}'`,
    ]);
  } catch {
    // Already gone — fine.
  }
}
