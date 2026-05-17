/**
 * OS-keychain adapter.
 *
 * Persists the agent's (seed, VC) pair to the host's secure store:
 *   - macOS: Keychain (`security` CLI)
 *   - Linux: Secret Service (`secret-tool`)
 *   - Windows: DPAPI / Credential Manager (via PowerShell)
 *
 * Keys used:
 *   lastid.co/agent-seed:<scope>   — 32-byte ai_agent_seed_N (base64url)
 *   lastid.co/agent-vc:<scope>     — compact SD-JWT VC string
 *   lastid.co/sub-agent-seed:<class>
 *   lastid.co/sub-agent-vc:<class>
 *
 * `<scope>` is "main" for the top-level agent or omitted for the
 * single-agent host case. Each sub-agent class gets its own pair so
 * a sub-agent can be revoked / re-provisioned independently.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SERVICE_SEED = 'lastid.co/agent-seed';
const SERVICE_VC = 'lastid.co/agent-vc';
const SERVICE_SUB_SEED = 'lastid.co/sub-agent-seed';
const SERVICE_SUB_VC = 'lastid.co/sub-agent-vc';

/**
 * Load the top-level agent's VC + seed from keychain. Returns null if
 * either piece is missing.
 */
export async function loadAgentVc(scope = 'main') {
  const seedB64 = await readSecret(`${SERVICE_SEED}:${scope}`);
  const vcCompact = await readSecret(`${SERVICE_VC}:${scope}`);
  if (!seedB64 || !vcCompact) return null;
  return {
    seed: Buffer.from(seedB64, 'base64url'),
    vcCompact,
  };
}

/**
 * Persist a freshly-provisioned agent.
 */
export async function persistAgentVc(provisioned, scope = 'main') {
  const seedB64 = Buffer.from(provisioned.seed).toString('base64url');
  await writeSecret(`${SERVICE_SEED}:${scope}`, seedB64);
  await writeSecret(`${SERVICE_VC}:${scope}`, provisioned.vcCompact);
}

/**
 * Persist a sub-agent's VC keyed by class slug.
 */
export async function persistSubAgentVc(classSlug, sub) {
  const seedB64 = Buffer.from(sub.seed).toString('base64url');
  await writeSecret(`${SERVICE_SUB_SEED}:${classSlug}`, seedB64);
  await writeSecret(`${SERVICE_SUB_VC}:${classSlug}`, sub.vcCompact);
}

/**
 * Delete an agent's stored material. Used on revocation.
 */
export async function deleteAgentVc(scope = 'main') {
  await deleteSecret(`${SERVICE_SEED}:${scope}`);
  await deleteSecret(`${SERVICE_VC}:${scope}`);
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
