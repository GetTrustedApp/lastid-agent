/**
 * Signed-broker daemon supervisor (Phase 1 of the broker-credential-custody
 * plan). The listener owns the broker's lifecycle: it spawns the code-signed
 * broker for its scope, waits for the socket + token + a healthy Health probe,
 * and restarts it on death — so a long-lived broker is available to serve
 * `brokerIdpFetch` (FORK1) for as long as the listener runs.
 *
 * Broker-native is the DEFAULT on macOS (no flag to opt in); `LASTID_BROKER_IDP`
 * set to a falsey value is only a rollback kill-switch. On any non-macOS platform,
 * with the kill-switch set, or when the binary can't be resolved, this is a no-op
 * (returns null) and the agent keeps the legacy node IdP path. The listener only
 * calls this for a broker-native agent (seed in the protected store); a legacy
 * seed-in-keychain agent never starts a broker. The broker's serve loop is its
 * DEFAULT action — there is NO `serve` subcommand (unknown arg fails closed).
 */
import { spawn } from 'node:child_process';
import { rm, stat } from 'node:fs/promises';

import { resolveBrokerPath } from './broker-client.js';
import { brokerSocketPath, brokerTokenPath, brokerHealth } from './broker-ipc.js';

/**
 * Whether the signed-broker credential path is active. Broker-native is now the
 * DEFAULT on macOS (the broker owns the Secure Enclave + data-protection
 * keychain) — you do NOT set a flag to opt in; a freshly provisioned agent is
 * broker-native automatically. `LASTID_BROKER_IDP` is only a rollback
 * KILL-SWITCH: an explicit falsey value (`0`/`false`/`off`/`no`) forces the
 * legacy in-node path. Non-macOS is always legacy (no Secure Enclave).
 *
 * NOTE: this gates whether the broker path is *permitted/preferred*; the actual
 * runtime discriminator for an EXISTING agent is where its seed lives
 * (`loaded.brokerNative` / `brokerAvailable(scope)`), so a legacy seed-in-keychain
 * agent keeps the node path regardless. Pure + injectable for tests.
 */
export function brokerIdpEnabled(env = process.env, platform = process.platform) {
  if (platform !== 'darwin') return false;
  const v = String(env.LASTID_BROKER_IDP ?? '').trim().toLowerCase();
  return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
}

async function fileExists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Start + supervise the signed broker for `scope`. Returns a handle
 * `{ stop, ready, pid, socketPath }`, or `null` when the broker path is not
 * taken (flag off, non-macOS, or the binary can't be resolved) so the caller
 * falls through to the legacy node path.
 *
 * Almost everything is injectable so the supervisor is unit-testable without the
 * real signed broker: `spawnImpl`, `healthImpl`, `socketReady`, `sleepImpl`,
 * `now`, and the timing knobs.
 *
 * @param {object} a
 * @param {string} a.scope
 * @param {string} [a.idpUrl]
 * @param {string} [a.platform]
 * @param {boolean} [a.enabled]            - default brokerIdpEnabled()
 * @param {boolean} [a.reprovision]        - pass --reprovision (reissue: force
 *   provisioning-only even if a seed already exists for the scope)
 * @param {string} [a.brokerPath]          - default resolveBrokerPath()
 * @param {typeof import('node:child_process').spawn} [a.spawnImpl]
 * @param {typeof brokerHealth} [a.healthImpl]
 * @param {() => Promise<boolean>} [a.socketReady] - default: socket+token exist
 * @param {(l:string)=>void} [a.log]
 * @param {number} [a.readyTimeoutMs]
 * @param {number} [a.pollMs]
 * @param {number} [a.restartBackoffMs]
 * @param {(ms:number)=>Promise<void>} [a.sleepImpl]
 * @param {()=>number} [a.now]
 */
export async function startBrokerSupervisor({
  scope = 'main',
  idpUrl,
  platform = process.platform,
  enabled,
  reprovision = false,
  brokerPath,
  spawnImpl = spawn,
  healthImpl = brokerHealth,
  socketReady,
  log = () => {},
  readyTimeoutMs = 15_000,
  pollMs = 200,
  restartBackoffMs = 1_000,
  sleepImpl = (ms) => new Promise((r) => setTimeout(r, ms)),
  now = () => Date.now(),
} = {}) {
  const on = enabled ?? brokerIdpEnabled();
  if (!on) {
    log('[broker] broker path disabled (LASTID_BROKER_IDP kill-switch) — legacy node IdP path');
    return null;
  }
  if (platform !== 'darwin') {
    log('[broker] non-macOS — legacy node IdP path (broker owns the Secure Enclave)');
    return null;
  }
  let bin;
  try {
    bin = brokerPath ?? resolveBrokerPath();
  } catch (err) {
    log(`[broker] could not resolve broker binary: ${err?.message ?? err} — legacy node path`);
    return null;
  }

  const sockPath = brokerSocketPath(scope);
  const tokPath = brokerTokenPath(scope);
  const isReady =
    socketReady ?? (async () => (await fileExists(sockPath)) && (await fileExists(tokPath)));

  let stopping = false;
  let child = null;

  const spawnOnce = () => {
    // DEFAULT action = serve/listen loop; NO `serve` subcommand (the broker
    // fails closed on an unknown argument). Just --scope (+ --idp for dev/mock).
    const args = ['--scope', scope];
    if (idpUrl) args.push('--idp', idpUrl);
    // Reissue: force the broker into provisioning-only mode even though a seed
    // exists for this scope (it would otherwise boot agent-mode and reject
    // ProvisionInitiate). The fresh provision overwrites the old protected-store
    // seed. Node can't clear that seed itself (it's in the broker's access group).
    if (reprovision) args.push('--reprovision');
    const c = spawnImpl(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
    if (c?.stdout?.on) c.stdout.on('data', (d) => log(`[broker] ${String(d).trimEnd()}`));
    if (c?.stderr?.on) c.stderr.on('data', (d) => log(`[broker] ${String(d).trimEnd()}`));
    if (c?.on) {
      c.on('exit', (code, sig) => {
        if (stopping) return;
        log(`[broker] exited (code=${code} sig=${sig}) — restarting in ${restartBackoffMs}ms`);
        sleepImpl(restartBackoffMs).then(() => {
          if (!stopping) child = spawnOnce();
        });
      });
    }
    return c;
  };

  // Clear any stale socket/token from a previous launch so we wait for OURS.
  await rm(sockPath, { force: true }).catch(() => {});
  await rm(tokPath, { force: true }).catch(() => {});
  child = spawnOnce();

  // Wait for socket+token to appear, then a healthy Health probe.
  let ready = false;
  const deadline = now() + readyTimeoutMs;
  while (now() < deadline && !stopping) {
    if (await isReady()) {
      try {
        const h = await healthImpl({ scope });
        if (h && h.ok) {
          ready = true;
          const provisioned = h.body?.device_provisioned === true;
          log(`[broker] ready (health ok, device_provisioned=${provisioned})`);
          break;
        }
      } catch {
        /* not up yet — keep polling */
      }
    }
    await sleepImpl(pollMs);
  }
  if (!ready) {
    log(`[broker] not healthy within ${readyTimeoutMs}ms — supervising (will retry); calls fall back to legacy until ready`);
  }

  const stop = () => {
    stopping = true;
    try {
      child?.kill?.('SIGTERM');
    } catch {
      /* ignore */
    }
  };

  return {
    stop,
    ready,
    get pid() {
      return child?.pid;
    },
    socketPath: sockPath,
  };
}
