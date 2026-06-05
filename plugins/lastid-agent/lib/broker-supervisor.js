/**
 * Signed-broker daemon supervisor (Phase 1 of the broker-credential-custody
 * plan). The listener owns the broker's lifecycle: it spawns the code-signed
 * broker for its scope, waits for the socket + token + a healthy Health probe,
 * and restarts it on death — so a long-lived broker is available to serve
 * `brokerIdpFetch` (FORK1) for as long as the listener runs.
 *
 * No-flag-day: gated behind `LASTID_BROKER_IDP` (default OFF) AND macOS-only
 * (the broker owns the macOS Secure Enclave). On any other platform, or with the
 * flag off, this is a no-op (returns null) and the agent keeps the legacy node
 * IdP path. The broker's serve loop is its DEFAULT action — there is NO `serve`
 * subcommand (an unknown arg fails closed in the broker's main.rs).
 */
import { spawn } from 'node:child_process';
import { rm, stat } from 'node:fs/promises';

import { resolveBrokerPath } from './broker-client.js';
import { brokerSocketPath, brokerTokenPath, brokerHealth } from './broker-ipc.js';

/**
 * The no-flag-day feature flag. OFF by default → legacy node IdP path. Set
 * `LASTID_BROKER_IDP=1` (or true/on/yes) to route authed IdP calls through the
 * signed broker. Pure + injectable for tests.
 */
export function brokerIdpEnabled(env = process.env) {
  const v = String(env.LASTID_BROKER_IDP ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'on' || v === 'yes';
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
    log('[broker] LASTID_BROKER_IDP off — legacy node IdP path');
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
