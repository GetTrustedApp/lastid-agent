/**
 * Regression tests for the listener single-instance lock
 * (lib/listener-daemon.js: shouldEvictListener / acquireListenerLock /
 *  releaseListenerLock).
 *
 * THE BUG (root-caused live): the listener is the SINGLE MLS-state writer and
 * the sole owner of the agent-state sync cursor for its scope. Nothing stopped
 * a SECOND listener from running on the same scope — a manual `lastid-agent
 * listen` (dev/testing) was invisible to the daemon supervisor and coexisted
 * with the installed daemon listener. Both received the `rules.changed` /
 * `memory.changed` doorbell, both pulled `?since=<cursor>`, and whichever won
 * advanced the SHARED cursor so the other applied nothing. A stray OLDER-build
 * listener (predating memory sync) ate the cursor advance while dropping the
 * memory records — so published memories silently never reached the agent.
 *
 * The fix: the listener itself acquires a per-scope lock on startup, evicting
 * any other live listener and claiming the pid file. Exactly one writer.
 */
import { test, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

// Lock files land under os.homedir()/.lastid-agent/<scope>; point HOME at a
// temp dir so the test never touches the real agent state. The lock functions
// read homedir() at call time, so setting this before any call is sufficient.
const HOME = mkdtempSync(join(tmpdir(), 'lastid-lock-'));
process.env.HOME = HOME;
process.env.USERPROFILE = HOME; // windows parity, harmless on posix

const {
  shouldEvictListener,
  acquireListenerLock,
  releaseListenerLock,
  listenerPidPath,
  parseScopeListenerPids,
  reapScopeListeners,
} = await import('../lib/listener-daemon.js');

after(() => {
  try {
    rmSync(HOME, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
});

const pidOf = (scope) => readFileSync(listenerPidPath(scope), 'utf-8').trim();

// ── shouldEvictListener (pure decision) ────────────────────────────

test('shouldEvictListener: evicts a live OTHER listener', () => {
  assert.equal(shouldEvictListener({ existingPid: 222, selfPid: 111, alive: true }), true);
});

test('shouldEvictListener: never evicts our OWN pid (daemon pre-wrote it)', () => {
  assert.equal(shouldEvictListener({ existingPid: 111, selfPid: 111, alive: true }), false);
});

test('shouldEvictListener: a dead recorded pid is not evicted (nothing to kill)', () => {
  assert.equal(shouldEvictListener({ existingPid: 222, selfPid: 111, alive: false }), false);
});

test('shouldEvictListener: no recorded pid → nothing to evict', () => {
  assert.equal(shouldEvictListener({ existingPid: null, selfPid: 111, alive: false }), false);
  assert.equal(shouldEvictListener({ existingPid: 0, selfPid: 111, alive: true }), false);
});

// ── acquireListenerLock ────────────────────────────────────────────

test('acquireListenerLock: claims the pid file when none exists', async () => {
  const scope = 'fresh';
  const r = await acquireListenerLock({ scope, selfPid: 4242, selfPath: '/x/bin/lastid-agent.js' });
  assert.equal(r.evicted, null);
  assert.equal(r.pid, 4242);
  assert.equal(pidOf(scope), '4242');
});

test('acquireListenerLock: re-acquire with our own pid does NOT self-evict', async () => {
  const scope = 'selfpid';
  await acquireListenerLock({ scope, selfPid: process.pid });
  const r = await acquireListenerLock({ scope, selfPid: process.pid });
  assert.equal(r.evicted, null);
  assert.equal(pidOf(scope), String(process.pid));
});

test('acquireListenerLock: claims over a STALE (dead) pid without a kill', async () => {
  const scope = 'stale';
  // 7777 is not a live process → isAlive false → no eviction, just claim.
  await acquireListenerLock({ scope, selfPid: 7777 });
  const r = await acquireListenerLock({ scope, selfPid: 9999 });
  assert.equal(r.evicted, null);
  assert.equal(pidOf(scope), '9999');
});

test('REGRESSION: acquireListenerLock evicts a LIVE foreign listener (the two-writers bug)', async () => {
  const scope = 'evict';
  // A real, long-lived child stands in for a second listener already running.
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1e9)'], { stdio: 'ignore' });
  child.unref();
  // Record it as the current listener (as a manual dev listener would).
  await acquireListenerLock({ scope, selfPid: child.pid, selfPath: '/old/bin/lastid-agent.js' });
  assert.equal(pidOf(scope), String(child.pid));

  // We start up: must evict the foreign listener and claim the lock.
  const r = await acquireListenerLock({ scope, selfPid: process.pid, selfPath: '/new/bin/lastid-agent.js' });
  assert.equal(r.evicted, child.pid, 'reports the evicted pid');
  assert.equal(pidOf(scope), String(process.pid), 'we now own the lock');

  // And the evicted listener is actually dead — not just unrecorded.
  let dead = false;
  for (let i = 0; i < 100; i++) {
    try {
      process.kill(child.pid, 0);
      await sleep(20);
    } catch {
      dead = true;
      break;
    }
  }
  assert.ok(dead, 'the evicted listener process is killed (single MLS writer enforced)');
});

// ── releaseListenerLock ────────────────────────────────────────────

test('releaseListenerLock: clears the lock when it is still ours', async () => {
  const scope = 'rel';
  await acquireListenerLock({ scope, selfPid: 5555 });
  const r = await releaseListenerLock({ scope, selfPid: 5555 });
  assert.equal(r.released, true);
  assert.equal(existsSync(listenerPidPath(scope)), false);
});

test('REGRESSION: releaseListenerLock does NOT delete a successor owner pid', async () => {
  const scope = 'rel2';
  await acquireListenerLock({ scope, selfPid: 5555 });
  // A successor took over while we were running (its acquire overwrote the pid).
  await acquireListenerLock({ scope, selfPid: 6666 });
  // We (5555) shut down — must leave the successor's lock intact.
  const r = await releaseListenerLock({ scope, selfPid: 5555 });
  assert.equal(r.released, false);
  assert.equal(pidOf(scope), '6666', "successor's lock is untouched");
});

// ── parseScopeListenerPids (pure, scope-isolated) ──────────────────
//
// THE BUG (root-caused live): three listeners ran for one identity — a v0.10.1
// listener plus a 4h-old v0.8.29 ORPHAN on the same scope (left over across
// /plugin updates, never in the current pid-lock). Two listeners raced the
// scope's MLS ratchet so inbound operator messages "delivered" but never
// decoded (processInbound threw). The pid-lock only tracks one pid; enumeration
// reaps the strays it can't see — but MUST stay scoped (never touch another
// scope's listener).

test('parseScopeListenerPids: matches `listen` for the EXACT scope only', () => {
  const lines = [
    '  100 /usr/bin/node /c/lastid-agent/0.10.1/bin/lastid-agent.js listen --scope main',
    '  101 /usr/bin/node /c/lastid-agent/0.8.29/bin/lastid-agent.js listen --scope main', // old version, same scope
    '  102 /usr/bin/node /c/lastid-agent/0.9.0/bin/lastid-agent.js listen --scope lastid', // OTHER scope
    '  103 /usr/bin/node /c/lastid-agent/0.10.1/bin/lastid-agent.js serve', // MCP server, not a listener
    '  104 /usr/bin/node /c/lastid-agent/0.10.1/bin/lastid-agent.js sync --scope main', // sync, not listen
    '  105 node -e setInterval(()=>{},1e9)', // unrelated process
  ];
  assert.deepEqual(parseScopeListenerPids(lines, 'main').sort((a, b) => a - b), [100, 101]);
  assert.deepEqual(parseScopeListenerPids(lines, 'lastid'), [102]);
});

test('parseScopeListenerPids: a `listen` with no --scope flag counts as main', () => {
  const lines = ['  200 /c/bin/lastid-agent.js listen'];
  assert.deepEqual(parseScopeListenerPids(lines, 'main'), [200]);
  assert.deepEqual(parseScopeListenerPids(lines, 'lastid'), []);
});

// ── reapScopeListeners (injectable ps + kill — no real processes) ──

test('reapScopeListeners: SIGTERMs every scope listener except `keep`', async () => {
  const lines = [
    '  300 /c/0.10.1/bin/lastid-agent.js listen --scope main',
    '  301 /c/0.8.29/bin/lastid-agent.js listen --scope main', // stray old version
    '  302 /c/0.9.0/bin/lastid-agent.js listen --scope lastid', // other scope — untouched
  ];
  const killed = [];
  const r = await reapScopeListeners({
    scope: 'main',
    keep: 300,
    psImpl: async () => lines,
    killImpl: (pid) => (killed.push(pid), true),
  });
  assert.deepEqual(r.found.sort((a, b) => a - b), [300, 301], 'only main-scope listeners found');
  assert.deepEqual(killed, [301], 'kept 300, killed the stray');
  assert.deepEqual(r.reaped, [301]);
});

test('REGRESSION: reaping `main` never kills a `lastid`-scope listener', async () => {
  const lines = [
    '  400 /c/bin/lastid-agent.js listen --scope main',
    '  401 /c/bin/lastid-agent.js listen --scope lastid',
  ];
  const killed = [];
  await reapScopeListeners({
    scope: 'main',
    keep: null,
    psImpl: async () => lines,
    killImpl: (p) => (killed.push(p), true),
  });
  assert.deepEqual(killed, [400], 'only main reaped; lastid listener untouched');
});

test('reapScopeListeners: never reaps the caller (process.pid)', async () => {
  const lines = [`  ${process.pid} /c/bin/lastid-agent.js listen --scope main`];
  const killed = [];
  const r = await reapScopeListeners({
    scope: 'main',
    keep: null,
    psImpl: async () => lines,
    killImpl: (p) => (killed.push(p), true),
  });
  assert.deepEqual(killed, [], 'self skipped');
  assert.deepEqual(r.reaped, []);
});

test('reapScopeListeners: ps failure → no reap (best-effort; pid-lock stays the guard)', async () => {
  const killed = [];
  const r = await reapScopeListeners({
    scope: 'main',
    keep: null,
    psImpl: async () => {
      throw new Error('no ps');
    },
    killImpl: (p) => (killed.push(p), true),
  });
  assert.deepEqual(r.found, []);
  assert.deepEqual(killed, []);
});
