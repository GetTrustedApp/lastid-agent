/**
 * Regression tests for the stale MCP-server reaper (lib/reap-stale-servers.js).
 *
 * THE BUG: `/plugin update` left an OLD-version `serve` process running (a
 * 0.8.16 serve still alive hours after the update to 0.8.19), which the
 * runtime never reaped and the plugin had no logic to recycle — unlike the
 * listener daemon. It competed for the agent's shared state and broke MCP
 * reconnects. The reaper kills other serves on a different (older) version
 * while leaving same-version concurrent sessions and dev runs untouched.
 */
import { test } from 'node:test';
import assert from 'node:assert';

import {
  versionFromPath,
  selectStaleServerPids,
  parseServeProcesses,
} from '../lib/reap-stale-servers.js';

const CACHE = (v) =>
  `/Users/x/.claude/plugins/cache/lastid-agent/lastid-agent/${v}/bin/lastid-agent.js`;

// ── versionFromPath ────────────────────────────────────────────────

test('versionFromPath: extracts version from a cache path', () => {
  assert.equal(versionFromPath(CACHE('0.8.19')), '0.8.19');
  assert.equal(versionFromPath(CACHE('0.8.16')), '0.8.16');
});

test('versionFromPath: dev / working-copy path has no version', () => {
  assert.equal(
    versionFromPath('/Users/x/GitHub/LastID/lastid-agent-plugin/plugins/lastid-agent/bin/lastid-agent.js'),
    null,
  );
  assert.equal(versionFromPath(undefined), null);
});

// ── selectStaleServerPids ──────────────────────────────────────────

test('REGRESSION: reaps an older-version serve, leaves self + same-version', () => {
  const self = { pid: 100, version: '0.8.19' };
  const kill = selectStaleServerPids({
    selfPid: self.pid,
    selfVersion: self.version,
    processes: [
      { pid: 100, version: '0.8.19' }, // self
      { pid: 200, version: '0.8.16' }, // STALE old version → reap
      { pid: 300, version: '0.8.19' }, // concurrent same-version session → leave
    ],
  });
  assert.deepEqual(kill, [200]);
});

test('reaps multiple distinct old versions', () => {
  const kill = selectStaleServerPids({
    selfPid: 1,
    selfVersion: '0.9.0',
    processes: [
      { pid: 2, version: '0.8.16' },
      { pid: 3, version: '0.8.19' },
      { pid: 4, version: '0.9.0' }, // same → leave
    ],
  });
  assert.deepEqual(kill.sort((a, b) => a - b), [2, 3]);
});

test('leaves unknown-version (dev) peers alone', () => {
  const kill = selectStaleServerPids({
    selfPid: 1,
    selfVersion: '0.8.19',
    processes: [{ pid: 2, version: null }],
  });
  assert.deepEqual(kill, []);
});

test('self version unknown (dev run) reaps nothing — never nukes the installed server', () => {
  const kill = selectStaleServerPids({
    selfPid: 1,
    selfVersion: null,
    processes: [
      { pid: 2, version: '0.8.19' },
      { pid: 3, version: '0.8.16' },
    ],
  });
  assert.deepEqual(kill, []);
});

test('never includes self even if listed', () => {
  const kill = selectStaleServerPids({
    selfPid: 42,
    selfVersion: '0.8.19',
    processes: [{ pid: 42, version: '0.8.16' }], // (hypothetical) self mislabeled — still excluded by pid
  });
  assert.deepEqual(kill, []);
});

// ── parseServeProcesses ────────────────────────────────────────────

test('parseServeProcesses: picks out serve invocations + their versions', () => {
  const ps = [
    `100 node ${CACHE('0.8.19')} serve`,
    `200 node ${CACHE('0.8.16')} serve --scope main`,
    `300 node ${CACHE('0.8.19')} listen --scope main`, // listener, NOT serve → ignored
    `400 /usr/bin/some-other-process --serve`, // unrelated → ignored
    ``,
  ].join('\n');
  const procs = parseServeProcesses(ps);
  assert.deepEqual(
    procs.map((p) => ({ pid: p.pid, version: p.version })),
    [
      { pid: 100, version: '0.8.19' },
      { pid: 200, version: '0.8.16' },
    ],
  );
});

test('parseServeProcesses: end-to-end with selectStaleServerPids reaps the old serve', () => {
  const ps = `100 node ${CACHE('0.8.19')} serve\n200 node ${CACHE('0.8.16')} serve`;
  const procs = parseServeProcesses(ps);
  const kill = selectStaleServerPids({ selfPid: 100, selfVersion: '0.8.19', processes: procs });
  assert.deepEqual(kill, [200]);
});
