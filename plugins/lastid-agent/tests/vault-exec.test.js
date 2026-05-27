/**
 * CLI credential proxy core (lib/vault-exec.js): the strict child env, the
 * streaming-safe secret scrubber (incl. secrets split across chunk boundaries),
 * and the streaming child runner (capture/exit, output cap, timeout, stdin
 * ignored). The spawn is injected so this runs without a real child process.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { buildChildEnv, makeStreamScrubber, runChildStreaming, commandBinary } from '../lib/vault-exec.js';

// ── buildChildEnv ────────────────────────────────────────────────────────────
test('buildChildEnv: injects creds, keeps allowlisted base, drops everything else', () => {
  const base = { PATH: '/bin', HOME: '/h', RANDOM_VAR: 'y', SOME_TOKEN: 'leak' };
  const env = buildChildEnv(base, { GH_TOKEN: 'tok' });
  assert.equal(env.GH_TOKEN, 'tok'); // injected present
  assert.equal(env.PATH, '/bin'); // allowlisted base kept
  assert.equal(env.HOME, '/h');
  assert.equal('RANDOM_VAR' in env, false); // non-allowlisted dropped
  assert.equal('SOME_TOKEN' in env, false); // sensitive base dropped
});

test('buildChildEnv: a sensitive-looking allowlisted extra is still dropped; non-sensitive extra kept', () => {
  const base = { PATH: '/bin', MY_TOKEN: 'leak', AWS_REGION: 'us-east-1' };
  const env = buildChildEnv(base, { AWS_SECRET_ACCESS_KEY: 'sek' }, { allowlist: ['MY_TOKEN', 'AWS_REGION'] });
  assert.equal('MY_TOKEN' in env, false, 'sensitive-suffix name dropped even if allowlisted');
  assert.equal(env.AWS_REGION, 'us-east-1', 'non-sensitive extra kept');
  assert.equal(env.AWS_SECRET_ACCESS_KEY, 'sek', 'injected cred present (exempt from denylist)');
});

test('buildChildEnv: injected var overrides a colliding base var', () => {
  const env = buildChildEnv({ PATH: '/bin', GH_TOKEN: 'old' }, { GH_TOKEN: 'new' });
  assert.equal(env.GH_TOKEN, 'new');
});

// ── makeStreamScrubber ───────────────────────────────────────────────────────
const drain = (scrubber, ...chunks) => {
  const parts = [];
  for (const c of chunks) parts.push(scrubber.push(Buffer.from(c)));
  parts.push(scrubber.flush());
  return Buffer.concat(parts).toString('utf8');
};

test('makeStreamScrubber: redacts a secret within one chunk', () => {
  assert.equal(drain(makeStreamScrubber(['SEKRET']), 'aaSEKRETbb'), 'aa[redacted]bb');
});

test('makeStreamScrubber: redacts a secret SPLIT across chunk boundaries', () => {
  assert.equal(drain(makeStreamScrubber(['SEKRET']), 'aaSEK', 'RETbb'), 'aa[redacted]bb');
});

test('makeStreamScrubber: longest-first so a contained secret is redacted whole', () => {
  assert.equal(drain(makeStreamScrubber(['SEK', 'SEKRET']), 'xSEKRETx'), 'x[redacted]x');
});

test('makeStreamScrubber: redacts both primary + secondary', () => {
  assert.equal(drain(makeStreamScrubber(['AAA', 'BBBBB']), 'xAAAyBBBBBz'), 'x[redacted]y[redacted]z');
});

test('makeStreamScrubber: leaves non-occurring text intact', () => {
  assert.equal(drain(makeStreamScrubber(['NOPE']), 'hello world'), 'hello world');
});

// ── runChildStreaming ────────────────────────────────────────────────────────
function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  return child;
}

test('runChildStreaming: streams SCRUBBED stdout + reports exit; secret never emitted', async () => {
  const child = fakeChild();
  const out = [];
  const p = runChildStreaming({
    argv: ['gh', 'api', 'user'], env: {}, secrets: ['TOPSECRET'], spawnImpl: () => child,
    onStdout: (b) => out.push(b.toString('utf8')), onStderr: () => {},
  });
  queueMicrotask(() => {
    child.stdout.emit('data', Buffer.from('login=me token=TOPSECRET done'));
    child.emit('close', 0, null);
  });
  const r = await p;
  assert.equal(r.exit_code, 0);
  assert.equal(r.timed_out, false);
  const joined = out.join('');
  assert.equal(joined.includes('TOPSECRET'), false, 'secret scrubbed from stream');
  assert.ok(joined.includes('[redacted]'));
});

test('runChildStreaming: output cap kills child + flags truncated', async () => {
  const child = fakeChild();
  child.kill = () => queueMicrotask(() => child.emit('close', null, 'SIGKILL'));
  const p = runChildStreaming({ argv: ['x'], env: {}, secrets: [], spawnImpl: () => child, outputCapBytes: 4, onStdout: () => {}, onStderr: () => {} });
  queueMicrotask(() => child.stdout.emit('data', Buffer.from('aaaaaaaa')));
  const r = await p;
  assert.equal(r.truncated, true);
});

test('runChildStreaming: timeout kills child + flags timed_out', async () => {
  const child = fakeChild();
  let killed = false;
  child.kill = () => { killed = true; queueMicrotask(() => child.emit('close', null, 'SIGKILL')); };
  const r = await runChildStreaming({ argv: ['x'], env: {}, secrets: [], spawnImpl: () => child, timeoutMs: 5, onStdout: () => {}, onStderr: () => {} });
  assert.equal(r.timed_out, true);
  assert.equal(killed, true);
});

test('runChildStreaming: stdin is IGNORED (no interactive prompt to feed an exfil)', async () => {
  let stdioSeen = null;
  const child = fakeChild();
  const spawnImpl = (_cmd, _args, opts) => { stdioSeen = opts.stdio; queueMicrotask(() => child.emit('close', 0, null)); return child; };
  await runChildStreaming({ argv: ['x'], env: {}, secrets: [], spawnImpl, onStdout: () => {}, onStderr: () => {} });
  assert.deepEqual(stdioSeen, ['ignore', 'pipe', 'pipe']);
});

test('runChildStreaming: a spawn throw surfaces as spawn_error, not a crash', async () => {
  const r = await runChildStreaming({ argv: ['nope'], env: {}, secrets: [], spawnImpl: () => { throw new Error('ENOENT nope'); }, onStdout: () => {}, onStderr: () => {} });
  assert.equal(r.exit_code, null);
  assert.ok(r.spawn_error.includes('ENOENT'));
});

// ── commandBinary ────────────────────────────────────────────────────────────
test('commandBinary: basename of argv[0]', () => {
  assert.equal(commandBinary(['/usr/local/bin/aws', 's3', 'ls']), 'aws');
  assert.equal(commandBinary(['gh']), 'gh');
  assert.equal(commandBinary([]), '');
});
