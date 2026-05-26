/**
 * vault-scope (lib/vault-scope.js) — builds the working-context scope map sent
 * with every vault_use so a share's scope_required constraint can match where
 * the agent is working. Without it a scoped share ALWAYS denies (the desktop
 * sent a SessionFingerprint for this; the SaaS port dropped it). Deps are
 * injected so we exercise the mapping without touching real git/cwd.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildVaultUseScope } from '../lib/vault-scope.js';

const FP = {
  cwd_hash: 'CWDHASH',
  host_machine_id: 'HOSTID',
  git_remote: 'git@github.com:GetTrustedApp/lastid.co.git',
  head_commit_sha: 'abc123',
  package_root_hash: 'PKGHASH',
};

test('repo comes from the sticky last-project (the live signal), verbatim', () => {
  const s = buildVaultUseScope({
    scope: 'main',
    readProject: () => 'github.com/gettrustedapp/lastid.co',
    fingerprint: () => FP,
  });
  assert.equal(s.repo, 'github.com/gettrustedapp/lastid.co');
  assert.equal(s.git_remote, 'git@github.com:GetTrustedApp/lastid.co.git'); // raw, desktop parity
  assert.equal(s.git_commit, 'abc123');
  assert.equal(s.cwd, 'CWDHASH');
  assert.equal(s.host, 'HOSTID');
  assert.equal(s.project, 'PKGHASH');
});

test('repo falls back to the normalized cwd origin when there is no sticky project', () => {
  const s = buildVaultUseScope({
    readProject: () => null,
    fingerprint: () => FP,
  });
  // normalizeRemoteUrl lowercases host/owner/repo and drops scheme/.git.
  assert.equal(s.repo, 'github.com/gettrustedapp/lastid.co');
});

test('project falls back to cwd_hash when no package manifest hash', () => {
  const s = buildVaultUseScope({
    readProject: () => null,
    fingerprint: () => ({ cwd_hash: 'CWDONLY', host_machine_id: 'H' }),
  });
  assert.equal(s.project, 'CWDONLY');
  assert.equal('git_remote' in s, false); // absent signal → key omitted
  assert.equal('repo' in s, false); // no sticky + no remote → no repo
});

test('a thrown fingerprint / readProject degrades to an empty-ish map, never throws', () => {
  const s = buildVaultUseScope({
    readProject: () => {
      throw new Error('boom');
    },
    fingerprint: () => {
      throw new Error('git unavailable');
    },
  });
  assert.deepEqual(s, {}); // safe: a scoped share then fails closed in the evaluator
});

test('the scope map keys match what vault-policy scope_required reads (ctx.scope[name])', () => {
  // Guard: the constraint names the console authors must line up with these keys.
  const s = buildVaultUseScope({ readProject: () => 'r/x', fingerprint: () => FP });
  for (const k of ['repo', 'git_remote', 'git_commit', 'cwd', 'host', 'project']) {
    assert.ok(k in s, `scope map must expose '${k}'`);
  }
});
