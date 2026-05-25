/**
 * Tests for project-key resolution (lib/project-key.js).
 *
 * Project-tier memories are keyed to the git REMOTE so the same codebase on
 * two machines (or two agents, at different paths) shares one key. These lock
 * the normalizer against the real remote forms (all SSH here) plus the https/
 * auth/port variants, and exercise the path→key walk including the worktree
 * `.git`-as-a-file case and the no-remote / no-git fallbacks.
 */
import { test, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  normalizeRemoteUrl,
  originUrlFromConfig,
  projectKeyForPath,
} from '../lib/project-key.js';

// ── normalizeRemoteUrl ─────────────────────────────────────────────

test('normalizeRemoteUrl: the real SSH form used by every repo here', () => {
  assert.equal(
    normalizeRemoteUrl('git@github.com:GetTrustedApp/gettrusted-idp.git'),
    'github.com/gettrustedapp/gettrusted-idp',
  );
  assert.equal(
    normalizeRemoteUrl('git@github.com:GetTrustedApp/lastid-agent.git'),
    'github.com/gettrustedapp/lastid-agent',
  );
});

test('normalizeRemoteUrl: https, with and without .git / auth', () => {
  assert.equal(
    normalizeRemoteUrl('https://github.com/Org/Repo.git'),
    'github.com/org/repo',
  );
  assert.equal(
    normalizeRemoteUrl('https://github.com/Org/Repo'),
    'github.com/org/repo',
  );
  assert.equal(
    normalizeRemoteUrl('https://user:ghp_token@github.com/Org/Repo.git'),
    'github.com/org/repo',
  );
});

test('normalizeRemoteUrl: ssh:// with a port, and git://', () => {
  assert.equal(
    normalizeRemoteUrl('ssh://git@gitlab.com:22/group/sub/repo.git'),
    'gitlab.com/group/sub/repo',
  );
  assert.equal(
    normalizeRemoteUrl('git://github.com/Org/Repo.git'),
    'github.com/org/repo',
  );
});

test('normalizeRemoteUrl: two clones differing only in case map to ONE key', () => {
  const a = normalizeRemoteUrl('git@github.com:GetTrustedApp/Repo.git');
  const b = normalizeRemoteUrl('https://github.com/gettrustedapp/repo');
  assert.equal(a, b, 'case-insensitive host/owner/repo must collapse to one key');
});

test('normalizeRemoteUrl: trailing slash / nested groups preserved', () => {
  assert.equal(normalizeRemoteUrl('git@github.com:Org/Repo.git/'), 'github.com/org/repo');
  assert.equal(
    normalizeRemoteUrl('https://gitlab.com/a/b/c/repo.git'),
    'gitlab.com/a/b/c/repo',
  );
});

test('normalizeRemoteUrl: negative — empty/garbage/non-string → null', () => {
  assert.equal(normalizeRemoteUrl(''), null);
  assert.equal(normalizeRemoteUrl('   '), null);
  assert.equal(normalizeRemoteUrl('not a url'), null);
  assert.equal(normalizeRemoteUrl(undefined), null);
  assert.equal(normalizeRemoteUrl(null), null);
  assert.equal(normalizeRemoteUrl(42), null);
});

// ── originUrlFromConfig ────────────────────────────────────────────

test('originUrlFromConfig: pulls origin url, ignores other remotes/sections', () => {
  const cfg = `[core]
\trepositoryformatversion = 0
[remote "upstream"]
\turl = git@github.com:Other/fork.git
[remote "origin"]
\turl = git@github.com:GetTrustedApp/gettrusted-idp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin`;
  assert.equal(originUrlFromConfig(cfg), 'git@github.com:GetTrustedApp/gettrusted-idp.git');
});

test('originUrlFromConfig: negative — no origin section → null', () => {
  assert.equal(originUrlFromConfig('[core]\n\tbare = false\n'), null);
  assert.equal(originUrlFromConfig(''), null);
});

// ── projectKeyForPath (temp-dir fixtures) ──────────────────────────

const ROOT = mkdtempSync(join(tmpdir(), 'lastid-projkey-'));
after(() => {
  try {
    rmSync(ROOT, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
});

function makeRepo(name, { url } = {}) {
  const repo = join(ROOT, name);
  mkdirSync(join(repo, '.git'), { recursive: true });
  const cfg = url
    ? `[remote "origin"]\n\turl = ${url}\n`
    : `[core]\n\tbare = false\n`;
  writeFileSync(join(repo, '.git', 'config'), cfg);
  return repo;
}

test('projectKeyForPath: resolves the remote from a file DEEP in the repo', () => {
  const repo = makeRepo('gettrusted-idp', { url: 'git@github.com:GetTrustedApp/gettrusted-idp.git' });
  const deep = join(repo, 'src', 'api', 'websocket', 'server.ts');
  // The leaf file need not exist — we only walk up to find .git.
  assert.equal(projectKeyForPath(deep), 'github.com/gettrustedapp/gettrusted-idp');
});

test('projectKeyForPath: two repos resolve to DIFFERENT keys (the whole point)', () => {
  const idp = makeRepo('idp2', { url: 'git@github.com:GetTrustedApp/gettrusted-idp.git' });
  const sdk = makeRepo('sdk2', { url: 'git@github.com:GetTrustedApp/lastid-sdk.git' });
  const ka = projectKeyForPath(join(idp, 'src', 'x.ts'));
  const kb = projectKeyForPath(join(sdk, 'src', 'y.ts'));
  assert.equal(ka, 'github.com/gettrustedapp/gettrusted-idp');
  assert.equal(kb, 'github.com/gettrustedapp/lastid-sdk');
  assert.notEqual(ka, kb);
});

test('projectKeyForPath: worktree .git FILE follows gitdir to the real config', () => {
  // Main repo with config.
  const main = makeRepo('wt-main', { url: 'git@github.com:GetTrustedApp/lastid.co.git' });
  // Simulate a linked worktree: worktrees/<name> dir with a commondir pointer,
  // and a checkout dir whose `.git` is a FILE pointing at it.
  const wtGitDir = join(main, '.git', 'worktrees', 'feature');
  mkdirSync(wtGitDir, { recursive: true });
  writeFileSync(join(wtGitDir, 'commondir'), '../..\n'); // → main/.git
  const checkout = join(ROOT, 'wt-checkout');
  mkdirSync(checkout, { recursive: true });
  writeFileSync(join(checkout, '.git'), `gitdir: ${wtGitDir}\n`);
  assert.equal(
    projectKeyForPath(join(checkout, 'src', 'page.tsx')),
    'github.com/gettrustedapp/lastid.co',
  );
});

test('projectKeyForPath: no remote → machine-local fallback key', () => {
  const repo = makeRepo('local-only');
  assert.equal(projectKeyForPath(join(repo, 'main.c')), 'local/local-only');
});

test('projectKeyForPath: negative — not in a git repo → null (no project scoping)', () => {
  const loose = join(ROOT, 'no-git-here');
  mkdirSync(loose, { recursive: true });
  assert.equal(projectKeyForPath(join(loose, 'file.txt')), null);
});

test('projectKeyForPath: negative — empty / non-string input → null', () => {
  assert.equal(projectKeyForPath(''), null);
  assert.equal(projectKeyForPath(undefined), null);
});
