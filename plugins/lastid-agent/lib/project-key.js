/**
 * Project-key resolution for project-tier memories.
 *
 * A "project" is identified by its git REMOTE, not its folder or path — so the
 * same codebase checked out on two machines (or by two agents, at different
 * paths) shares one key and one set of project memories. (Operator decision,
 * 2026-05-25: folder names don't even match repo names here — `lastid-idp/` is
 * the `gettrusted-idp` remote — so the path is a poor identity; the remote is
 * the true one.)
 *
 * Injection follows the WORK, not the session cwd: the listener/session starts
 * in some fixed dir (often ~), but the agent edits files across many repos in
 * one session. So callers resolve the key from the path of the file/command a
 * tool is about to act on (PreToolUse), walking up to that path's git root.
 *
 * `normalizeRemoteUrl` is pure (the bulk of the edge cases live there and are
 * unit-tested directly). `projectKeyForPath` does fs reads (find `.git`, read
 * its config) and is exercised against temp-dir fixtures.
 */
import { readFileSync, existsSync, statSync } from 'node:fs';
import { dirname, join, resolve, basename, isAbsolute, relative, sep } from 'node:path';

/**
 * Normalize a git remote URL to a stable, machine-independent project key of
 * the form `host/owner/repo` (lowercased). Handles the forms that actually
 * appear in the wild:
 *   - scp-like:   git@github.com:GetTrustedApp/gettrusted-idp.git
 *   - https:      https://github.com/Org/Repo.git
 *   - https+auth: https://user:token@github.com/Org/Repo
 *   - ssh://:     ssh://git@gitlab.com:22/group/sub/repo.git
 *   - git://:     git://host/owner/repo.git
 * Returns null for empty / unparseable input.
 *
 * Lowercased because GitHub (and most forges) treat host + owner + repo
 * case-insensitively, so two clones differing only in case must map to ONE
 * key. Nested groups (GitLab subgroups) are preserved in the path.
 */
export function normalizeRemoteUrl(url) {
  if (typeof url !== 'string') return null;
  let s = url.trim();
  if (s.length === 0) return null;

  let host;
  let path;

  // scp-like syntax: [user@]host:path  (no scheme, single colon before path,
  // path is NOT a port — i.e. not all-digits). This is the default `git@…:…`.
  const scp = s.match(/^(?:[^@/]+@)?([^/:]+):(.+)$/);
  if (scp && !/^\/\//.test(s) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^\d+(\/|$)/.test(scp[2])) {
    host = scp[1];
    path = scp[2];
  } else {
    // scheme://[user[:pass]@]host[:port]/path
    const m = s.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]+@)?([^/]+)\/(.+)$/i);
    if (!m) return null;
    host = m[1];
    path = m[2];
  }

  // Strip a port from the host (ssh://git@host:22/…).
  host = host.replace(/:\d+$/, '').toLowerCase();
  if (!host) return null;

  // Clean the path: drop leading/trailing slashes, a trailing `.git`, and any
  // querystring/fragment that snuck in.
  path = path.replace(/[?#].*$/, '').replace(/^\/+/, '').replace(/\/+$/, '');
  path = path.replace(/\.git$/i, '').replace(/\/+$/, '');
  if (!path) return null;

  return `${host}/${path}`.toLowerCase();
}

/**
 * Resolve the path to a repo's `.git/config`, given a directory KNOWN to
 * contain a `.git` entry. Handles both a real `.git` directory and a worktree/
 * submodule `.git` FILE (`gitdir: <path>`) by following it to the commondir's
 * config. Returns an absolute config path, or null if none is found.
 */
function configPathFromGitEntry(gitEntry) {
  try {
    const st = statSync(gitEntry);
    if (st.isDirectory()) {
      const cfg = join(gitEntry, 'config');
      return existsSync(cfg) ? cfg : null;
    }
    // `.git` is a file: `gitdir: /abs/or/rel/path/to/.git/worktrees/<name>`
    const raw = readFileSync(gitEntry, 'utf-8');
    const m = raw.match(/^gitdir:\s*(.+)\s*$/m);
    if (!m) return null;
    let gitDir = m[1].trim();
    if (!isAbsolute(gitDir)) gitDir = resolve(dirname(gitEntry), gitDir);
    // For a worktree this is `…/.git/worktrees/<name>`; config lives in the
    // commondir. Read `commondir` if present, else fall back two levels up.
    const commonFile = join(gitDir, 'commondir');
    let commonDir;
    if (existsSync(commonFile)) {
      const c = readFileSync(commonFile, 'utf-8').trim();
      commonDir = isAbsolute(c) ? c : resolve(gitDir, c);
    } else {
      commonDir = gitDir;
    }
    const cfg = join(commonDir, 'config');
    return existsSync(cfg) ? cfg : null;
  } catch {
    return null;
  }
}

/** Parse the `origin` remote URL out of a git config file's text. */
export function originUrlFromConfig(configText) {
  if (typeof configText !== 'string') return null;
  // Find the [remote "origin"] section, then its first `url = …` before the
  // next section header.
  const lines = configText.split('\n');
  let inOrigin = false;
  for (const line of lines) {
    const header = line.match(/^\s*\[(.+?)\]\s*$/);
    if (header) {
      inOrigin = /^remote\s+"origin"$/.test(header[1].trim());
      continue;
    }
    if (inOrigin) {
      const u = line.match(/^\s*url\s*=\s*(.+?)\s*$/);
      if (u) return u[1];
    }
  }
  return null;
}

/**
 * Resolve a stable project key for the repo enclosing `startPath`.
 *
 * Walks up from `startPath` (a file or directory — it need not exist beyond
 * its nearest existing ancestor) looking for a `.git` entry, reads the origin
 * remote, and normalizes it. Returns:
 *   - `host/owner/repo` when an origin remote is found (the portable key);
 *   - `local/<repo-folder>` when the repo has NO remote (degenerate, machine-
 *     local — better than nothing, clearly marked so it can't collide);
 *   - null when `startPath` isn't inside a git repo (→ no project scoping).
 *
 * `maxDepth` bounds the walk so a pathological path can't spin.
 */
export function projectKeyForPath(startPath, { maxDepth = 64 } = {}) {
  if (typeof startPath !== 'string' || startPath.length === 0) return null;
  let dir = resolve(startPath);
  // If the path points at a file (or a not-yet-existing file), start from its
  // directory. We don't require the leaf to exist — only that we can climb.
  try {
    if (existsSync(dir) && statSync(dir).isFile()) dir = dirname(dir);
  } catch {
    dir = dirname(dir);
  }

  for (let i = 0; i < maxDepth; i++) {
    const gitEntry = join(dir, '.git');
    if (existsSync(gitEntry)) {
      const cfg = configPathFromGitEntry(gitEntry);
      if (cfg) {
        const url = originUrlFromConfig(readFileSafe(cfg));
        const key = normalizeRemoteUrl(url);
        if (key) return key;
      }
      // Inside a git repo but no usable origin remote → machine-local fallback.
      return `local/${basename(dir).toLowerCase()}`;
    }
    const parent = dirname(dir);
    if (parent === dir) break; // reached filesystem root
    dir = parent;
  }
  return null;
}

/**
 * Resolve a file path to a sticky-note ANCHOR: { repo_key, rel_path }. Same
 * git-root walk as projectKeyForPath, but also captures the repo ROOT so the
 * path is stored REPO-RELATIVE — portable to console + other checkouts, unlike
 * this machine's absolute path. Write-time and read-time both call this, so the
 * keying matches exactly. Not in a git repo → { repo_key: null, rel_path:
 * <absolute> } (still usable locally on this machine, just not portable).
 */
export function anchorForPath(startPath, { maxDepth = 64 } = {}) {
  if (typeof startPath !== 'string' || startPath.length === 0) return null;
  const fileAbs = resolve(startPath);
  let dir = fileAbs;
  try {
    if (existsSync(dir) && statSync(dir).isFile()) dir = dirname(dir);
  } catch {
    dir = dirname(dir);
  }
  for (let i = 0; i < maxDepth; i++) {
    const gitEntry = join(dir, '.git');
    if (existsSync(gitEntry)) {
      const cfg = configPathFromGitEntry(gitEntry);
      let key = cfg ? normalizeRemoteUrl(originUrlFromConfig(readFileSafe(cfg))) : null;
      if (!key) key = `local/${basename(dir).toLowerCase()}`;
      const rel = relative(dir, fileAbs).split(sep).join('/');
      return { repo_key: key, rel_path: rel || basename(fileAbs) };
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { repo_key: null, rel_path: fileAbs };
}

function readFileSafe(p) {
  try {
    return readFileSync(p, 'utf-8');
  } catch {
    return '';
  }
}

/**
 * Extract the filesystem path a tool is about to act on, from its tool_input.
 * This is the signal that makes project memory FOLLOW THE WORK rather than the
 * session cwd: Read/Edit/Write carry `file_path`, Glob/Grep/LS carry `path`,
 * notebooks carry `notebook_path`, and Bash carries a `command` we best-effort
 * scan for a `cd <dir>` target or the first absolute path. Returns null when no
 * path is discernible (→ caller falls back to cwd / sticky).
 */
export function operativePathFromToolInput(toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return null;
  if (typeof toolInput.file_path === 'string' && toolInput.file_path) return toolInput.file_path;
  if (typeof toolInput.notebook_path === 'string' && toolInput.notebook_path) return toolInput.notebook_path;
  if (typeof toolInput.path === 'string' && toolInput.path) return toolInput.path;
  if (typeof toolInput.command === 'string' && toolInput.command) {
    // `cd /abs/dir && …` — the strongest signal of where work is happening.
    const cd = toolInput.command.match(/\bcd\s+"?(\/[^"\s&|;]+)/);
    if (cd) return cd[1];
    // Otherwise the first absolute path token in the command.
    const abs = toolInput.command.match(/(?:^|\s)(\/[^\s"'&|;:]+)/);
    if (abs) return abs[1];
  }
  return null;
}
