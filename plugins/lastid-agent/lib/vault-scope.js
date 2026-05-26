/**
 * Vault-use SCOPE map — the working-context identity that a share's
 * `scope_required` constraints match against.
 *
 * The operator scopes a credential to a project/repo in the console
 * ({ type: 'scope_required', name: 'repo', value: 'github.com/owner/repo' }).
 * The agent must SEND where it is working at vault_use time, or the listener's
 * policy evaluator (vault-policy.js: scope_required reads ctx.scope[name]) can
 * never satisfy the constraint — a scoped share would ALWAYS deny. The desktop
 * sent a signed SessionFingerprint for exactly this; the SaaS port dropped it,
 * so scoped credentials silently broke. This rebuilds the scope map locally.
 *
 * Keys a constraint `name` may select:
 *   - repo        normalized git remote `host/owner/repo` (the headline, human-
 *                 authorable scope — SAME identity memories key on). Sourced
 *                 from the sticky last-project (updated as the agent works, so
 *                 reliable even when the MCP server's cwd is the launch dir),
 *                 falling back to normalizing this cwd's origin.
 *   - git_remote  raw `git remote get-url origin` (desktop parity)
 *   - git_commit  HEAD sha
 *   - cwd         SHA-256 of the absolute cwd
 *   - host        SHA-256 of the hostname
 *   - project     package-manifest hash (else cwd hash) — "did this project change"
 *
 * Null/absent signals are simply omitted (a constraint naming an absent key
 * fails closed in the evaluator, which is the safe default).
 */
import { computeProjectFingerprint } from './session-fingerprint.js';
import { readLastProject } from './project-sticky.js';
import { normalizeRemoteUrl } from './project-key.js';

export function buildVaultUseScope({
  scope = 'main',
  cwd = process.cwd(),
  readProject = readLastProject,
  fingerprint = computeProjectFingerprint,
} = {}) {
  const out = {};

  // Live repo identity: prefer the sticky last-project (the repo the agent has
  // actually been touching this session); fall back to normalizing this cwd's
  // git origin so a fresh session still scopes correctly.
  let repo = null;
  try {
    repo = readProject(scope) || null;
  } catch {
    repo = null;
  }

  let fp = {};
  try {
    fp = fingerprint(cwd) || {};
  } catch {
    fp = {};
  }

  if (!repo && typeof fp.git_remote === 'string') {
    try {
      repo = normalizeRemoteUrl(fp.git_remote) || null;
    } catch {
      repo = null;
    }
  }

  if (repo) out.repo = repo;
  if (fp.git_remote) out.git_remote = fp.git_remote;
  if (fp.head_commit_sha) out.git_commit = fp.head_commit_sha;
  if (fp.cwd_hash) out.cwd = fp.cwd_hash;
  if (fp.host_machine_id) out.host = fp.host_machine_id;
  if (fp.package_root_hash || fp.cwd_hash) out.project = fp.package_root_hash || fp.cwd_hash;
  return out;
}
