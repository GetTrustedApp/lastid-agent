/**
 * SessionFingerprint — agent-signed environment claim.
 *
 * The agent computes a ProjectFingerprint at the start of every MCP
 * session, signs it with its stable Ed25519 key, and ships the signed
 * envelope in the body of `POST /session`. The desktop verifies the
 * signature, asserts the inner agent_did matches the VC's sub, and
 * caches the verified ProjectFingerprint on the bearer-token-backed
 * AgentSession. Per-call vault_use evaluation reads the cached
 * fingerprint for `Constraint::ScopeRequired` enforcement.
 *
 * What goes in the fingerprint:
 *   - cwd_hash:           SHA-256 of the absolute, normalized cwd
 *   - host_machine_id:    SHA-256 of os.hostname() (stable per host)
 *   - git_remote:         best-effort `git -C <cwd> remote get-url origin`
 *   - head_commit_sha:    best-effort `git -C <cwd> rev-parse HEAD`
 *   - package_root_hash:  best-effort SHA-256 over package.json /
 *                         Cargo.toml / pyproject.toml top-of-file bytes
 *                         (whichever is present, in that order)
 *
 * Anything best-effort that fails resolves to `null`. The point isn't
 * forensic certainty — it's a stable scope key the desktop can compare
 * against scope-bound share constraints. False negatives are surfaced
 * as policy `Deny`, not silently accepted.
 *
 * Canonical bytes for the signature are computed Rust-side
 * (`serde_json_canonicalizer` per RFC 8785). The JS surface only
 * builds the unsigned object; the wasm `signSessionFingerprint` call
 * produces the signed copy.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

function sha256B64u(buf) {
  return createHash('sha256').update(buf).digest('base64url');
}

function safeGit(cwd, args) {
  try {
    const res = spawnSync('git', ['-C', cwd, ...args], {
      encoding: 'utf-8',
      timeout: 1500,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (res.status !== 0) return null;
    const out = res.stdout.trim();
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
}

function packageRootHash(cwd) {
  // First marker wins. We hash the file's raw bytes — not its parsed
  // semantics. The point is "did this project change?" not "is the
  // declared name a specific value?".
  const candidates = ['package.json', 'Cargo.toml', 'pyproject.toml'];
  for (const f of candidates) {
    try {
      const bytes = readFileSync(join(cwd, f));
      return sha256B64u(bytes);
    } catch {
      // try next
    }
  }
  return null;
}

/**
 * Build a ProjectFingerprint for the given cwd. Returns the plain
 * object shape the wasm bridge accepts.
 */
export function computeProjectFingerprint(cwd) {
  const abs = resolve(cwd);
  const cwdHash = sha256B64u(Buffer.from(abs, 'utf-8'));
  const hostMachineId = sha256B64u(Buffer.from(hostname(), 'utf-8'));
  const gitRemote = safeGit(abs, ['remote', 'get-url', 'origin']);
  const headCommitSha = safeGit(abs, ['rev-parse', 'HEAD']);
  const pkgRoot = packageRootHash(abs);
  return {
    cwd_hash: cwdHash,
    host_machine_id: hostMachineId,
    git_remote: gitRemote,
    head_commit_sha: headCommitSha,
    package_root_hash: pkgRoot,
  };
}

/**
 * Build the unsigned SessionFingerprint shape expected by the wasm
 * `signSessionFingerprint` wrapper. The wasm side fills the
 * `signature` field; everything else is the agent's job.
 *
 * `parentSessionId` is null for top-level sessions and set to the
 * parent session's id for sub-agent sessions.
 */
export function buildUnsignedSessionFingerprint({
  agentDid,
  cwd,
  parentSessionId = null,
}) {
  const nowMs = Date.now();
  return {
    session_id: randomUUID(),
    agent_did: agentDid,
    project: computeProjectFingerprint(cwd),
    started_at_ms: nowMs,
    signed_at_ms: nowMs,
    parent_session_id: parentSessionId,
    signature: '',
  };
}
