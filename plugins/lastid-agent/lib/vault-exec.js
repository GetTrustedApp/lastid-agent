/**
 * CLI credential proxy — spawn a child process with a vault secret injected as
 * env vars, STREAM its output back (scrubbed), and never let the secret reach
 * the agent. Runs INSIDE the listener (same trust boundary as http_fetch). Pure
 * of sockets + crypto: the spawn is dependency-injected so the whole flow is
 * unit-tested without a real child or unix socket.
 *
 * Three pieces:
 *   buildChildEnv   — the child's env: a strict allowlist (NOT the listener's
 *                     full env) plus the injected credential vars, overlaid last.
 *   makeStreamScrubber — exact-bytes secret redaction that survives chunk
 *                     boundaries (a secret split across two reads is still
 *                     caught) by holding back maxSecretLen-1 bytes between chunks.
 *   runChildStreaming — spawn, stream scrubbed stdout/stderr via callbacks, with
 *                     an output cap + timeout (SIGKILL), returning exit metadata.
 */

import { basename } from "node:path";

// Generic, non-secret base env a CLI commonly needs. Anything else is dropped —
// the child must NOT inherit the listener's full env (which may hold OTHER
// secrets). A share can add service-specific non-secret vars via env_allowlist
// (e.g. AWS_REGION). Injected credential vars are overlaid last and always win.
const BASE_ALLOW = new Set([
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "TZ", "TERM",
  "LANG", "TMPDIR", "TMP", "TEMP", "COLUMNS", "LINES",
  "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
  "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
]);
// Belt-and-suspenders: even an allowlisted/extra name that LOOKS like a secret
// is dropped from the inherited base (injected vars are exempt — they're the
// intended credential). Defends against a share allowlisting FOO_SECRET.
const SENSITIVE_NAME = /(?:_TOKEN|_KEY|_SECRET|_SECRETS|_PASSWORD|_PASSWD|_CREDENTIAL|_CREDENTIALS)$/i;

/**
 * Build the child's environment: allowlisted base vars (+ share extras) MINUS
 * anything that looks sensitive, then the injected credential vars overlaid last.
 * @param {Record<string,string>} baseEnv   typically process.env
 * @param {Record<string,string>} injectedEnv  from buildEnvInjection().env
 * @param {{ allowlist?: string[] }} [opts]  extra non-secret base var names
 */
export function buildChildEnv(baseEnv, injectedEnv, { allowlist = [] } = {}) {
  const allow = new Set(BASE_ALLOW);
  for (const name of Array.isArray(allowlist) ? allowlist : []) {
    if (typeof name === "string" && name) allow.add(name);
  }
  const out = {};
  for (const [k, v] of Object.entries(baseEnv || {})) {
    if (typeof v !== "string") continue;
    const keep = allow.has(k) || k.startsWith("LC_");
    if (keep && !SENSITIVE_NAME.test(k)) out[k] = v;
  }
  for (const [k, v] of Object.entries(injectedEnv || {})) {
    if (typeof k === "string" && k && typeof v === "string") out[k] = v;
  }
  return out;
}

/**
 * Streaming-safe exact-bytes secret scrubber. Replaces every literal secret in
 * the output with [redacted], INCLUDING occurrences split across chunk
 * boundaries: it scrubs the full pending buffer each push, then holds back the
 * last (maxSecretLen-1) bytes as carry so a secret straddling the next chunk is
 * matched when that chunk arrives. Operates on latin1 (1 byte = 1 char,
 * lossless for arbitrary bytes), so binary output is preserved.
 *
 * @param {string[]} secrets  literal secret values to redact
 * @returns {{ push(buf: Buffer): Buffer, flush(): Buffer }}
 */
export function makeStreamScrubber(secrets) {
  const lat = (Array.isArray(secrets) ? secrets : [])
    .filter((s) => typeof s === "string" && s.length > 0)
    .map((s) => Buffer.from(s, "utf8").toString("latin1"))
    // Longest-first so a secret that contains a shorter one is redacted whole.
    .sort((a, b) => b.length - a.length);
  const maxLen = lat.reduce((m, s) => Math.max(m, s.length), 0);
  const keep = Math.max(0, maxLen - 1);
  let pending = "";

  const replaceComplete = (s) => {
    for (const sec of lat) s = s.split(sec).join("[redacted]");
    return s;
  };

  return {
    push(buf) {
      pending = replaceComplete(pending + buf.toString("latin1"));
      if (pending.length <= keep) return Buffer.alloc(0);
      const emit = pending.slice(0, pending.length - keep);
      pending = pending.slice(pending.length - keep); // carry (already scrubbed)
      return Buffer.from(emit, "latin1");
    },
    flush() {
      const out = replaceComplete(pending);
      pending = "";
      return Buffer.from(out, "latin1");
    },
  };
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_OUTPUT_CAP = 10 * 1024 * 1024; // 10 MiB total across both streams

/**
 * Spawn argv[0] with the given env/cwd and stream scrubbed output via callbacks.
 * stdin is IGNORED (no interactive prompt can be fed an exfil command). Enforces
 * an overall timeout (SIGKILL) and a total-output cap (SIGKILL + truncated flag).
 * Resolves AFTER the carried scrub tails are flushed, with exit metadata only —
 * never any secret.
 *
 * @returns {Promise<{ exit_code:number|null, signal:string|null, timed_out:boolean, truncated:boolean, spawn_error?:string }>}
 */
export function runChildStreaming({
  argv,
  cwd,
  env,
  secrets = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  outputCapBytes = DEFAULT_OUTPUT_CAP,
  spawnImpl,
  onStdout,
  onStderr,
}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawnImpl(argv[0], argv.slice(1), {
        cwd: cwd || undefined,
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      resolve({ exit_code: null, signal: null, timed_out: false, truncated: false, spawn_error: e?.message ?? String(e) });
      return;
    }

    const scrubOut = makeStreamScrubber(secrets);
    const scrubErr = makeStreamScrubber(secrets);
    let total = 0;
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const pump = (scrub, emit) => (chunk) => {
      total += chunk.length;
      const safe = scrub.push(chunk);
      if (safe.length && typeof emit === "function") emit(safe);
      if (total > outputCapBytes && !truncated) {
        truncated = true;
        try { child.kill("SIGKILL"); } catch { /* already gone */ }
      }
    };
    child.stdout?.on("data", pump(scrubOut, onStdout));
    child.stderr?.on("data", pump(scrubErr, onStderr));

    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
    }, timeoutMs);

    const finish = (exitCode, signal, spawnErr) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const fo = scrubOut.flush();
      if (fo.length && typeof onStdout === "function") onStdout(fo);
      const fe = scrubErr.flush();
      if (fe.length && typeof onStderr === "function") onStderr(fe);
      resolve({
        exit_code: typeof exitCode === "number" ? exitCode : null,
        signal: signal ?? null,
        timed_out: timedOut,
        truncated,
        ...(spawnErr ? { spawn_error: spawnErr } : {}),
      });
    };

    child.on("error", (e) => finish(null, null, e?.message ?? String(e)));
    child.on("close", (code, signal) => finish(code, signal));
  });
}

/** basename of argv[0], for the binary-binding check. Exported for reuse/tests. */
export function commandBinary(argv) {
  const a0 = Array.isArray(argv) && typeof argv[0] === "string" ? argv[0] : "";
  return a0 ? basename(a0) : "";
}
