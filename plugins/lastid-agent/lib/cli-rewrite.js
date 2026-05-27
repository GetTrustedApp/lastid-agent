/**
 * Transparent CLI credential proxy rewrite (Phase 2): decide whether a Bash
 * command should be rewritten to run under `lastid-agent run`, injecting a
 * bound vault credential as env. PURE — the PreToolUse hook supplies the command
 * + the (non-secret) binding index, this returns the plan. Mirrors the
 * socket-firewall rewrite shape (`aws …` → wrapped form).
 *
 * SAFETY: we only rewrite a SIMPLE command whose leading token is the bound
 * binary — no pipes / `&&` / `;` / redirects / command substitution / leading
 * env assignments. Those make a naive prefix-wrap mis-scope (only the first
 * segment would get the credential) and are an injection-evasion surface, so we
 * leave them alone (the agent can call `lastid-agent run` explicitly, or the
 * command simply runs un-credentialed and fails, which is safe).
 */
import { basename } from "node:path";

// Shell metacharacters that mean "not a single simple command".
const SHELL_OPS = /[|&;<>`\n]|\$\(/;

/** The basename of a simple command's leading binary, or null if the command
 *  isn't a single simple command (piped/compound/env-prefixed/empty). */
export function leadingBinary(command) {
  const cmd = String(command ?? "").trim();
  if (!cmd) return null;
  if (SHELL_OPS.test(cmd)) return null; // compound / piped / redirected / subshell
  if (/^\w+=/.test(cmd)) return null; // leading FOO=bar env assignment
  const argv0 = cmd.split(/\s+/)[0];
  if (!argv0 || argv0.includes("=")) return null;
  return basename(argv0);
}

/**
 * Plan a CLI-credential rewrite.
 * @param {string} command   the Bash command
 * @param {Array<{item_id:string,binaries:string[]}>} bindings  the non-secret index
 * @param {{ cliPath: string }} opts
 * @returns {null | { ambiguous:true, binary:string, items:string[] }
 *               | { rewritten:true, binary:string, item_id:string, command:string }}
 */
export function planCliRewrite(command, bindings, { cliPath } = {}) {
  const cmd = String(command ?? "");
  // Never re-wrap our own run invocation (no infinite loop).
  if (cmd.includes(" run --item ") || (cliPath && cmd.includes(cliPath))) return null;
  const bin = leadingBinary(cmd);
  if (!bin) return null;
  const items = [];
  for (const b of Array.isArray(bindings) ? bindings : []) {
    if (Array.isArray(b?.binaries) && b.binaries.includes(bin) && typeof b.item_id === "string") {
      items.push(b.item_id);
    }
  }
  if (items.length === 0) return null;
  if (items.length > 1) return { ambiguous: true, binary: bin, items };
  // Wrap: the agent's shell runs `lastid-agent run`, which mints a handle +
  // asks the listener to spawn the binary with the credential in its env.
  return {
    rewritten: true,
    binary: bin,
    item_id: items[0],
    command: `node ${JSON.stringify(cliPath)} run --item ${items[0]} -- ${cmd.trim()}`,
  };
}
