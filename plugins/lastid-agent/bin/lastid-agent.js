#!/usr/bin/env node
/**
 * lastid-agent — bootstrap entry point.
 *
 * Claude Code's marketplace install copies plugin contents into
 * `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/` but does
 * NOT run `npm install`, so on first run our `node_modules/` is empty.
 *
 * This file:
 *   1. Resolves the plugin root (the parent of `bin/`).
 *   2. Checks that EVERY declared dependency is present in `node_modules`.
 *      If ANY is missing, runs `npm install --omit=dev --no-audit
 *      --no-fund --silent` once in that directory.
 *   3. Dynamically imports `lib/cli.js`, which does the real work with
 *      its static imports now resolvable.
 *
 * Why check every dep (not a single sentinel): a single-package sentinel
 * (we used `qrcode-terminal`) skips the install on an existing install
 * that already has it — so a dep ADDED in a later version (this bit us
 * with `ws`, then `@noble/hashes`) never gets installed and its import
 * throws at runtime. Reading the dependency list straight from
 * package.json makes this self-maintaining: add a dep, it's covered.
 *
 * Kept tiny and dependency-free so it can run before any deps exist.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pluginRoot = join(__dirname, '..');

let requiredDeps = [];
try {
  const pkg = JSON.parse(readFileSync(join(pluginRoot, 'package.json'), 'utf8'));
  requiredDeps = Object.keys(pkg.dependencies ?? {});
} catch {
  // No/unreadable package.json — nothing to verify; fall through to import.
}
// A dep is present iff its own package.json resolves under node_modules.
// Handles scoped names (@scope/name) via path join.
const missingDeps = requiredDeps.filter(
  (dep) => !existsSync(join(pluginRoot, 'node_modules', ...dep.split('/'), 'package.json')),
);
if (missingDeps.length > 0) {
  process.stderr.write(
    `[lastid-agent] installing dependencies (${missingDeps.join(', ')})…\n`,
  );
  // CRITICAL: route npm's stdout to OUR stderr, not stdout.
  // Hooks (memory-retrieve, policy-check) parse stdout as JSON;
  // npm's "added N packages" lines would corrupt the parse and
  // the hook falls through its catch into fail-open (which is how
  // git stash slipped past the PreToolUse policy check on the very
  // first run after a clean install). `--silent` quiets most
  // chatter but the npm wrapper still prints summary lines. Belt-
  // and-suspenders: redirect at the stdio level so nothing npm
  // emits can land on our stdout, period.
  const result = spawnSync(
    'npm',
    ['install', '--omit=dev', '--no-audit', '--no-fund', '--silent'],
    {
      cwd: pluginRoot,
      stdio: ['ignore', process.stderr, process.stderr],
    },
  );
  if (result.status !== 0) {
    process.stderr.write(
      `[lastid-agent] dependency install failed (exit ${result.status ?? 'n/a'}). ` +
        `cd ${pluginRoot} && npm install --omit=dev\n`,
    );
    process.exit(result.status ?? 1);
  }
}

await import('../lib/cli.js');
