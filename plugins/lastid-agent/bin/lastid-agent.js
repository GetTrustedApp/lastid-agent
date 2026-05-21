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
 *   2. If `node_modules/qrcode-terminal` is missing, runs
 *      `npm install --omit=dev --no-audit --no-fund --silent` once in
 *      that directory.
 *   3. Dynamically imports `lib/cli.js`, which does the real work with
 *      its static imports now resolvable.
 *
 * Kept tiny and dependency-free so it can run before any deps exist.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pluginRoot = join(__dirname, '..');

const sentinel = join(pluginRoot, 'node_modules', 'qrcode-terminal', 'package.json');
if (!existsSync(sentinel)) {
  process.stderr.write(
    '[lastid-agent] installing dependencies (one-time, ~10s)…\n',
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
