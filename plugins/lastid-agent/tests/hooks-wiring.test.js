/**
 * Hook-wiring regression. Two things silently broke the operator-facing
 * "working" status and must never regress:
 *
 *   1. hooks.json must register a `Stop` hook → before-stop.js. Without it the
 *      turn_end signal is never fired, so "working" lingers until the slow
 *      maxMs backstop instead of clearing at the end of the turn (the
 *      operator-reported bug: "working is not going away after you finish").
 *
 *   2. before-stop.js must be SELF-RUNNING — `node before-stop.js` (how
 *      hooks.json invokes it) must actually write the turn_end signal. It was
 *      a bare `export default async function` that defined a function and never
 *      called it, so even wiring it would have been a no-op.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(__dirname, '..');
const hooksJson = JSON.parse(readFileSync(join(PLUGIN_ROOT, 'hooks', 'hooks.json'), 'utf-8'));

/** All hook commands registered for a Claude Code event name. */
function commandsFor(eventName) {
  const groups = hooksJson.hooks?.[eventName] ?? [];
  return groups.flatMap((g) => (g.hooks ?? []).map((h) => h.command ?? ''));
}

test('REGRESSION: hooks.json registers a Stop hook → before-stop.js', () => {
  const cmds = commandsFor('Stop');
  assert.ok(cmds.length > 0, 'a Stop hook MUST be registered (clears "working" at turn-end)');
  assert.ok(
    cmds.some((c) => c.includes('before-stop.js')),
    `Stop must run before-stop.js; got: ${JSON.stringify(cmds)}`,
  );
});

test('POSITIVE: the other presence hooks are still wired', () => {
  assert.ok(
    commandsFor('PreToolUse').some((c) => c.includes('pre-tool-use.js')),
    'PreToolUse → pre-tool-use.js (the "sending"/typing signal)',
  );
  assert.ok(
    commandsFor('PostToolUse').some((c) => c.includes('post-tool-use.js')),
    'PostToolUse → post-tool-use.js (the "activity"/working keep-alive)',
  );
});

test('BEHAVIOR: running before-stop.js self-fires the turn_end signal', () => {
  const home = mkdtempSync(join(tmpdir(), 'lastid-hooktest-'));
  try {
    const res = spawnSync('node', [join(PLUGIN_ROOT, 'hooks', 'before-stop.js')], {
      encoding: 'utf-8',
      timeout: 10_000,
      // Redirect HOME so the signal lands in the temp dir; pin the scope.
      env: { ...process.env, HOME: home, LASTID_AGENT_SCOPE: 'test' },
    });
    assert.equal(res.status, 0, `hook must exit 0 (stderr: ${res.stderr})`);
    // SIGNALS.turn_end → basename 'presence-turn-end' under ~/.lastid-agent/<scope>/.
    const signalFile = join(home, '.lastid-agent', 'test', 'presence-turn-end');
    assert.ok(
      existsSync(signalFile),
      'before-stop.js MUST write the turn_end signal — not just define an unused export',
    );
    const ts = Number.parseInt(readFileSync(signalFile, 'utf-8').trim(), 10);
    assert.ok(Number.isFinite(ts) && ts > 0, 'turn_end signal holds a timestamp');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
