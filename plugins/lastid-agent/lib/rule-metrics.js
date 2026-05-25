/**
 * Rule-hit metrics — local recorder + ship queue.
 *
 * When a rule fires (PreToolUse deny/warn/rewrite, or an inbound redact), the
 * hook appends a hit here — a fast, local, append-only line. The listener ships
 * unshipped hits to the IdP best-effort (ship cursor only advances on a 2xx),
 * so recording never blocks the tool-call latency path and a down IdP just
 * means a longer queue.
 *
 * The payload carries NO sensitive content — only the rule id, severity, tool
 * category, and (for curated-pack rules) the pack + rule id so the IdP can keep
 * a private per-rule count AND an anonymized curated-pack aggregate. The matched
 * command/pattern text is never recorded.
 *
 * Append at ~/.lastid-agent/<scope>/rule-metrics.jsonl; cursor in
 * rule-metrics-cursor.json.
 */
import { readFileSync, appendFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

export function ruleMetricsPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'rule-metrics.jsonl');
}
function cursorPath(scope = 'main') {
  return join(homedir(), '.lastid-agent', scope ?? 'main', 'rule-metrics-cursor.json');
}

/**
 * Record one rule fire. Best-effort + fast (a single append). Returns true if
 * written. `curated` + `pack` + `rule` are present only for curated-pack rules
 * (so the IdP can increment the shared aggregate, not just the private count).
 */
export function recordRuleHit({
  scope = 'main',
  ruleId,
  severity,
  tool = null,
  curated = false,
  pack = null,
  rule = null,
  at = Date.now(),
} = {}) {
  if (!ruleId || !severity) return false;
  const entry = {
    rule_id: ruleId,
    severity,
    tool: tool || null,
    ...(curated ? { curated: true, pack: pack ?? null, rule: rule ?? null } : {}),
    at,
  };
  try {
    const p = ruleMetricsPath(scope);
    mkdirSync(dirname(p), { recursive: true });
    appendFileSync(p, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

/** All recorded hits (parsed; malformed lines dropped). */
export function readRuleHits(scope = 'main') {
  try {
    return readFileSync(ruleMetricsPath(scope), 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function readCursor(scope) {
  try {
    const n = Number(JSON.parse(readFileSync(cursorPath(scope), 'utf8'))?.shipped);
    return Number.isFinite(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
}
function writeCursor(scope, shipped) {
  try {
    const p = cursorPath(scope);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify({ shipped }), { mode: 0o600 });
  } catch {
    /* best-effort */
  }
}

/** Hits not yet shipped to the IdP. */
export function unshippedHits(scope = 'main') {
  return readRuleHits(scope).slice(readCursor(scope));
}

/**
 * Ship unshipped hits via `sendFn(records) => boolean`. Advances the ship
 * cursor only on a truthy result, so a failed/again-offline send just retries
 * next time. Returns the count shipped (0 if nothing pending or send failed).
 */
export async function shipRuleHits(scope = 'main', sendFn) {
  const all = readRuleHits(scope);
  const pending = all.slice(readCursor(scope));
  if (pending.length === 0) return 0;
  let ok = false;
  try {
    ok = await sendFn(pending);
  } catch {
    ok = false;
  }
  if (ok) {
    writeCursor(scope, all.length);
    return pending.length;
  }
  return 0;
}
