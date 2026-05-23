#!/usr/bin/env node
/**
 * UserPromptSubmit clock hook.
 *
 * Injects the operator's current local time + date into the agent's
 * context on every prompt. Cheap, deterministic, never blocks the
 * user — local clock read + JSON.stringify, no network, no I/O.
 *
 * Why a separate hook from `user-prompt-submit.js`:
 *   - The memory-retrieve hook may soft-fail (desktop unavailable,
 *     no memories) and exit 0 with no output. The clock should
 *     STILL fire on those turns — most useful context the agent
 *     can have when the operator says "by tomorrow" or
 *     "after lunch." Splitting keeps the two reliabilities
 *     independent.
 *   - Time budget is microseconds vs the memory hook's ~1.8s
 *     desktop round-trip; declaring as a separate hook entry
 *     lets the runtime apply a much tighter timeout.
 *
 * Output shape mirrors the existing memory hook: a JSON object on
 * stdout with `hookSpecificOutput.additionalContext` carrying a
 * short Markdown block the runtime injects into the next-turn
 * context window.
 */

// Locale resolution: respect $LANG / Intl defaults so the operator
// sees the same date format their OS uses. Defensive fallback to
// `en-US` if the environment doesn't expose a usable locale (e.g.
// stripped CI containers).
const localeCandidates = [
  process.env.LC_ALL,
  process.env.LC_TIME,
  process.env.LANG,
]
  .map((s) => (typeof s === 'string' ? s.split('.')[0]?.replace('_', '-') : null))
  .filter((s) => s && /^[a-zA-Z-]+$/.test(s));
const locale = localeCandidates[0] ?? 'en-US';

const now = new Date();
let timeStr;
let dateStr;
let tz;
try {
  // Operator's system tz; passing `undefined` to toLocaleString uses
  // the host default, which is what we want here.
  timeStr = now.toLocaleTimeString(locale, {
    hour: 'numeric',
    minute: '2-digit',
    hour12: undefined,
  });
  dateStr = now.toLocaleDateString(locale, {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  // `resolvedOptions` is the only portable way to read the host tz
  // name. Wrap in try/catch because some minimal Node builds elide
  // Intl data.
  tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? 'unknown';
} catch (_err) {
  // Fall back to ISO if the locale lookups choke. Still useful.
  timeStr = now.toISOString().slice(11, 16);
  dateStr = now.toISOString().slice(0, 10);
  tz = 'UTC';
}

const additionalContext =
  `<clock>\n` +
  `Local time: ${timeStr} (${tz})\n` +
  `Date: ${dateStr}\n` +
  `ISO: ${now.toISOString()}\n` +
  `</clock>`;

process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext,
    },
  }),
);
process.exit(0);
