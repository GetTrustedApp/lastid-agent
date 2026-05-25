/**
 * Curated rule packs — cross-repo parity guard.
 *
 * data/rule-packs.json is the ONE source of truth. The browser console
 * (lastid.co) ships a verbatim copy at src/lib/rule-packs.json so it can
 * display/search/enable the same packs the agent enforces — but a copy can
 * drift. This test fails the build if the lastid.co copy is not byte-for-byte
 * semantically identical to ours, so "tested == shipped == enabled" holds:
 * rule-packs.test.js proves every rule fires; this proves the copy operators
 * enable in the browser is that exact, tested set.
 *
 * lastid.co has no test runner of its own, so the guarantee lives here. When
 * the sibling checkout isn't present (e.g. the plugin built in isolation), the
 * test SKIPS loudly rather than passing silently — any environment with both
 * repos (local dev, the LastID monorepo CI) enforces parity.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const OURS = fileURLToPath(new URL('../data/rule-packs.json', import.meta.url));
// tests/ -> lastid-agent/ -> plugins/ -> lastid-agent-plugin/ -> LastID/ -> lastid.co/...
const SIBLING = fileURLToPath(
  new URL('../../../../lastid.co/src/lib/rule-packs.json', import.meta.url),
);

test('lastid.co rule-packs.json is byte-parity with data/rule-packs.json', { skip: existsSync(SIBLING) ? false : 'lastid.co sibling checkout not present — parity not enforced here' }, () => {
  const ours = JSON.parse(readFileSync(OURS, 'utf-8'));
  const sibling = JSON.parse(readFileSync(SIBLING, 'utf-8'));
  // Semantic deep-equal (tolerant of trailing-newline/whitespace formatting)
  // — but the canonical re-serialization below ALSO catches key reordering.
  assert.deepEqual(
    sibling,
    ours,
    'lastid.co/src/lib/rule-packs.json drifted from plugin data/rule-packs.json — re-copy it (cp the plugin file into lastid.co).',
  );
  assert.equal(
    JSON.stringify(sibling),
    JSON.stringify(ours),
    'lastid.co copy differs in key order / canonical form — re-copy the plugin file verbatim.',
  );
});
