/**
 * Curated rule packs — lineage / rename safety guard.
 *
 * Background: a pack-version bump that rotated rule ids (V1→V2 sfw-*)
 * silently orphaned operators' existing enablements. The fix in the
 * console (lastid.co/src/lib/agent-state.ts resolveEnabledForPack) has
 * three layers — strict, lineage via `renamed_from[]`, then content
 * fingerprint fallback. Lineage is the deterministic path WE ship
 * when WE rename a rule. This test catches the ways an authored
 * `renamed_from` could go wrong BEFORE the pack reaches an operator.
 *
 * Invariants enforced here (per pack):
 *
 *   1. No `renamed_from` entry collides with another current rule's id
 *      in the same pack — that would make lineage ambiguous (does
 *      "old-id" mean "use the rule that still has it" or "treat the
 *      rule that lists it as the new home"?).
 *
 *   2. No two current rules in the same pack claim the same old id
 *      via `renamed_from` — only one current rule can be the
 *      successor of a given prior id.
 *
 *   3. No rule lists its OWN current id in `renamed_from` (paranoia).
 *
 * These are cheap, structural; they catch authoring slips without
 * requiring a snapshot of prior pack versions on disk.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PACKS_PATH = fileURLToPath(new URL('../data/rule-packs.json', import.meta.url));

test('rule packs — renamed_from lineage is unambiguous', () => {
  const { packs } = JSON.parse(readFileSync(PACKS_PATH, 'utf-8'));
  for (const pack of packs) {
    const currentIds = new Set(pack.rules.map((r) => r.id));
    const claimedBy = new Map(); // oldId -> currentRule.id

    for (const rule of pack.rules) {
      const lineage = rule.renamed_from ?? [];
      for (const oldId of lineage) {
        assert.notEqual(
          oldId,
          rule.id,
          `pack "${pack.id}": rule "${rule.id}" lists itself in renamed_from — drop it.`,
        );
        assert.ok(
          !currentIds.has(oldId),
          `pack "${pack.id}": rule "${rule.id}" claims renamed_from "${oldId}", but a current rule with that id still exists in the pack — lineage is ambiguous.`,
        );
        const prior = claimedBy.get(oldId);
        assert.ok(
          prior === undefined,
          `pack "${pack.id}": both "${prior}" and "${rule.id}" claim renamed_from "${oldId}" — only one rule can succeed a prior id.`,
        );
        claimedBy.set(oldId, rule.id);
      }
    }
  }
});
