/**
 * Curated LastID rule packs — loader over the single source of truth,
 * data/rule-packs.json.
 *
 * The JSON is the ONE definition consumed by everything: the plugin tests
 * validate it (so "tested" == what ships), and the browser console imports the
 * same JSON to display/search/enable/publish (so "shipped" == "what the
 * operator enables"). No drift between tested and live.
 *
 * Versioning: each pack carries a `version`. When LastID changes a pack, bump
 * its version; operators who enabled an older version see an update they can
 * roll out (the published rule records its pack + pack_version — see
 * publishableRuleContent). An operator who EDITS a curated rule forks it to
 * their own (curated:false) and is no longer auto-updated.
 *
 * Each rule ships `examples: { hit, also_hits?, miss }` — inputs it MUST catch
 * / ignore. tests/rule-packs.test.js runs them through the real matcher so a
 * dead regex fails the build; the examples also drive the "what it catches"
 * preview in the console.
 */
import { readFileSync } from 'node:fs';

const DATA = JSON.parse(
  readFileSync(new URL('../data/rule-packs.json', import.meta.url), 'utf-8'),
);

/** Schema/format version of the pack file as a whole. */
export const RULE_PACKS_FORMAT_VERSION = DATA.format_version;

/** All packs (each with id, version, name, summary, why, tags, rules). */
export const RULE_PACKS = DATA.packs;

/** Flat list: every rule with its pack id + pack version attached. */
export function allPackRules() {
  return RULE_PACKS.flatMap((p) =>
    p.rules.map((r) => ({ ...r, pack: p.id, pack_version: p.version })),
  );
}

/**
 * The EXACT rule content published when an operator enables a curated rule.
 * This is the contract shared with the browser's enable/publish flow: the
 * enforcement fields (tool/pattern/is_regex/severity/replacement/reason) plus
 * curated provenance (pack + rule id + pack_version) so the rule can be:
 *   - attributed in the console ("curated · supply-chain-firewall"),
 *   - metered as a curated-pack hit (cumulative, shared) vs a private rule,
 *   - offered an update when its pack_version is behind the current pack,
 *   - and forked to the operator's own (curated:false) the moment they edit it.
 * Excludes display-only metadata (examples). Pure — testable.
 */
export function publishableRuleContent(rule, pack) {
  return {
    tool: rule.tool,
    pattern: rule.pattern,
    is_regex: rule.is_regex === true,
    severity: rule.severity,
    ...(rule.replacement !== undefined ? { replacement: rule.replacement } : {}),
    reason: rule.reason,
    curated: true,
    pack: pack.id,
    rule: rule.id,
    pack_version: pack.version,
  };
}
