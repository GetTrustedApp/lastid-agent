# LastID agent — rules + memory wrap-up: continuation plan

**Goal:** finish the remaining rules + memory work, commit everything, then the
operator (matt) **reissues this agent** and live-tests memories + project
memories. After that we design the next phase: **vault-use + trusted access**
(the money-maker). Do NOT start vault/trusted-access until the wrap-up below is
done and the agent is reissued.

Repos are siblings under `/Users/matt/Documents/GitHub/LastID/`:
`lastid-agent-plugin` (this; branch `main`), `lastid-idp` (branch
`feature/identity-v2`), `lastid-sdk` (branch `main`), `lastid.co` (branch
`main`). The plugin package lives at `plugins/lastid-agent/`.

## Working agreements (from the operator — follow exactly)
- **Tests before done.** Every change ships with positive AND negative tests. Don't say "done" without them. `[mem_27962]`
- **Correct over expedient.** Slow down; don't rush — especially crypto/security. `[mem_ce30f]`
- **Find bugs on disk.** Never blame "not deployed"; own it. `[mem_1da38]`
- **Public/operator copy leads with a verb** the user can do; the "why" is one caveat line at most. `[mem_09992]`
- **Commits:** stage SPECIFIC paths, NEVER `git add -A`/`.` (shared checkouts). Commit/push only when asked. Plugin → push `main`, **no version bump** until the operator says ship (`npm run plugin:bump -- patch` then push). IdP → push `feature/identity-v2` (operator deploys). lastid.co → **commit, do NOT push**. lastid-sdk → push `main`.
- **wasm builds:** after changing `lastid-sdk/lastid-agent-wasm`, run `lastid-sdk/scripts/build-and-copy-agent-wasm.sh` (needs `wasm-pack`) — copies Node target → plugin `vendor/lastid-agent-wasm`, web target → `lastid.co/public/wasm`. Commit the rebuilt artifacts (plugin push; lastid.co commit-no-push).
- **Gotcha:** the operator's LIVE shell rules block authoring strings like `git stash`/`--force`/`--no-verify` when they appear in a *Bash command* (e.g. a heredoc). Use the Write/Edit tools (file edits aren't shell-scoped) and neutral test tokens, not shell heredocs, when a file's content contains rule trigger strings.

## What's DONE this session (committed + pushed, tested)
Plugin tests: **292 green** (`node --test tests/*.test.js`). IdP: `npx tsc --noEmit` clean + jest unit tests. Rust: `cargo test -p lastid-identity`.

- **Doorbell fix** — single-instance listener lock (two listeners raced the shared cursor). Plugin shipped **v0.8.27** (`cde77fa`).
- **Project-tier memories (Option B)** — shared across an operator's agents, scoped to a git remote, injected only when working in that repo. SDK (`ec8a0cf`), IdP (`a9c139b4`), plugin (`2014c8a`).
- **Curated rule packs** — versioned JSON single source `plugins/lastid-agent/data/rule-packs.json` (7 packs, ~33 rules); `lib/rule-packs.js` loader + `publishableRuleContent()`; full selector-category coverage; matcher surfaces curated provenance. Plugin `976ab54`.
- **All memories signed + fail-closed verified** — agent signs every write (EdDSA), gate is fail-closed for rules AND memories. Plugin `6c35e51`, IdP `f99e95ad`.
- **TOFU delegation-key pin** — pin the operator delegation key on first sync, verify against the pinned key thereafter. Plugin `c73fa91`.
- **Rule-hit metrics (backend)** — record on fire → ship best-effort → two-tier IdP store (private per-rule + anonymized curated aggregate) + endpoints. Plugin `2eee640`, IdP `d3b04568`.

## Locked decisions (do NOT re-litigate)
- Project memories = **Option B**: one shared encrypted record (not per-agent fan-out). Content key = `HKDF(project_root_seed, salt=routing_id)`; routing_id = `HMAC(project_root_seed, project_key)` (the IdP stores the opaque routing_id, never the repo name). `project_root_seed = HKDF(ai_agent_seed)` — derived, not stored, NO BIP85 tree change (`lastid-identity/src/v2.rs::derive_project_memory_root_seed`), sealed to each agent at provisioning.
- Project key = **normalized git remote** (machine-independent). Resolved per-tool-call from the operative path (injection follows the WORK, not session cwd).
- Packs live in **lastid.co** (the interface). "Enabling" = the operator **signs** each pack rule with `delegation_authority` and **publishes** via the existing operator-rule path; agents just receive synced signed rules. No agent-side "enable".
- Capabilities: agents write `agent` + `project` by default under the existing `memory:write` grant; **no `memory:write:project`**; `global` is the high bar (agent global writes are draft-for-promote via fan-out). (Operator decided — no per-tier cap code.)
- Memory metrics tiers: PRIVATE per-rule (operator's own) + CURATED-PACK aggregate (anonymized, shared with LastID).
- `#24` (capability-scoped enforcement + registry-anchored delegation-key verification) is **deferred to the vault/trusted-access phase**, NOT the wrap-up.

## REMAINING before reissue — both in lastid.co (+ one Rust/WASM piece)

### Task #22 — curated-pack console UX (lastid.co)
The pack data + contracts already exist in the plugin. The browser work:
1. **Pack data in lastid.co.** Copy/import `plugins/lastid-agent/data/rule-packs.json` into lastid.co (e.g. `src/lib/rule-packs.ts` or a fetched asset). Keep ONE source of truth: add a plugin test (or CI check) that the lastid.co copy matches `data/rule-packs.json` so "tested == shipped" survives (the plugin's `tests/rule-packs.test.js` validates every rule's pattern through the real matcher — keep that authoritative).
2. **Console UI** at `lastid.co/src/app/console/rules/` (mirror the memory page `console/memory/page.tsx`): empty-state surfaces the packs (don't make operators guess); search by name/summary/tags; collapsed list shows name + summary + tags + rule count; expand shows `why` + each rule + its `examples` ("what it catches/ignores"). Lead copy with a verb. `[mem_09992]`
3. **Enable = sign + publish.** Enable a whole pack OR a single rule → for each rule call `lastid.co/src/lib/agent-state.ts` publishRule (it already signs the canonical record with `delegation_authority` via `wasm.sdkSignAgentStateRecord` and POSTs per-agent copies). Publish `publishableRuleContent(rule, pack)` — enforcement fields + `{curated:true, pack, rule, pack_version}`. Confirm the matcher already carries `curated`/`pack` provenance through (it does: `operator-store.matchRules`).
4. **Fork-on-edit + edit-capture.** Editing a curated rule flips it to the operator's own (`curated:false`) AND captures the edit (the diff vs the curated original) so LastID can improve packs. Decide capture sink: simplest = a field on the published record (`forked_from: {pack, rule, pack_version}`) + the edit shipped to an IdP endpoint for LastID review. Add the IdP endpoint if needed.
5. **Version rollout.** When a pack's `version` > the operator's enabled `pack_version` (and they haven't forked), surface "update available" + re-publish the new rule content.
6. **Metrics display.** Read `GET /v1/agent-state/rule-metrics` (operator) → show per-rule hit count + `last_hit_at` in the list. (Endpoint + store DONE this session.)

### Task #20 — attribution + browser project authoring (lastid.co + Rust/WASM)
- **9a attribution (smaller):** the console memory list shows a generic "from agent" badge. Show WHICH agent. The IdP returns `author` + `author_agent_did` (project records) / `for_agent_did` (operator authored view). lastid.co should resolve the agent DID → a friendly name via the **agent registry** (there's an agent list/registry the operator owns) and render it. Files: IdP `agent-state.ts` `toWire`/`listForOperator` already carry author info; thread `author_agent_did` into `lastid.co/src/lib/agent-state.ts` `MemoryContent`/`StoredMemory`; resolve+render in `console/memory/page.tsx` (replace the generic "from agent").
- **9b browser project authoring (needs Rust/WASM):** let the operator author a project memory in the browser. The web wallet has `ai_agent_seed`; it must derive `project_root_seed`, compute `routing_id`, and encrypt under the project content key — the SAME crypto as the agent (`plugins/lastid-agent/lib/project-crypto.js` + `lib/project-key.js`). **Export to WASM** (`lastid-sdk/lastid-agent-wasm`): `derive_project_memory_root_seed` (already in `v2.rs`; add a `#[wasm_bindgen]` wrapper), plus a project routing-id (HMAC) + project content encrypt (port `project-crypto.js`'s `deriveProjectRoutingId` / `deriveProjectContentKey` / `encryptProjectContent` to Rust, or expose equivalents) so lastid.co produces a record byte-compatible with the agent's `decryptProjectContent`. Then UI: pick a repo (from agents' reported project_keys or a manual git remote) → POST `target:'project'` + `routing_id` + `enc_b64` + `sig` (operator signs with delegation_authority OR the browser signs as the operator). The IdP project-write branch already accepts it. Rebuild+copy wasm (script above). **Round-trip test mandatory:** a project memory authored in the browser must decode + verify on the agent (mirror `plugins/lastid-agent/tests/memory-project-sync.test.js`).

## Key contracts a fresh session needs
- `plugins/lastid-agent/lib/rule-packs.js` → `RULE_PACKS`, `publishableRuleContent(rule, pack)`, `allPackRules()`. Pack JSON shape in `data/rule-packs.json` (per-pack `version`; each rule `{id, tool, pattern, is_regex, severity, replacement?, reason, examples:{hit, also_hits?, miss}}`).
- Tool categories + mapping: `lib/tool-taxonomy.js` (`canonicalTool`, `CANONICAL_TOOLS`). Rule matcher: `lib/operator-store.js` (`matchRules`, `policyDecision`, `compileRulePattern`, `applyRewrite`). PreToolUse hook: `hooks/pre-tool-use.js`.
- Memory signing/verify: `lib/agent-sig-verify.js` (`verifyRecordSignature` fail-closed; `signAgentRecordJws`; `agentEd25519PublicKeyFromDid`). Publish: `lib/agent-memory-publish.js`. Sync: `lib/agent-state-sync.js` (TOFU pin via `operator-store.pinnedDelegationJwk`).
- Metrics: plugin `lib/rule-metrics.js` + `lib/rule-metrics-ship.js`; IdP `src/services/agent/rule-metrics-store.ts` + routes in `src/api/agents/agent-state.ts` (`POST /rule-hits`, `GET /rule-metrics`).
- Project crypto: `lib/project-crypto.js`, `lib/project-key.js`, `lib/project-sticky.js`. Provisioning seed: `v2.rs::derive_project_memory_root_seed`, sealed in `lastid-runtime/src/agent_provisioning_runtime.rs` + `lastid-agent-wasm/src/lib.rs`; unsealed in `lib/agent-provisioning.js` → `lib/keychain.js` (`SERVICE_PROJECT_ROOT_SEED`).

## After the wrap-up
Operator reissues this agent (delivers `project_root_seed`) → agent live-writes memories + project memories. Then design **vault-use + trusted access** (includes `#24`: capability-scoped tool enforcement + registry-anchored delegation-key verification — see task #24).
