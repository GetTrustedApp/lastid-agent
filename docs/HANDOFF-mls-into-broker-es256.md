# HANDOFF — Move ALL MLS + crypto into the broker for ES256 agents

**Date:** 2026-06-09
**Author:** prior session (context-exhausted handoff)
**Governing memories** (full ULIDs — `lastid_memory_get` needs the FULL id, a prefix returns "no memory with id"; if you only have a prefix, use `lastid_memory_search`):
- `mem_01KTQK1EYYZCSCMK390WCJE5KH` — custody invariant
- `mem_01KTQNCQYW3DZR5GKJSK81CHZQ` — MLS-in-broker architecture (THE program)
- `mem_01KTQNZBM6J7WPYCR45HYNC9RE` — session-state / this handoff's open-loop
- `mem_01KTCAMMSG35S286N8MT3DRAHC` — Phase 3-5 broker-op reuse points
- `mem_01KTHKFGGYQSNAR6JVDBN5VRAW` — broker-native custody live-proven
- dual-algo + broker-sole-custody origin: search `lastid_memory_search` for "dual-algo agent identity" and "broker sole credential holder" (prefixes `mem_01KTAGN9…`, `mem_01KSWNT0…`)

---

## 0. The one-line goal

For **ES256 / P-256 (`zDn…`) agents**, the signed broker owns **all** MLS + crypto;
node is a thin non-key shell. Keys never transit node. Ed25519 (`z6Mk…`) legacy
agents keep the node path unchanged (**no-flag-day; discriminate by the agent DID
algo**, never by a feature flag).

Operator verbatim:
- "node should never have seed data ever with the broker active and that should be default with es256"
- "only thing that should be in node is es25519 agents [ed25519]"
- "all the mls etc should be in the broker for es256 - we should be minimizing node for those so that keys are handled properly all the time"
- "keypackage should be published inside the broker for p256"

---

## 1. What triggered this (the live bug, now root-caused)

The operator shared an AWS credential to a P-256 broker agent (`logdiver`). The
agent could not decrypt it: **"Unsupported state or unable to authenticate data."**

That string is the **exact** error `node:crypto` throws from `decipher.final()` on a
bad AES-GCM tag (`agent-content-crypto.js gcmDecrypt`). `openWithHandle` is wasm
(Rust) and the broker is Rust — both would throw different strings. So the failing
decrypt ran in **node's slot path** — which for a P-256 agent must never run.

**Root cause (verified on disk):** `keychain.js loadAgentVc` keyed custody off
`brokerNative: slotSeed === null` — i.e. *seed-presence*, not algo. A P-256 agent
that still had a (stale) seed sitting in the keychain was mis-classified as a legacy
node agent and handed a 32-byte `slotSeed`, so `decryptVaultEnvelope` took the
**node** path with a key that ≠ what the console sealed to → AEAD auth failure.

The fix is custody-**by-algo**: node uses seed material ONLY for Ed25519; every
P-256 agent gets `slotSeed: null` + `brokerNative: true` even if a stale seed is
physically present, so every downstream consumer routes to the broker.

---

## 2. What is DONE this session (the vault root-cause fix)

**Committed locally on `lastid-agent-plugin` branch `main` (HELD — do NOT push; see §7).**

| File | Change |
|---|---|
| `plugins/lastid-agent/lib/keychain.js` | New pure `deriveSeedCustody(agentDid, rawSlotSeed, rawProjectRootSeed)` + `seedAlgoFromDid(agentDid)`. `loadAgentVc` now drops the P-256 seed (custody by algo). |
| `plugins/lastid-agent/lib/cli.js` | Provision-time keypackage publish runs in-node only for Ed25519 (has a node seed); P-256 **defers to the listener** (broker auth + MLS handle). Kills the "mls keypkg: publish failed (slotSeed required)" + "had to restart" symptom. |
| `plugins/lastid-agent/tests/keychain-seed-custody.test.js` | NEW. 8 pos/neg tests incl. the headline "P-256 + stale seed → dropped" regression + a drift-guard tying `seedAlgoFromDid` to the canonical `agentKeyTypeFromDid`. |

**Tests: full plugin suite `node --test` = 999/999 green.**

**Status:** unit-proven, **NOT** live-proven (the only scope available — `test-logdiver`
— is corrupted, see §4). The loader fix is correct and independent of the MLS-in-broker
work; it should ship once a CLEAN P-256 scope confirms the vault decrypts via the broker.

The cascade was audited — these already route to the broker when `slotSeed` is null,
so only the two files above needed changing:
- vault decrypt → `decryptVaultEnvelope` → `brokerDecryptContent` (broker DecryptAgentContent op)
- content sync decrypt → broker
- MLS wrap key → `brokerDeriveMlsStateKey`
- operator-state MAC → `brokerDeriveOperatorStoreMacKey`
- sub-agent provisioning → Phase-3-op-4 `subBrokerOn` (broker derives sub-seed + signs parent-auth)
- device_id → pinned `md-…` (no seed needed)

---

## 3. The architecture to build (MLS into the broker for P-256)

### 3.1 Key engineering constraint — it moves as a UNIT
The MLS keypackage's **private parts live inside the MLS state** (`mls-state.b64`).
Whoever generates a KeyPackage must also be whoever processes the welcome that
consumes it. **You cannot split "keypackage gen" from "welcome/state"** — doing so
splits the private material across broker+node → `NoMatchingKeyPackage` (the agent's
operator can't add it to a group / chat silently breaks). So the broker must own the
whole MLS engine + state for P-256.

### 3.2 Clean design (reuse the WS pattern, `mem_fdf4ae`)
- **Broker** hosts `lastid-mls-core` for the scope: owns `mls-state`, exposes ops —
  `GenerateKeyPackages{count, device_id}`, `ProcessWelcome`, `Encrypt`, `Decrypt`,
  `Reconcile` (mirror the node `MlsClient` surface).
- **Plugin:** add a **broker-backed `MlsClient` backend** (a proxy) selected for
  `zDn` agents — exactly mirroring `BrokerWsTransport` in `broker-ipc.js`, which
  already proxies the `/v1/ws` channel through the broker (see `mem` broker-phase3-op3).
  `MlsClient` already has two backends (`open` with seed/wrapKey, `fromOrchestrator`);
  add a third: `fromBroker(scope, agentDid, deviceId)`.
- Ed25519 keeps the node MLS path untouched (discriminate by `seedAlgoFromDid`).

### 3.3 Reuse points (do NOT reinvent — `mem_01KTCAMM`)
- Broker op pattern: `protocol.rs` (Op enum) + `ipc.rs` (dispatch) + `idp.rs`/a new
  module (impl). See the existing `DecryptAgentContent`, `SignAgentRecord`,
  `DeriveMlsStateKey`, `DeriveSubAgentSeed` ops as templates.
- `sign_p256_raw`, `lastid_identity::agent_keypair::AgentKeypair`, the `IdpDispatch`
  seam (the broker already mints the resource-token + makes authed IdP calls — reuse
  it for the keypackages POST, just as `publishAgentKeyPackage` POSTs today).
- `brokerDeriveMlsStateKey` already exists (the broker derives the MLS wrap key) — the
  broker can open the same `mls-state` node uses, OR own it outright.
- The MLS keypackage/credential codec (v2 `lidc1:<did>\u1f<device_id>`) lives in
  `lastid-mls-membership` (`mem_01KSXFV6`) — single parser, reuse it.

### 3.4 Suggested phasing (each phase: pos/neg tests + CLEAN live e2e + rebuild/notarize/ship)
> **Treat A + B as ONE coherent unit** (§3.1 — the MLS state can't be split). The
> A/B/C breakdown below is for reasoning about scope, not separate shippable steps.
- **Phase A — broker MLS engine + keypackages.** Broker generates+signs+publishes KPs
  and owns the MLS state for the scope; node `MlsClient.fromBroker` proxies
  `generateKeyPackage`. Proves: fresh P-256 agent publishes KPs (md- device), operator
  can add it to a group.
- **Phase B — group ops in broker.** `ProcessWelcome` + `Encrypt`/`Decrypt` + `Reconcile`
  through the broker. Proves: operator→agent + agent→operator chat round-trips e2e.
- **Phase C — node holds nothing.** node never opens `mls-state`; the broker is the sole
  holder. Fold the `wrapKey`-in-node path out for P-256.

> NOTE: A and B are tightly coupled (§3.1). If a phase split would split-brain the MLS
> state, merge them. Prefer one coherent "broker is the MLS client for P-256" migration
> over micro-ops.

---

## 4. ⚠️ Do NOT test on `test-logdiver` — it is corrupted

`~/.lastid-agent/test-logdiver` has **three** mismatched identities from repeated test
cycles. Verified on disk 2026-06-09:
- node keychain **seed** derives to `zDnaebef…`
- node keychain **DID label** + **broker seed** = `zDnaeSK2…`
- the stale vault share is sealed to `zDnaetPg…` (`vault_c4e50ba436f343c18a9748cf8594ee43`)

A reused/cycled scope is NOT a valid test. **Every live test in this program MUST use a
freshly provisioned P-256 agent** (provision → share/keypackage → verify), never a
reused scope. (This is also why the earlier "live e2e" gave a false signal — the prior
session wrongly blamed a reprovision; the real story is tangled multi-cycle state.)

Other stale scopes with vault shares exist (`lastid-cloudwatch-dive`, `lastid-log-diver`,
`main`, `lastid`) — treat them as suspect too.

---

## 5. Bugs surfaced (separate threads, capture before they're lost)

1. **Keypackage batch publish → HTTP 400** `"expected string, received undefined"` ×6
   on the seedless node path — observed on the corrupted scope (MLS state failed to load
   → `generateKeyPackage()` minted `undefined`). The MLS-in-broker work (§3) replaces
   this path; verify it's gone on a clean scope. If it reproduces on a CLEAN scope, it's
   a real seedless-node-path bug to fix independently.
2. **Reprovision identity churn (unconfirmed).** Whether `--reprovision` reuses the
   protected-store seed (same identity) or mints a new one needs a clean check — if it
   mints new, every reprovision orphans shared creds + MLS state. (Operator stated the
   test-logdiver share was provisioned-then-shared, single identity — so the 3-identity
   tangle came from *something*; worth understanding, but NOT from the corrupted scope.)
3. **Physical seed purge is gated on P5.** The stale node `lastid.co/agent-slot-seed`
   keychain item is still physically present for P-256 scopes. The loader fix makes node
   *ignore* it. Do NOT delete it yet: the broker currently reads the **same** keychain
   item — `credential_store.rs` defines + reads `SERVICE_SLOT_SEED` (lines ~34/109);
   `main.rs:353` then consumes the unsealed `bundle.slot_seed`. The per-broker ACL
   lockdown is the gated/inert **P5** step. Naive deletion bricks the broker. The
   byte-level purge belongs to P5 (ACL the item to the broker signature).

---

## 6. Other uncommitted work from this session (don't lose it)

- **`lastid-idp` (DONE + pushed):** the P-256 agent chat-delivery fix — commit `5b379184`
  on `feature/agent-resource-token-keystone` (pushed). `device-delivery.ts`
  `resolveDurableActiveDeviceIdsForDid` resolves the `md-` machine device for P-256
  agents (not the phantom `ad-`) + 2 regression tests. Ready for the operator to deploy.
- **`lastid-sdk` broker (UNCOMMITTED on branch `agents`):** `main.rs` (md- canonical
  device) + `ws_proxy.rs` (25s keepalive ping). The broker was rebuilt, **notarized
  (Accepted)**, stapled, and shipped into `plugins/lastid-agent/native/lastid-agent-broker.app`.
  Commit these when the keystone branch is being finalized.

---

## 7. Constraints (load-bearing — follow exactly)

- **NEVER push `lastid-agent-plugin` branch `main`** — it publishes a plugin version.
  Push only when the operator says "release." Local commits are fine.
- **NEVER `git add -A` / `git add .`** — stage specific paths only (shared checkout WIP).
- **No-flag-day:** discriminate by the agent DID algo (`seedAlgoFromDid` /
  `agentKeyTypeFromDid`: `z6Mk`→ed25519, else p256). No `LASTID_BROKER_IDP`-style flag.
- **Test for real:** pos/neg unit tests AND a clean-scope live e2e before claiming done
  (operator bedrock `mem_788c`). The system is always deployed — find bugs on disk, don't
  blame "not deployed" (`mem_f0e4`).
- **Reuse over fork** (`mem_fdf4ae`); **clean as you go** (`mem_71be`).
- Broker build/sign/ship: `lastid-sdk/lastid-agent-broker/scripts/build-sign-ship-broker.sh`
  (full notarize via the `lastid-notary` keychain profile; `SKIP_NOTARIZE=1` for local).
- Use **GitNexus** to navigate (`mem_3f36`): `lastid-idp` = `gettrusted-idp`,
  `lastid-agent-plugin` = `lastid-agent`, `lastid-sdk` = `lastid-sdk`. (Note: `lastid-sdk`
  GitNexus index was mid-rebuild / stale DB version on 2026-06-09 — read Rust directly if
  it errors.)

---

## 8. First concrete step for the next session/builder

1. Read the governing memories (full ULIDs in the header — `lastid_memory_get` needs
   the FULL id, not a prefix) + this doc + `docs/broker-credential-custody-plan.md`.
2. Map the node `MlsClient` surface (`lib/mls-client.js`) + the MLS orchestrator
   (`lib/mls-orchestrator.js`, `mls-state-store.js`) — the exact methods to proxy.
3. Map the broker's existing MLS surface (`lastid-agent-broker/src/`: `mls_state.rs`,
   `content_crypto.rs`, the Op enum in `protocol.rs`, dispatch in `ipc.rs`).
   NOTE: `lastid-mls-core` exposes orchestration *ports* (`src/ports.rs`:
   `validate_key_package`, `fetch_*_key_packages`), NOT a ready `generate_key_package`
   entry point — the KP-gen + signing machinery is deeper and today runs in the node
   **wasm** (`lastid-agent-wasm` / the MLS wasm) over the `wrapKey`-sealed state. First
   trace exactly how node's wasm generates+signs a KeyPackage today; that path is what
   moves into the broker, so budget for "stand up the MLS engine in the broker," not
   "call one existing fn."
4. Decide the state-ownership boundary (broker owns `mls-state` vs broker opens the
   node-held sealed state per-op) and write it into `broker-credential-custody-plan.md`.
5. Provision a CLEAN P-256 agent as the test fixture — a FRESH scope name (never reuse
   `test-logdiver`/`main`/`lastid`/etc., see §4). Provisioning is driven from the plugin
   (`node bin/lastid-agent.js provision --scope <fresh> [--idp …]`, or the operator's
   provision skill); confirm the new DID is `zDn…` and the broker enrolled an `md-` device.
6. Build the broker MLS engine + keypackages + `MlsClient.fromBroker` proxy (A+B as one
   unit, §3.1) → pos/neg tests → rebuild/notarize/ship (`build-sign-ship-broker.sh`) →
   clean live e2e. Live-test harnesses to model on (in `lastid-sdk/lastid-agent-broker/
   scripts/`): `run-signed-plugin-bridge-e2e.sh`, `run-signed-crossover-e2e.sh`,
   `lib-broker-e2e.sh` (shared runway). Prove: fresh `zDn` agent publishes KPs (md-
   device) → operator adds it to a group → welcome → owner↔agent chat round-trips.
