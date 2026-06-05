# lastid-agent-broker — epic plan & NEW-SESSION PICKUP DOC

> Fresh session picking this up: read this top-to-bottom, then the memories
> in §0. Durable state = THIS file + the cited memories + the folder-anchored
> stickies (kind:sticky). The session task list is ephemeral.
>
> **Authoritative decision:** mem_01KSWNT0ERFVN1H1QV3PQXCSFE (operator
> 2026-05-30). This plan executes it.

## Why

The agent holds its Ed25519 slot key as raw bytes in Node memory (HKDF from a
slot seed in the OS keychain; no per-app ACL). Two problems:

1. **No trust boundary below the key.** Guardrails (MCP capability checks,
   self-protection hooks) sit ABOVE the signing call — a plain `node` import can
   sign + POST and bypass the entire MCP/hook surface.
2. **Bespoke auth.** The agent is the only LastID client on `Bearer <Agent.Base
   SD-JWT>` + token-less DPoP; native/bots use canonical DPoP `<resource_token>`.
   A Bearer-VC agent is a latent ML-DSA time bomb (ML-DSA-65 SD-JWTs blow the
   ~16 KB Authorization-header cap).

**Fix:** a code-signed Rust helper shipped with the plugin that owns a
per-machine Secure-Enclave device key, runs `lastid-api` end-to-end, and exposes
a local IPC. Node stops signing and stops calling the IdP directly. The same
broker becomes the credentialed-access boundary (vault handle unwrap +
injection).

## §0 Read-first (durable state)

- **mem_01KSWNT0ERFVN1H1QV3PQXCSFE** — THE locked decision (auth divergence,
  SE/NAPI constraint, code-signed Rust helper vehicle, FORK1/FORK2,
  IdP resource-token KEYSTONE, no-flag-day migration, shipped BRIDGE).
- **mem_01KSZHXB319PGTNJWWNE6FTGRB** — use gitnexus over grep/Read for LastID
  code; rtk hook can FABRICATE file contents. lastid-idp indexes as
  `gettrusted-idp`. Verify any long bash/Read output via exit codes / od / the
  harness <new-diagnostics>; the Edit/Write tools (match-or-fail / direct) are
  the trustworthy write channel.
- mem_01KSTVFY — prod logs via vault (LastID-IDP-AWS) to confirm, not guess.
- mem_01KSMS3RK / mem_01KSGKGF — agent WASM is built from Rust; rebuild+copy via
  `lastid-sdk/scripts/build-and-copy-agent-wasm.sh` (no auto-update).
- mem_788c / mem_734725 / mem_f0e4 / mem_fdf4ae — pos+neg tests before "done";
  slow-is-smooth; find bugs on disk; optimize for reuse.

## Locked decisions (mem_01KSWNT0 — do NOT re-litigate)

- **Vehicle:** code-signed Rust helper (LastID Apple keys, macOS-first), shipped
  WITH the plugin. Not the desktop, not unsigned node.
- **FORK1:** broker does the FULL IdP call — Node sends `{method,path,body}`;
  broker runs `lastid-api` → Node deletes `authedIdpFetch`/`dpop.js`/`ws-auth`.
- **FORK2:** identity ≠ device. Identity = slot-seed Ed25519 DID (portable;
  Agent.Base VC cnf UNCHANGED). SE key = per-machine DEVICE key, bound at the
  token + device-registration layer. One identity → N hw-attested, revocable
  devices.
- **KEYSTONE (done first, independently shippable):** IdP agent branch at
  `POST /v1/auth/resource-token` modeled on the bot branch.
- **MIGRATION:** NO flag day. Feature-detect; upgrade-in-place under existing
  identity (no VC re-issue); fallback to legacy Bearer when broker absent /
  non-macOS; IdP keeps accepting legacy + emits legacy-auth telemetry; delete
  legacy + bridge only after all agents are on DPoP.
- **Broker home:** its OWN repo + crate `lastid-agent-broker` (NOT the
  lastid-sdk workspace). Reason: distribution — ships as a prebuilt, NOTARIZED
  binary via npm (notarization needs SE entitlements → cannot source-build on
  the user's machine → independent build/notarize/publish pipeline).
  Distribution mechanism TBD in Phase 2 (optionalDependencies per-platform pkg,
  à la esbuild, OR postinstall fetch from GitHub Releases w/ checksum+sig).
  Cross-repo Rust deps: pin lastid-sdk crates (lastid-api,
  lastid-platform/MacOSPlatformSecurity) via cargo git/path deps.

## Phases

- **Phase 1 — IdP resource-token AGENT branch (KEYSTONE). ✅ DONE 2026-05-31.**
  lastid-idp branch `feature/agent-resource-token-keystone`, origin HEAD `010e8b4`
  (pushed to origin). PR NOT yet opened — repo has NO `develop` branch; remote
  has `main` + `feature/identity-v2` only. Recommended PR base =
  `feature/identity-v2` (all the code this builds on — agentContext, devices
  bridge, bot branch, #843 — lives there). Awaiting operator confirmation.
  See §Phase-1-detail.
- **Phase 2 — lastid-agent-broker Rust helper + notarization.** 🟡 SKELETON DONE
  2026-05-31 — own repo at `~/Documents/GitHub/LastID/lastid-agent-broker`,
  branch `main`, initial commit `ac73afc` (triple-verified:
  .git/refs/heads/main + od byte-dump + git log all agree), PUSHED to
  `git@github.com:GetTrustedApp/lastid-agent-broker.git` (`[new branch] main`;
  local HEAD == origin/main confirmed via `cmp`).
  Built + verified (cargo test 18 pass; clippy -D warnings
  clean; cargo fmt --check clean): protocol.rs (NDJSON IPC wire types), auth.rs
  (per-launch token constant-time + peer-cred same-uid policy, fail-closed),
  device_key.rs (DeviceKey trait + fail-closed StubDeviceKey), idp.rs (IdpClient
  = FORK1 boundary, stubbed), ipc.rs (unix-socket server + pure tested
  handle_request), main.rs (args, runtime dir, 0600 token file). npm/ packaging
  skeleton (prebuilt notarized binary; mechanism A optionalDeps vs B postinstall
  fetch — TBD). STILL TODO (clearly-marked fail-closed stubs, crate-level
  allow(dead_code) until wired): wire lastid-api (real IdP call) + lastid-platform
  MacOSPlatformSecurity (real SE key); LOCAL_PEERCRED peer-uid syscall; CSPRNG
  token; notarization pipeline on LastID Apple keys. Owns SE device key, runs
  lastid-api end-to-end, local IPC (peer-cred + per-launch token).
  - **Next-increment wiring map (recon-confirmed 2026-05-31 via gitnexus;
    lastid-sdk @29ca6f49, 31 behind — re-verify before editing):** the broker's
    `IdpClient.call(method, path, body)` delegates to
    `lastid-api/src/lib.rs::authed_request<P: PlatformSecurity>(client:
    &ApiClient, platform: &P, creds: &CredentialStore, method, path, body)`
    (it mints/refreshes the DPoP resource-token binding the device key in cnf,
    attaches an ath-bound proof, sends). The broker's `DeviceKey` trait maps
    1:1 onto `lastid-platform/src/lib.rs` `PlatformSecurity`
    (`ensure_device_key`/`has_device_key`/`device_public_jwk`/
    `sign_with_device_key`/`hardware_attestation`; macOS impl
    `MacOSPlatformSecurity`), so `SecureEnclaveDeviceKey` is a thin adapter over
    `Arc<dyn PlatformSecurity>` + a label. OPEN GAP: `CredentialStore` — how the
    broker gets the Agent.Base VC + slot seed (today Node `keychain.js` loads
    the slot seed from the OS keychain); decide broker-reads-keychain vs
    Node-hands-over-IPC-at-startup. (Full detail in the idp.rs sticky.)
- **Phase 3 — provisioning: SE device key + device registration.** Broker gens SE
  key, attests (HardwareInfo/verify_hardware_attestation), registers a device row
  under the EXISTING identity (reuse V2DeviceRecord/View/DelegationRow,
  device_type='agent', per-device revocable). Bind SE key via resource-token cnf.
- **Phase 4 — migrate agent IdP calls through the broker; delete bespoke auth.**
  Route signing/seed call sites + authedIdpFetch/dpop.js/ws-auth through broker
  IPC. Only after telemetry shows all agents on DPoP.
- **Phase 0.5 (cross-cutting) — migration.** Feature-detect at startup +
  dual-auth; IdP keeps accepting legacy Bearer + legacy-auth telemetry; remove
  legacy + bridge LAST.
- **Credentialed-access broker (extends 2/3).** Move `open_with_handle` +
  `applyInjection` + network fetch + zeroize into the broker (layer-1 primitive
  ready: lastid-sdk `lastid-identity/src/handle_envelope.rs`). Listener keeps
  handle minting + policy + audit.

## Phase 1 detail (as built, 2026-05-31)

Repo: lastid-idp (gitnexus: `gettrusted-idp`). Branch
`feature/agent-resource-token-keystone`, origin HEAD `010e8b4`. Files changed (6):
- `src/models/resource-token.ts` — `ResourceTokenClaims` gains optional agent
  fields: parent_human_did, capabilities, may_delegate, agent_device_id,
  slot_index, parent_agent_did, sub_agent_class, audit_endpoint. (NOT
  human_authorization — never read downstream, not persisted.)
- `src/services/resource-token.ts` —
  - `mintResourceAccessToken` takes an optional `agent` block, mirrors it into
    the token, amr=['base_vc','agent_pop']; synthesized device id overrides the
    generic device_id/identity.
  - `resolveDeviceKeyForResourceTokenClaims` — agent path returns the Ed25519
    identity key via `parseAgentDidToJwk(subject_did)` (no Firestore).
  - `buildVCContextFromResourceTokenClaims` — agent path rebuilds agentContext
    from token claims, no Firestore read.
  - `updateLastSeenFromResourceTokenClaims` — agents skipped (like bots).
- `src/middleware/vc-auth.ts` — `AgentContext.humanAuthorization` made OPTIONAL
  (present on Bearer path, absent on token-rebuilt path).
- `src/api/auth/resource-token.ts` — handler accepts agent VC
  (allowAgentCredential:true); agent branch verifies the Ed25519 PoP carried in
  `device_attestation_token` via `verifyAgentPopJwt` (htu=<issuer>/v1/auth/
  resource-token, method=POST), 401 fail-closed; mints with the agent block; the
  separate `dpop_jwk` (hardware/SE key) → token cnf.jkt (FORK2).
- Tests: `tests/unit/services/resource-token-agent.test.ts` (6),
  `tests/unit/api/auth/resource-token-agent-route.test.ts` (3, pos+neg PoP).

Design fork RESOLVED (operator-confirmed "inline fine", 2026-05-31): the token
is **self-contained / inline** (carries capabilities etc.), NOT Firestore-
rehydrated — matches the keystone's "skip Firestore" and is ~2 KB, far under the
16 KB cap that forced DPoP. Server-side rehydration was impossible anyway:
Firestore stores only `human_authorization_jti`, not the capabilities/JWS.

Verified: tsc 0 errors, eslint 0, 18 tests green (6 service + 3 route pos/neg +
9 existing regression). Verify in prod after deploy: vault → LastID-IDP-AWS
CloudWatch, "Issued REST resource token" with credential_type=LastID.Agent.Base
+ device_key_source=agent_synthesized [mem_01KSTVFY]. No client change → no agent
regression.

## Agent-side code map (for Phase 4 — confirm on disk before editing)

`lastid-agent-plugin/plugins/lastid-agent/lib/`: keychain.js (slot seed),
agent-provisioning.js (HKDF keypair), dpop.js (mintDpopJwt), agent-sig-verify.js,
project-crypto.js, agent-content-crypto.js, vault-cache.js, mls-client.js,
mls-publish.js, mls-groups-api.js (authedIdpFetch), ws-client.js,
desktop-mcp-client.js, agent-state-sync.js, memory-audit-ship.js,
rule-metrics-ship.js, subagent-provisioning.js. (Paths from the plan; verify via
gitnexus repo `lastid-agent` before touching.)

## Tooling note

rtk Claude-Code hook corrupts/fabricates bash + Read output (even temp-file
reads). Keep bash commands short; verify via exit codes + the harness
<new-diagnostics> LSP reports; prefer gitnexus (its index is rtk-immune) and the
Edit/Write tools (match-or-fail / direct write). Clean settings backup:
`~/.claude/settings.json.rtk-backup-broker`.
