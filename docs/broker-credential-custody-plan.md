# Plan — Broker as Sole Credential Holder ("credentials stay in the broker")

**Goal (the END state the operator wants — no intermediary is acceptable):**
The code-signed Rust broker is the **sole reader** of the agent's 32-byte BIP85
slot seed and the **sole maker** of every authenticated IdP call. Unsigned node
NEVER reads the slot seed, NEVER derives keys, NEVER signs. Final step locks the
keychain slot-seed item's ACL to the broker's code signature so unsigned node
*cannot* read it. (Refs: mem_01KSWNT0 broker = hardware-rooted credential holder
on the canonical native DPoP resource-token path; mem_01KT0831 lock-down is LAST,
gated on DPoP adoption, dual-read during migration.)

Status of this doc: written 2026-06-05 from a full read-only map of both sides.
Plug-in epic before this (device model md-, L2/L4/L5, dual-algo, signed broker
shipped in plugin native/) is DONE + committed. This plan is the NEXT phase.

---

## THE KEY INSIGHT (do not miss this)

The broker **already** has everything to be the credential holder for runtime
traffic — it just isn't wired to the plugin yet:

- Reads the slot seed + VC from the OS keychain (`credential_store.rs`, services
  `lastid.co/agent-slot-seed:<scope>`, `…/agent-vc:<scope>`, …). Holds the slot
  seed resident; **never returns it over IPC**.
- Derives `AgentKeypair::from_seed`, does full device **enrollment** (3-signature
  build + POST `/v1/identity/devices/agent`).
- Exposes a **GENERIC `Op::IdpCall{method, path, body}`** (`protocol.rs`,
  `idp.rs::RealIdpClient::call`) that: SSRF-guards the path, mints/refreshes a
  **DPoP resource-token** via the canonical `lastid-api::ApiClient::send_v2_request`
  (reuses `lastid-vc::pop`, `lastid-platform` SE signing), makes the HTTPS call,
  returns `{status, body}`. On 401 it invalidates the cached token.
- IPC is authed: per-launch `broker.token` (32 random bytes, 0600) + same-uid
  `getpeereid` peer check. Socket `~/.lastid-agent/<scope>/broker.sock`.
- Crossover E2E (`run-signed-crossover-e2e.sh`) PROVES IdpCall works:
  `GET /v1/identity/devices` → 200 via resource-token; SSRF rejected; post-revoke
  fresh-mint 401.

**Therefore: most of the migration is routing the plugin's authed fetches through
the EXISTING `Op::IdpCall`. DO NOT add a new broker op per endpoint** (an earlier
analysis proposed `MlsKeypackagePublish`, `MlsGroupCreate`, `MemoryPublish`, … —
that is WRONG and wasteful; the generic IdpCall already covers every plain
method+path+body call). New broker ops are needed ONLY for the non-HTTP-request
pieces listed in Phase 3.

**One scheme change to internalize:** the plugin today authenticates with the
bespoke `Authorization: Bearer <vcCompact>` + `DPoP <agent-key proof>` path. The
broker's IdpCall uses the canonical `Authorization: DPoP <resource-token>` path.
Routing through the broker therefore ALSO migrates the agent onto the canonical
resource-token path (the mem_01KSWNT0 unification; IdP branch is literally
`feature/agent-resource-token-keystone`). **Phase 0 must confirm every agent
endpoint accepts the resource-token auth + scopes.**

---

## MIGRATION SURFACE (node-side, must all move behind the broker)

### A. Authed IdP calls — route through existing Op::IdpCall (the bulk, ~30 sites)
All are `Bearer <vc> + DPoP` → `/v1/...`. Flat endpoint list:
```
GET    /v1/agent-state/{rules,memories,vault,audit-policy,self-protection,subagents}
POST   /v1/agent-state/{memories,audit,rule-hits}
POST   /v1/agent-state/vault/:id/secret
POST   /v1/mls/keypackages/batch        GET /v1/mls/keypackages/{me,:did}
POST   /v1/groups   POST /v1/groups/:id/members
POST   /v1/groups/:id/member-devices/{reconcile,evict}   GET /v1/groups/:id/member-devices/:did
DELETE /v1/identity/devices/:device_id   GET /v1/trust/:did/devices
POST   /v1/agent-use-approvals           GET /v1/agent-use-approvals/:approval_id
```
Plugin files (each currently mints DPoP + fetches; `mls-publish.js` and
`agent-memory-publish.js` also call `deriveAgentKeypair` directly — the others
receive `signingKey` as an injected param, so don't expect a derive call in each):
`mls-groups-api.js` (shared `authedIdpFetch` — biggest win, many callers),
`mls-publish.js`, `agent-state-sync.js`, `agent-memory-publish.js`,
`memory-audit-ship.js`, `rule-metrics-ship.js`, `vault-secret-fetch.js`,
`vault-use-metrics.js`, `use-approval-loop.js`, `desktop-mcp-client.js`.

### B. Non-IdpCall pieces — genuinely need NEW broker capability (Phase 3)
- **WebSocket** `/v1/ws` (`ws-client.js` `#openSocket` ~:214, URL :216, headers
  :230-237): long-lived upgrade w/ Bearer+DPoP —
  cannot be an IdpCall (request/response only). Broker must mint the upgrade auth.
- **Content decryption** (`agent-state-sync.js` → `agent-content-crypto.js`,
  `project-crypto.js`): pulled rules/memories are AES-256-GCM under slot-seed- and
  project-root-seed-derived keys. Broker holds those keys → broker must decrypt.
- **Record signing** (`agent-sig-verify.js::signAgentRecordJws`,
  `agent-memory-publish.js`): provenance signature on authored memory/rule records.
- **Sub-agent provisioning** (`subagent-provisioning.js`): derives sub-agent seed
  from the PARENT slot seed + `signParentAuthorization` + `mintProofJwt`.

### C. Provisioning — slot-seed BIRTH (Phase 4)
`agent-provisioning.js`: `POST /v1/oid4vci/agent-provision/initiate` (ephemeral +
machine key) → `POST /v1/oid4vci/agent-provision/poll` → `unsealSlotSeed` (the
32-byte seed arrives from the wallet, ECDH-P256+AES-GCM) → `POST /v1/oid4vci/token`
→ `POST /v1/oid4vci/credential` (`mintProofJwt` with the NEW slot key) → persist to
keychain. Today node unseals + holds the slot seed at birth. To hit the end goal,
this must move into the broker (broker generates the ephemeral, unseals, claims
the VC, persists). Node drives only the `user_code` UX.

### D. Keychain read (Phase 5 — the lock-down)
`keychain.js::loadAgentVc` reads `SERVICE_SLOT_SEED`. Final cutover: node stops
reading the seed (loads only VC + metadata + device_id); ACL on the slot-seed item
locked to the broker signature.

---

## OPEN DESIGN QUESTIONS (resolve at kickoff, before coding)

1. **IdP resource-token scopes.** Does the deployed IdP (keystone branch) accept
   the broker's resource-token (DPoP) auth on EVERY endpoint in list A, with scopes
   that authorize the agent's resources (agent-state, mls, groups, vault,
   use-approvals)? If not → IdP work to grant agent resource-token scopes. **Phase 0
   is a test that proves IdpCall succeeds against every endpoint.**
2. **WebSocket auth.** Recommend a `WsUpgradeAuth` broker op returning the
   `Authorization`+`DPoP` headers for a SPECIFIC `/v1/ws` upgrade (scoped,
   short-lived). Node opens the socket with those headers; the slot seed never
   leaves the broker. (Acceptable: the goal is slot-seed custody, not zero token in
   node. Confirm the operator agrees a short-lived scoped token in node is fine.)
   Alternative (heavier): broker owns the WS and proxies frames over IPC.
3. **Content decryption.** Recommend the broker's state-sync path returns
   **decrypted** content (broker fetches via IdpCall + decrypts with the
   slot/project keys), OR a generic `DecryptAgentContent{envelope}` op. Do NOT hand
   node the content key.
4. **Provisioning custody.** Confirm the broker does the unseal + VC claim + persist
   (node never sees the seed even at birth) — vs a bootstrap where node provisions
   then hands the seed to the broker and is locked out after. End goal favors the
   former.

---

## PHASED PLAN (no-flag-day; positive+negative tests each phase — mem_788c11)

**Phase 0 — IdP readiness (de-risk first).** Prove the broker's `Op::IdpCall`
resource-token auth succeeds against EVERY endpoint in list A on the deployed IdP.
Close any scope gaps IdP-side (`feature/agent-resource-token-keystone`). Output: a
harness that drives the signed broker over IPC and asserts 200/expected for each
endpoint. This single phase de-risks Phases 1–2.

**Phase 1 — Plugin broker-IPC bridge.** New `lib/broker-ipc.js` (port
`broker-ipc-call.mjs`): connect `broker.sock` w/ `broker.token`, send
`{kind:"idp_call", method, path, body, auth_token}` — the IPC discriminator field
is **`kind`** (serde tag), value `"idp_call"`, NOT `op`; return `{status,body}`.
Add `brokerIdpFetch(...)` mirroring `authedIdpFetch`'s shape (drop-in). The
listener (`bin/lastid-agent.js listen`; lifecycle in `listener-daemon.js`) starts
the signed broker daemon — **the serve/listen loop is the
DEFAULT action; there is NO `serve` subcommand** (passing one hits the
`unknown argument` fail-closed exit in `main.rs:120-123`). Spawn:
`native/lastid-agent-broker.app/Contents/MacOS/lastid-agent-broker --scope <s> [--idp <url>]`,
wait for socket+token, health-check, restart on death. Feature-flag
`LASTID_BROKER_IDP` (default off → legacy node path; on → broker path) for
no-flag-day rollout/rollback. Tests: IPC client unit (mock socket); listener
starts broker + Health.

**Phase 2 — Route list A through the broker.** Swap `mintDpopJwt`+`fetch` /
`authedIdpFetch` → `brokerIdpFetch` in the list-A files. Start with the shared
`mls-groups-api.js::authedIdpFetch` (covers the most callers — mem_fdf4ae reuse).
Node stops deriving keys / minting DPoP for these. Tests: each path pos+neg vs a
mock broker IPC; full plugin suite green; live smoke against deployed IdP behind
the flag.

**Phase 3 — New broker ops for the non-HTTP pieces (list B).** `WsUpgradeAuth`;
content-decrypt (broker returns decrypted state-sync content); record signing
(fold into memory-publish: broker signs the body then POSTs); sub-agent
provisioning (move parent-key crypto into the broker). Rust broker tests + plugin
integration each.

**Phase 4 — Provisioning into the broker (list C).** Broker owns ephemeral gen →
machine-pubkey → `/initiate` → poll → unseal → `/token`+`/credential` → persist.
Node drives only UX. e2e provision-through-broker test (mock IdP): assert the slot
seed never enters node and the broker serves immediately after.

**Phase 5 — Lock-down (list D, FINAL, no-flag-day cutover).** Node stops reading
the slot seed (loadAgentVc loads VC+metadata+device_id only). Lock the keychain
slot-seed ACL to the broker code signature (kSecAttrAccessControl / SecAccess).
Tests: negative — unsigned node read of the slot seed FAILS; positive — full agent
flow works broker-only. Dual-read during migration → broker-only after (mem_01KT0831).

---

## CROSS-CUTTING
- **No-flag-day everywhere.** Feature-flag the broker routing; legacy node path
  stays until the broker path is proven; flip + lock only at Phase 5.
- **Platform.** Broker is macOS-only (`broker-client.js` already gates non-darwin →
  null → legacy node path). Non-mac agents keep the node path permanently; Phase 5
  lock-down applies only where the broker runs.
- **Broker lifecycle.** The listener must own `serve` (start/health/restart). One
  broker per scope; the SE key is pinned to the broker's signing identity (a
  dev-signed vs Developer-ID broker derive DIFFERENT machine keys — production is
  uniformly Developer ID; see mem_01KTBY13).
- **Reuse (mem_fdf4ae).** Broker already reuses lastid-api/identity/vc/platform;
  plugin reuses the one generic Op::IdpCall. No per-endpoint ops.

## ALREADY DONE — do not redo
- Broker: slot-seed read, enrollment, generic IdpCall (resource-token), machine-
  pubkey, IPC auth, SE keys.
- Broker built/signed/notarized/stapled + shipped in plugin `native/`; macOS-gated
  `broker-client.js`; verified survives git checkout (mem_01KTBY13).
- Device model md-, L2 (IdP, deployed), L4 wallet device_authorization, L5 MLS
  device_id, L5a/b reissue+revoke cleanup, dual-algo Ed25519/P-256 (committed across
  the 3 repos: sdk `agents` 5385c87, idp keystone, plugin `main` b360de3).
</content>
