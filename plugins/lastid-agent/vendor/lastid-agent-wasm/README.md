# lastid-agent-wasm (vendored)

Real Rust crypto for the LastID agent plugin, packaged as a Node-target
WASM module. Sourced from `lastid-sdk/lastid-agent-wasm` and copied here
by `lastid-sdk/scripts/build-and-copy-agent-wasm.sh` while we're
pre-publish.

When LastID moves to a private npm registry the plugin's
`lib/sdk-bindings.js` will switch from `require('../vendor/...')` to
`require('@lastid/agent-wasm')` and this directory goes away. No
call-site changes.

## Refreshing

From the SDK repo:

```bash
cd ~/Documents/GitHub/LastID/lastid-sdk
scripts/build-and-copy-agent-wasm.sh
```

The script `wasm-pack build`s the crate in release mode for Node and
copies the artifacts (.wasm + JS bindings + .d.ts) into this dir.
Commit the result alongside the plugin so `/plugin update` ships the
new binary.

## What's exposed

Single source of truth lives in `lastid-sdk/lastid-agent-wasm/src/lib.rs`
plus the canonical Rust under `lastid-identity` and `lastid-vc`. The
plugin sees this surface via `lib/sdk-bindings.js`:

- `agentKeypairFromSeed(seed)` — derive Ed25519 keypair + DID + JWK
  thumbprint from a 32-byte seed
- `deriveAgentSlotSeed` / `deriveSubAgentSeed` — HKDF-SHA512 with
  domain-separated info strings (pinned by KAT vectors in the Rust
  test suite so JS↔Rust drift is impossible)
- `agentDidFromPubkey` / `parseAgentDid` / `ed25519JwkThumbprint`
- `mintOid4vciProofJwtEdDsa` — agent-side proof JWT for OID4VCI
- `mintPopJwt` / `verifyPopJwt` — DPoP-shaped steady-state auth
- `verifyAgentVcOuter` / `verifyAgentVcWithHumanAuthorization` /
  `verifyHumanAuthorization` — SD-JWT VC chain verification
- `capabilityPermits` / `capabilitiesPermits` /
  `capabilityIsSubsetOf` / `capabilitiesIsSubsetOf`
- `signEd25519` / `verifyEd25519`

## Why vendored, not vendored

We considered publishing to GitHub Packages npm at `@lastid/agent-wasm`
plus `@lastid/enterprise-identity-wasm` and `@lastid/mls-wasm` to share
the same artifacts with the bot runtimes (credential service) and any
future Node consumer. That's the plan once the SDK pipeline is set up
for tagged releases; until then, vendor-and-commit is the lower-friction
path.
