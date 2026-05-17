#!/usr/bin/env node
/**
 * PreToolUse hook.
 *
 * Intercepts every tool invocation. The relevant case for the LastID
 * Agent plugin is when the runtime calls the built-in `Task` tool to
 * spawn a sub-agent: we want to provision that sub-agent with its own
 * `LastID.Agent.Base` VC, capabilities-bounded by the parent's grant.
 *
 * Flow:
 *   1. Detect Task tool invocation.
 *   2. If parent agent's VC carries `may_delegate=true`, build a
 *      sub-agent offer request (slug, capabilities_subset, exp).
 *   3. POST to the IdP's `/v1/oid4vci/agent-offer/sub` endpoint with
 *      the parent's DPoP-PoP JWT.
 *   4. Receive a credential offer URI, claim it via OID4VCI with a
 *      newly-derived sub-agent Ed25519 keypair.
 *   5. Persist the sub-agent's (seed, VC) to a keychain entry keyed by
 *      the sub-agent's class slug.
 *   6. Hand the sub-agent's identity to the spawned runtime instance.
 *
 * If the parent does not have `may_delegate`, the sub-agent runs
 * UNCREDENTIALED — no LastID identity, no memory access. The runtime
 * is told this fact so it can decide whether to proceed.
 */

import { loadAgentVc, persistSubAgentVc } from '../lib/keychain.js';
import { requestSubAgentOffer, claimVcFromOffer } from '../lib/oauth-device-code.js';
import { initializeSdkBindings } from '../lib/sdk-bindings.js';

/**
 * Hook entry. `context.toolName` and `context.toolInput` tell us what
 * the runtime is about to do. We only intercept `Task`.
 */
export default async function preToolUse(context) {
  if (context?.toolName !== 'Task') {
    return { allow: true };
  }

  const parent = await loadAgentVc();
  if (!parent) {
    // Parent isn't provisioned (shouldn't happen if session-start ran),
    // so we can't issue a sub-credential. Allow the Task but flag.
    return { allow: true, note: 'parent agent has no LastID identity; sub-agent will run uncredentialed' };
  }
  if (!parent.claims.may_delegate) {
    return { allow: true, note: 'parent VC has may_delegate=false; sub-agent will run uncredentialed' };
  }

  const sdk = await initializeSdkBindings();
  const classSlug = deriveClassSlug(context.toolInput);
  const subCapabilities = deriveSubCapabilities(parent.claims.capabilities, context.toolInput);

  const subKeypair = await sdk.deriveSubAgentKeypair({
    parentSeed: parent.seed,
    classSlug,
    index: 0,
  });

  const offerUri = await requestSubAgentOffer({
    parentVcCompact: parent.vcCompact,
    parentKeypair: parent.keypair,
    subAgentClass: classSlug,
    subAgentPubkeyJwk: subKeypair.jwk,
    capabilitiesSubset: subCapabilities,
    exp: parent.claims.exp,
  });

  const sub = await claimVcFromOffer({ offerUri, agentKeypair: subKeypair });
  await persistSubAgentVc(classSlug, sub);

  return {
    allow: true,
    contextOverride: {
      subAgentDid: sub.claims.sub,
      subAgentVcThumbprint: sub.thumbprint,
    },
  };
}

function deriveClassSlug(toolInput) {
  // Best-effort: Claude Code's Task tool takes a `subagent_type` arg.
  // We slugify it; fall back to 'general' if unset or unrecognized.
  const raw = toolInput?.subagent_type ?? 'general';
  return String(raw).toLowerCase().replace(/[^a-z0-9._:-]+/g, '-');
}

function deriveSubCapabilities(parentCaps, _toolInput) {
  // Conservative default: sub-agents inherit parent's capabilities
  // minus delegation authority and minus any wildcard write/sign
  // capabilities. Refinements live in lib/capability-policy.js (TBD).
  return parentCaps
    .filter((c) => c.actions.some((a) => a === 'read' || a === 'list'))
    .map((c) => ({
      resource: c.resource,
      actions: c.actions.filter((a) => a !== 'spawn'),
      constraints: c.constraints ?? [],
    }));
}
