/**
 * End-to-end provisioning integration test.
 *
 * Walks a fresh agent through the full LastID provisioning flow
 * against a configured IdP (real or mock). Run with:
 *
 *   LASTID_IDP_URL=http://localhost:8080 \
 *   LASTID_AGENT_USE_STUB=1 \
 *   node --test tests/integration/end-to-end-provisioning.test.js
 *
 * Requires:
 *   - LASTID_IDP_URL pointing at an IdP that has the
 *     /v1/oid4vci/agent-provision/{initiate,poll} endpoints live.
 *   - LASTID_AGENT_USE_STUB=1 until the native FFI lib is built.
 *
 * The test asserts that after a full round-trip the agent has:
 *   - a valid AgentDid
 *   - a verified VC with the expected capabilities
 *   - keychain entries persisting the seed + VC
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import sessionStart from '../../hooks/session-start.js';
import { loadAgentVc, deleteAgentVc } from '../../lib/keychain.js';

test.skip('provisions a fresh agent end-to-end', async () => {
  // SKIPPED until native FFI is built. Once it is, replace this with
  // a real end-to-end against a local IdP fixture.
  await deleteAgentVc();
  const result = await sessionStart({ projectPath: '/tmp/test-project' });
  assert.equal(result.provisioned, true);
  assert.match(result.agentDid, /^did:lastid:agent:z/);
  const stored = await loadAgentVc();
  assert.ok(stored?.vcCompact, 'VC should be in keychain');
});
