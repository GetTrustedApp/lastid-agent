// agentCredentialChanged: the predicate that lets the long-lived MCP server
// pick up a `provision --reissue` (new slot/DID/VC) without a full restart.
// Before this, the server cached the credential for its process lifetime, so a
// reissue left the tools answering + signing as the OLD (revoked) identity.
import { test } from 'node:test';
import assert from 'node:assert';
import { agentCredentialChanged } from '../lib/mcp-server.js';

const CACHED = { agentDid: 'did:lastid:agent:zAAA', vcCompact: 'vc-AAA' };

test('agentCredentialChanged: a different agent DID is a change (reissue → new slot)', () => {
  assert.equal(
    agentCredentialChanged(CACHED, { agentDid: 'did:lastid:agent:zBBB', vcCompact: 'vc-AAA' }),
    true,
  );
});

test('agentCredentialChanged: a new VC for the SAME DID is a change (re-attest)', () => {
  assert.equal(agentCredentialChanged(CACHED, { agentDid: CACHED.agentDid, vcCompact: 'vc-BBB' }), true);
});

test('agentCredentialChanged: identical DID + VC is NOT a change (no needless reload)', () => {
  assert.equal(
    agentCredentialChanged(CACHED, { agentDid: CACHED.agentDid, vcCompact: CACHED.vcCompact }),
    false,
  );
});

test('agentCredentialChanged: a null fresh read is NOT a change (keep what we have)', () => {
  assert.equal(agentCredentialChanged(CACHED, null), false);
});

test('agentCredentialChanged: no cached agent + a fresh one IS a change (adopt it)', () => {
  assert.equal(agentCredentialChanged(null, CACHED), true);
});
