/**
 * Sub-agent provisioning orchestrator (lib/subagent-provisioning.js):
 *   PURE input-validation paths covered here. The full happy path
 *   touches WASM + HTTP + keychain and is exercised end-to-end in
 *   Slice 9 (live publish → provision → spawn), not synthetically.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { provisionSubagent, subagentNextIndexUrls } from '../lib/subagent-provisioning.js';

test('provisionSubagent: NEGATIVE — parentSlotSeed must be a 32-byte Buffer', async () => {
  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: Buffer.alloc(31), // too short
      parentSigningKey: {},
      parentDid: 'did:lastid:agent:zPARENT',
      parentVcCompact: 'vc.compact',
      parentScope: 'main',
      subagent: { slug: 'echo' },
    }),
    /parentSlotSeed must be a 32-byte Buffer/,
  );

  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: 'not-a-buffer',
      parentSigningKey: {},
      parentDid: 'did:lastid:agent:zPARENT',
      parentVcCompact: 'vc.compact',
      parentScope: 'main',
      subagent: { slug: 'echo' },
    }),
    /parentSlotSeed must be a 32-byte Buffer/,
  );
});

// REGRESSION (broker-credential-custody Phase 3 op 4 — 2026-06-07):
// The seed guard is relaxed ONLY when the broker is actually doing the
// parent-key crypto (subBrokerOn = P-256 parent AND LASTID_BROKER_IDP on AND a
// broker socket+token present for the scope). A P-256 parent DID (zDn…) must NOT
// be a free pass: with no broker running for the scope, subBrokerOn is false and
// the 32-byte seed is still mandatory. Locks the relaxation so it can't silently
// bypass the seed requirement when the broker isn't up.
test('provisionSubagent: NEGATIVE — P-256 parent with no seed STILL requires it when no broker is up', async () => {
  // Force the flag on; brokerAvailable() still returns false (no socket/token in
  // this test env), so subBrokerOn must resolve false → seed guard fires.
  const prev = process.env.LASTID_BROKER_IDP;
  process.env.LASTID_BROKER_IDP = '1';
  try {
    await assert.rejects(
      provisionSubagent({
        idpUrl: 'https://idp.example',
        parentSlotSeed: null, // broker-native shape, but no broker is running
        parentSigningKey: null,
        parentDid: 'did:lastid:agent:zDnPARENT', // P-256 (zDn) parent
        parentVcCompact: 'vc.compact',
        parentScope: 'main',
        subagent: { slug: 'echo' },
      }),
      /parentSlotSeed must be a 32-byte Buffer \(or a running broker for a P-256 parent\)/,
    );
  } finally {
    if (prev === undefined) delete process.env.LASTID_BROKER_IDP;
    else process.env.LASTID_BROKER_IDP = prev;
  }
});

test('provisionSubagent: NEGATIVE — subagent.slug required', async () => {
  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: Buffer.alloc(32),
      parentSigningKey: {},
      parentDid: 'did:lastid:agent:zPARENT',
      parentVcCompact: 'vc.compact',
      parentScope: 'main',
      subagent: {},
    }),
    /subagent\.slug required/,
  );

  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: Buffer.alloc(32),
      parentSigningKey: {},
      parentDid: 'did:lastid:agent:zPARENT',
      parentVcCompact: 'vc.compact',
      parentScope: 'main',
      subagent: null,
    }),
    /subagent\.slug required/,
  );

  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: Buffer.alloc(32),
      parentSigningKey: {},
      parentDid: 'did:lastid:agent:zPARENT',
      parentVcCompact: 'vc.compact',
      parentScope: 'main',
      subagent: { slug: '' },
    }),
    /subagent\.slug required/,
  );
});

// REGRESSION (DPoP htu mismatch on /sub/next-index — 2026-05-28):
// fetchNextSubagentIndex initially passed the full URL (with the
// ?sub_agent_class=… query string) to mintDpopJwt, which embedded it
// into the DPoP `htu` claim. The IdP verifier strips the query before
// comparing, so EVERY new sub-agent provision returned 401
// invalid_dpop_proof and silently failed at the parent listener.
// Split the htu (no query) from the fetch url (with query); these
// tests pin that contract so a future refactor can't reintroduce it.
test('subagentNextIndexUrls: htu has NO query string; url DOES carry the param', () => {
  const { htu, url } = subagentNextIndexUrls(
    'https://human.lastid.co',
    'test-writer',
  );
  // The DPoP claim half — strict equality, no surprise additions.
  assert.equal(htu, 'https://human.lastid.co/v1/oid4vci/agent-provision/sub/next-index');
  assert.ok(!htu.includes('?'), 'htu must NOT contain a query string');
  assert.ok(!htu.includes('#'), 'htu must NOT contain a fragment');
  // The fetch half — same base + the routing param.
  assert.equal(
    url,
    'https://human.lastid.co/v1/oid4vci/agent-provision/sub/next-index?sub_agent_class=test-writer',
  );
});

test('subagentNextIndexUrls: slugs with reserved characters are URL-encoded', () => {
  // The slug regex (/^[a-z0-9-_:.]+$/) allows ':' and '.', both reserved.
  // encodeURIComponent must percent-encode them so the IdP parses the param
  // correctly. The htu still drops the whole query, so encoding is fetch-only.
  const { htu, url } = subagentNextIndexUrls(
    'https://human.lastid.co',
    'sweep:v2.beta',
  );
  assert.equal(htu, 'https://human.lastid.co/v1/oid4vci/agent-provision/sub/next-index');
  assert.equal(
    url,
    'https://human.lastid.co/v1/oid4vci/agent-provision/sub/next-index?sub_agent_class=sweep%3Av2.beta',
  );
});
