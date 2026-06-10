/**
 * Sub-agent provisioning orchestrator (lib/subagent-provisioning.js):
 *   PURE input-validation paths covered here. The full happy path
 *   touches WASM + HTTP + keychain and is exercised end-to-end in
 *   Slice 9 (live publish → provision → spawn), not synthetically.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import {
  provisionSubagent,
  subagentNextIndexUrls,
  capabilitiesEqual,
} from '../lib/subagent-provisioning.js';

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
// The seed guard is relaxed ONLY when the broker is actually doing the parent-key
// crypto (subBrokerOn = P-256 parent AND a broker socket+token present for the
// scope). The broker path is now the macOS default — but that's not a free pass:
// with no broker actually RUNNING for the scope, subBrokerOn is false and the
// 32-byte seed is still mandatory. A unique scope guarantees no broker is up
// (brokerAvailable=false) regardless of any real listener on this machine, so the
// test is deterministic across platforms + whatever's running locally.
test('provisionSubagent: NEGATIVE — P-256 parent with no seed STILL requires it when no broker is up', async () => {
  await assert.rejects(
    provisionSubagent({
      idpUrl: 'https://idp.example',
      parentSlotSeed: null, // broker-native shape, but no broker is running
      parentSigningKey: null,
      parentDid: 'did:lastid:agent:zDnPARENT', // P-256 (zDn) parent
      parentVcCompact: 'vc.compact',
      parentScope: `subagent-test-${randomUUID()}`, // no broker for this scope
      subagent: { slug: 'echo' },
    }),
    /parentSlotSeed must be a 32-byte Buffer \(or a running broker for a P-256 parent\)/,
  );
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

// ── capabilitiesEqual: order-insensitive (regression for duplicate sub-agents) ──
// The agent re-minted the sub-agent VC on EVERY broker/listener load — and so
// accumulated duplicate sub-agents (operator saw 5x "logdiver slot #0") —
// because capabilitiesEqual was `JSON.stringify(a) === JSON.stringify(b)`,
// which is sensitive to object-KEY order. The VC-parsed caps are
// `{actions, resource}`; the desired (config) caps are `{resource, actions}`.
// Identical capabilities, different key order → reported "drift" → re-mint.

test('capabilitiesEqual: POSITIVE — identical caps with different object KEY order are equal (the dup-subagent bug)', () => {
  // Exactly the two shapes from the live caps-drift log.
  const existingFromVc = [
    { actions: ['Read'], resource: 'memory:read:global' },
    { actions: ['Draft'], resource: 'memory:draft:global' },
    { actions: ['Use'], resource: 'vault:use' },
  ];
  const desiredFromConfig = [
    { resource: 'memory:read:global', actions: ['Read'] },
    { resource: 'memory:draft:global', actions: ['Draft'] },
    { resource: 'vault:use', actions: ['Use'] },
  ];
  assert.equal(capabilitiesEqual(existingFromVc, desiredFromConfig), true);
});

test('capabilitiesEqual: POSITIVE — same caps in different ARRAY order are equal', () => {
  const a = [
    { resource: 'vault:use', actions: ['Use'] },
    { resource: 'memory:read:global', actions: ['Read'] },
  ];
  const b = [
    { resource: 'memory:read:global', actions: ['Read'] },
    { resource: 'vault:use', actions: ['Use'] },
  ];
  assert.equal(capabilitiesEqual(a, b), true);
});

test('capabilitiesEqual: POSITIVE — same cap with ACTIONS in different order are equal', () => {
  const a = [{ resource: 'r', actions: ['Read', 'Draft'] }];
  const b = [{ resource: 'r', actions: ['Draft', 'Read'] }];
  assert.equal(capabilitiesEqual(a, b), true);
});

test('capabilitiesEqual: NEGATIVE — a missing capability is NOT equal', () => {
  const a = [
    { resource: 'memory:read:global', actions: ['Read'] },
    { resource: 'vault:use', actions: ['Use'] },
  ];
  const b = [{ resource: 'memory:read:global', actions: ['Read'] }];
  assert.equal(capabilitiesEqual(a, b), false);
});

test('capabilitiesEqual: NEGATIVE — a different action is NOT equal', () => {
  const a = [{ resource: 'vault:use', actions: ['Use'] }];
  const b = [{ resource: 'vault:use', actions: ['Read'] }];
  assert.equal(capabilitiesEqual(a, b), false);
});
