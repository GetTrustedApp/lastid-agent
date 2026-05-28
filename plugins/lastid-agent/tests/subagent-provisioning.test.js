/**
 * Sub-agent provisioning orchestrator (lib/subagent-provisioning.js):
 *   PURE input-validation paths covered here. The full happy path
 *   touches WASM + HTTP + keychain and is exercised end-to-end in
 *   Slice 9 (live publish → provision → spawn), not synthetically.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { provisionSubagent } from '../lib/subagent-provisioning.js';

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
