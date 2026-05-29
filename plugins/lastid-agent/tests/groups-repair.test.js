/**
 * Regression: repairGroupIdMappings heals the persisted group map at startup.
 *
 * Covers the two real states found in the operator's live groups.json
 * (2026-05-28): valid-but-unmapped openmls ids (the common case — the agent
 * recorded them to groups.json but never seeded the wasm idp→openmls map, so a
 * fresh process crashed reconcile), and one CORRUPT record whose group_id_b64
 * is a base64'd UUID (unrecoverable → must be dropped).
 *
 * POSITIVE — a valid 32-byte openmls id is re-seeded via mls.bindGroupIdMapping
 *   and KEPT in groups.json.
 * NEGATIVE/DESTRUCTIVE — a base64'd-UUID record is DROPPED and never seeded.
 *
 * Uses a fake MlsClient (records bindGroupIdMapping calls) + a temp scope dir
 * so nothing touches real agent state.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';

// repairGroupIdMappings resolves groups.json under ~/.lastid-agent/<scope>/.
// We point HOME at a temp dir so the test's scope dir is isolated, then import
// the module fresh (it reads HOME lazily per call via homedir()).
const realHome = process.env.HOME;

function openmlsId(seed) {
  return Buffer.alloc(32, seed & 0xff).toString('base64'); // 32 bytes → valid
}
const UUID_AS_GID = Buffer.from('1f2a8757-ddbf-4754-bb87-9bdae7f2d236', 'utf8').toString('base64'); // 36 bytes → corrupt

test('repairGroupIdMappings seeds valid ids and drops base64-UUID corrupt records', async () => {
  const home = await mkdtemp(join(tmpdir(), 'lastid-grp-repair-'));
  process.env.HOME = home;
  try {
    const scope = 'main';
    const dir = join(home, '.lastid-agent', scope);
    await mkdir(dir, { recursive: true });

    const VALID_IDP = '215172b5-93af-4560-9965-ba0c1ca597af';
    const CORRUPT_IDP = '4a1bb42a-f1df-4e5b-b54f-fa90e97e21f2';
    const validB64 = openmlsId(7);
    const groups = {
      [VALID_IDP]: { group_id_b64: validB64, operator_did: 'did:lastid:zOp', updated_at: 'x' },
      [CORRUPT_IDP]: { group_id_b64: UUID_AS_GID, operator_did: 'did:lastid:zOp', updated_at: 'y' },
    };
    await writeFile(join(dir, 'groups.json'), JSON.stringify(groups), 'utf8');

    const seededCalls = [];
    const fakeMls = {
      async bindGroupIdMapping(idp, openmls) {
        seededCalls.push([idp, openmls]);
      },
    };

    // Fresh import so homedir() (read per fs call) sees the temp HOME.
    const { repairGroupIdMappings } = await import('../lib/agent-groups.js');
    const res = await repairGroupIdMappings({ scope, mls: fakeMls, log: () => {} });

    // Only the valid record was seeded — with the right (idp, openmls) pair.
    assert.deepEqual(seededCalls, [[VALID_IDP, validB64]], 'seeded exactly the valid record');
    assert.equal(res.seeded, 1);
    assert.equal(res.dropped, 1);

    // groups.json now has the valid record and NOT the corrupt one.
    const after = JSON.parse(await readFile(join(dir, 'groups.json'), 'utf8'));
    assert.ok(after[VALID_IDP], 'valid record kept');
    assert.equal(after[CORRUPT_IDP], undefined, 'corrupt record dropped');
  } finally {
    process.env.HOME = realHome;
    await rm(home, { recursive: true, force: true });
  }
});

test('repairGroupIdMappings tolerates a missing handle method (stale vendored wasm)', async () => {
  const home = await mkdtemp(join(tmpdir(), 'lastid-grp-repair2-'));
  process.env.HOME = home;
  try {
    const scope = 'main';
    const dir = join(home, '.lastid-agent', scope);
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, 'groups.json'),
      JSON.stringify({ 'idp-1': { group_id_b64: openmlsId(3) } }),
      'utf8',
    );
    // mls without bindGroupIdMapping — must not throw, just skip seeding.
    const { repairGroupIdMappings } = await import('../lib/agent-groups.js');
    const res = await repairGroupIdMappings({ scope, mls: {}, log: () => {} });
    assert.equal(res.dropped, 0);
    assert.equal(res.seeded, 0); // no method → nothing seeded, no crash
  } finally {
    process.env.HOME = realHome;
    await rm(home, { recursive: true, force: true });
  }
});
