/**
 * Transparent CLI credential proxy (Phase 2): the pure rewrite planner
 * (lib/cli-rewrite.js) + the non-secret binding index (lib/vault-cache.js
 * refreshCliBindings/readCliBindings) the PreToolUse hook uses to rewrite a
 * bound `aws …` into `lastid-agent run --item <id> -- aws …`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { rmSync, readFileSync } from 'node:fs';
import { leadingBinary, planCliRewrite } from '../lib/cli-rewrite.js';
import { refreshCliBindings, readCliBindings } from '../lib/vault-cache.js';

const CLI = '/p/bin/lastid-agent.js';
const bindings = [
  { item_id: 'vault_aws', binaries: ['aws'] },
  { item_id: 'vault_gh', binaries: ['gh'] },
];

// ── leadingBinary ─────────────────────────────────────────────────────────────
test('leadingBinary: basename of a simple command', () => {
  assert.equal(leadingBinary('aws s3 ls'), 'aws');
  assert.equal(leadingBinary('/usr/local/bin/aws s3 ls'), 'aws');
  assert.equal(leadingBinary('  gh   api user '), 'gh');
});

test('leadingBinary: null for compound / piped / redirected / subshell', () => {
  assert.equal(leadingBinary('aws s3 ls | grep x'), null);
  assert.equal(leadingBinary('aws s3 ls && rm -rf /'), null);
  assert.equal(leadingBinary('aws s3 ls; echo hi'), null);
  assert.equal(leadingBinary('aws s3 ls > out.txt'), null);
  assert.equal(leadingBinary('echo $(aws sts get-caller-identity)'), null);
  assert.equal(leadingBinary('cat `which aws`'), null);
});

test('leadingBinary: null for a leading env assignment + empty', () => {
  assert.equal(leadingBinary('AWS_REGION=us-east-1 aws s3 ls'), null);
  assert.equal(leadingBinary('   '), null);
});

// ── planCliRewrite ────────────────────────────────────────────────────────────
test('planCliRewrite: rewrites a bound simple command to lastid-agent run', () => {
  const p = planCliRewrite('aws s3 ls', bindings, { cliPath: CLI });
  assert.equal(p.rewritten, true);
  assert.equal(p.item_id, 'vault_aws');
  assert.equal(p.binary, 'aws');
  assert.equal(p.command, `node ${JSON.stringify(CLI)} run --item vault_aws -- aws s3 ls`);
});

test('planCliRewrite: null for an UNbound binary', () => {
  assert.equal(planCliRewrite('kubectl get pods', bindings, { cliPath: CLI }), null);
});

test('planCliRewrite: ambiguous when 2 shares bind the same binary (no guess)', () => {
  const amb = [
    { item_id: 'a', binaries: ['aws'] },
    { item_id: 'b', binaries: ['aws'] },
  ];
  const p = planCliRewrite('aws s3 ls', amb, { cliPath: CLI });
  assert.equal(p.ambiguous, true);
  assert.deepEqual(p.items, ['a', 'b']);
});

test('planCliRewrite: never re-wraps its own run invocation', () => {
  assert.equal(planCliRewrite(`node ${JSON.stringify(CLI)} run --item vault_aws -- aws s3 ls`, bindings, { cliPath: CLI }), null);
  assert.equal(planCliRewrite('lastid-agent run --item x -- aws s3 ls', bindings, { cliPath: CLI }), null);
});

test('planCliRewrite: null for a compound command (refuses unsafe wrap)', () => {
  assert.equal(planCliRewrite('aws s3 ls && printenv', bindings, { cliPath: CLI }), null);
});

// ── binding index (refreshCliBindings / readCliBindings) ──────────────────────
const envShareBytes = () =>
  Buffer.from(
    JSON.stringify({
      item_id: 'vault_aws',
      title: 'AWS',
      kind: 'api_key',
      injection: {
        type: 'env',
        env_map: [
          { name: 'AWS_ACCESS_KEY_ID', field: 'secret' },
          { name: 'AWS_SECRET_ACCESS_KEY', field: 'secret_secondary' },
        ],
      },
      binaries: ['aws'],
      constraints: [],
      on_violation: { type: 'deny' },
      granted_actions: ['use'],
      secret: 'AKIA-SECRET',
      secret_secondary: 'shh-secret',
    }),
    'utf8',
  );
const headerShareBytes = () =>
  Buffer.from(
    JSON.stringify({
      item_id: 'vault_oai',
      injection: { type: 'header', name: 'Authorization' },
      constraints: [],
      on_violation: { type: 'deny' },
      granted_actions: ['use'],
      secret: 'sk-zzz',
    }),
    'utf8',
  );

test('refreshCliBindings: writes only env-share bindings, never a secret', () => {
  const scope = `test-${randomUUID()}`;
  const dir = join(homedir(), '.lastid-agent', scope);
  try {
    const deps = {
      listCache: () => [
        { id: 'vault_aws', enc_b64: 'x', status: 'active' },
        { id: 'vault_oai', enc_b64: 'y', status: 'active' },
      ],
      decrypt: (_seed, enc) => (enc === 'x' ? envShareBytes() : headerShareBytes()),
    };
    const written = refreshCliBindings(scope, Buffer.alloc(32), deps);
    assert.deepEqual(written, [{ item_id: 'vault_aws', binaries: ['aws'] }], 'env share bound; header share skipped');
    assert.deepEqual(readCliBindings(scope), [{ item_id: 'vault_aws', binaries: ['aws'] }]);
    const raw = readFileSync(join(dir, 'cli-bindings.json'), 'utf8');
    assert.equal(raw.includes('AKIA-SECRET'), false, 'index carries no secret');
    assert.equal(raw.includes('shh-secret'), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('readCliBindings: [] when the index is absent', () => {
  assert.deepEqual(readCliBindings(`test-${randomUUID()}`), []);
});
