/**
 * Markdown outbox path (lib/agent-send.js): enqueueMarkdownSend writes a
 * kind:'markdown' line, and drainOutbox builds the canonical
 * lastid-core MessageEnvelope ({ v:1, t:'markdown', p:JSON({tldr,body}) })
 * and ships it through the SAME MLS path as a text message — same WS frame
 * shape, but with message_type = 'markdown' so receivers (mobile + console)
 * pick the right bubble.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  enqueueMarkdownSend,
  enqueueSend,
  drainOutbox,
  MARKDOWN_TLDR_MAX_CHARS,
  PLAIN_TEXT_SOFT_CAP_CHARS,
} from '../lib/agent-send.js';
import { recordGroup } from '../lib/agent-groups.js';

const OPERATOR = 'did:lastid:z5cZOperatorHuman';
const AGENT = 'did:lastid:agent:z6MkAgent';
const SCOPE = 'md-test';
const IDP_GROUP = 'idp-group-uuid-md';

let home;
let prevHome;
const outboxPath = () => join(home, '.lastid-agent', SCOPE, 'outbox.jsonl');

before(async () => {
  prevHome = process.env.HOME;
  home = await mkdtemp(join(tmpdir(), 'lastid-md-'));
  process.env.HOME = home;
});
after(async () => {
  process.env.HOME = prevHome;
  await rm(home, { recursive: true, force: true });
});
beforeEach(async () => {
  await rm(join(home, '.lastid-agent', SCOPE), { recursive: true, force: true });
});

async function readOutboxLines() {
  try {
    const raw = await readFile(outboxPath(), 'utf-8');
    return raw.split('\n').filter((l) => l.trim().length > 0);
  } catch {
    return [];
  }
}

// MLS stub that captures the envelope handed to it, so we can assert on the
// JSON shape without spinning up real openmls. Returns a sentinel ciphertext.
function captureMls() {
  const captured = [];
  return {
    captured,
    mls: {
      encryptApplicationMessage: async (_groupIdB64, envelopeB64) => {
        captured.push(Buffer.from(envelopeB64, 'base64').toString('utf-8'));
        return 'mls-cipher-sentinel';
      },
      persist: async () => {},
      groupEpoch: async () => 7,
    },
  };
}

test('exports plain-text soft cap + markdown tldr max so the tool boundary stays in sync', () => {
  assert.equal(typeof PLAIN_TEXT_SOFT_CAP_CHARS, 'number');
  assert.equal(typeof MARKDOWN_TLDR_MAX_CHARS, 'number');
  // Sanity: caps are tight enough to be meaningful + match the Rust constants
  // (lastid-core::types::mls). Keep these synchronized if either side changes.
  assert.ok(PLAIN_TEXT_SOFT_CAP_CHARS >= 500 && PLAIN_TEXT_SOFT_CAP_CHARS <= 5000);
  assert.equal(MARKDOWN_TLDR_MAX_CHARS, 140);
});

test('enqueueMarkdownSend writes a kind:markdown line with tldr + body', async () => {
  const id = await enqueueMarkdownSend({
    scope: SCOPE,
    operatorDid: OPERATOR,
    tldr: 'Found the leak',
    body: '# Root cause\n\nThe forwarder retains bus subs.',
  });
  const lines = await readOutboxLines();
  assert.equal(lines.length, 1);
  const req = JSON.parse(lines[0]);
  assert.equal(req.kind, 'markdown');
  assert.equal(req.operator_did, OPERATOR);
  assert.equal(req.tldr, 'Found the leak');
  assert.equal(req.body, '# Root cause\n\nThe forwarder retains bus subs.');
  assert.equal(req.id, id);
});

test('enqueueMarkdownSend trims whitespace on tldr', async () => {
  await enqueueMarkdownSend({
    scope: SCOPE,
    operatorDid: OPERATOR,
    tldr: '   tldr with whitespace   ',
    body: 'body',
  });
  const lines = await readOutboxLines();
  const req = JSON.parse(lines[0]);
  assert.equal(req.tldr, 'tldr with whitespace');
});

test('NEGATIVE: enqueueMarkdownSend rejects missing operatorDid', async () => {
  await assert.rejects(
    () => enqueueMarkdownSend({ scope: SCOPE, tldr: 'x', body: 'y' }),
    /operatorDid required/,
  );
});

test('NEGATIVE: enqueueMarkdownSend rejects whitespace-only tldr', async () => {
  await assert.rejects(
    () =>
      enqueueMarkdownSend({
        scope: SCOPE,
        operatorDid: OPERATOR,
        tldr: '   ',
        body: 'body',
      }),
    /tldr required/,
  );
});

test('NEGATIVE: enqueueMarkdownSend rejects empty body', async () => {
  await assert.rejects(
    () =>
      enqueueMarkdownSend({
        scope: SCOPE,
        operatorDid: OPERATOR,
        tldr: 'x',
        body: '',
      }),
    /body required/,
  );
});

test('drain encrypts a markdown request as {v:1,t:"markdown",p:JSON({tldr,body})} and sends with message_type=markdown', async () => {
  await recordGroup({
    scope: SCOPE,
    idpGroupId: IDP_GROUP,
    groupIdB64: 'gb-md',
    operatorDid: OPERATOR,
    deviceIds: [],
  });
  await enqueueMarkdownSend({
    scope: SCOPE,
    operatorDid: OPERATOR,
    tldr: 'Found the leak',
    body: '# Root cause',
  });

  const { captured, mls } = captureMls();
  const sentFrames = [];
  await drainOutbox({
    scope: SCOPE,
    mls,
    agentDid: AGENT,
    send: (frame) => sentFrames.push(frame),
  });

  // Envelope is the canonical {v,t,p} shape with t=markdown and p as JSON
  // string with tldr + body.
  assert.equal(captured.length, 1);
  const envelope = JSON.parse(captured[0]);
  assert.equal(envelope.v, 1);
  assert.equal(envelope.t, 'markdown');
  const payload = JSON.parse(envelope.p);
  assert.equal(payload.tldr, 'Found the leak');
  assert.equal(payload.body, '# Root cause');

  // WS frame carries message_type=markdown so the IdP relays it to clients
  // who can then route to the right bubble.
  assert.equal(sentFrames.length, 1);
  assert.equal(sentFrames[0].type, 'group_chat.message');
  assert.equal(sentFrames[0].payload.message_type, 'markdown');

  // Outbox cleared on success.
  assert.deepEqual(await readOutboxLines(), []);
});

test('drain on a text request still emits {v:1,t:"text",p:text} (no regression)', async () => {
  await recordGroup({
    scope: SCOPE,
    idpGroupId: IDP_GROUP,
    groupIdB64: 'gb-txt',
    operatorDid: OPERATOR,
    deviceIds: [],
  });
  await enqueueSend({ scope: SCOPE, operatorDid: OPERATOR, text: 'plain hi' });

  const { captured, mls } = captureMls();
  const sentFrames = [];
  await drainOutbox({
    scope: SCOPE,
    mls,
    agentDid: AGENT,
    send: (frame) => sentFrames.push(frame),
  });

  assert.equal(captured.length, 1);
  const envelope = JSON.parse(captured[0]);
  assert.equal(envelope.t, 'text');
  assert.equal(envelope.p, 'plain hi');
  assert.equal(sentFrames[0].payload.message_type, 'text');
});

test('drain processes a markdown request that was hand-appended to the outbox (forward-compat path)', async () => {
  await recordGroup({
    scope: SCOPE,
    idpGroupId: IDP_GROUP,
    groupIdB64: 'gb-mix',
    operatorDid: OPERATOR,
    deviceIds: [],
  });
  // Hand-craft a kind:markdown line at the same shape enqueueMarkdownSend
  // writes — guards against the drain blowing up on an outbox written by a
  // future plugin version that already supports markdown.
  const handCrafted = {
    id: 'manual-1',
    kind: 'markdown',
    operator_did: OPERATOR,
    tldr: 'manual tldr',
    body: 'manual body',
    enqueued_at: new Date().toISOString(),
  };
  await writeFile(outboxPath(), `${JSON.stringify(handCrafted)}\n`, { flag: 'a' });

  const { captured, mls } = captureMls();
  const sentFrames = [];
  await drainOutbox({
    scope: SCOPE,
    mls,
    agentDid: AGENT,
    send: (frame) => sentFrames.push(frame),
  });

  const envelope = JSON.parse(captured[0]);
  assert.equal(envelope.t, 'markdown');
  const payload = JSON.parse(envelope.p);
  assert.equal(payload.tldr, 'manual tldr');
  assert.equal(payload.body, 'manual body');
  assert.equal(sentFrames[0].payload.message_type, 'markdown');
});
