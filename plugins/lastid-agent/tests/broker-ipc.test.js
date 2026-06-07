/**
 * Tests for lib/broker-ipc.js — the plugin → signed-broker IPC client.
 *
 * No real broker is spawned. We stand up a REAL unix-domain socket server on a
 * temp path that speaks the NDJSON wire contract (src/protocol.rs), so the tests
 * exercise the actual framing/parse — request shape in, {status,body} out — the
 * way the live broker would, plus the transport-failure path.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync, mkdirSync, writeFileSync } from 'node:fs';

import {
  brokerIpcCall,
  brokerIdpFetch,
  brokerHealth,
  brokerAvailable,
  brokerSignAgentRecord,
  brokerDecryptContent,
  brokerDeriveSubAgentSeed,
  brokerSignParentAuthorization,
  brokerSocketPath,
  brokerTokenPath,
  brokerRuntimeDir,
  brokerSocketExistsSync,
  BrokerWsTransport,
  brokerProvisionInitiate,
  brokerProvisionPoll,
  brokerDeriveMlsStateKey,
} from '../lib/broker-ipc.js';

let _n = 0;
function tmpSock() {
  _n += 1;
  // Keep the path short — macOS caps unix socket paths at ~104 bytes.
  return join(tmpdir(), `lidbrk-${process.pid}-${_n}.sock`);
}

/**
 * Start a unix-socket server that reads ONE newline-delimited request, hands the
 * parsed object to `respond(req)`, and writes back `respond`'s return value as a
 * JSON line. If `respond` returns null, the server closes WITHOUT replying (to
 * exercise the transport-failure path). Returns { socketPath, received, close }.
 */
async function startServer(respond) {
  const socketPath = tmpSock();
  try {
    rmSync(socketPath, { force: true });
  } catch {
    /* ignore */
  }
  const received = [];
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      const req = JSON.parse(line);
      received.push(req);
      const res = respond(req);
      if (res === null) {
        sock.end(); // close with no response — transport failure on the client
        return;
      }
      sock.write(`${JSON.stringify(res)}\n`);
      sock.end();
    });
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  return {
    socketPath,
    received,
    close: () =>
      new Promise((resolve) => {
        server.close(() => {
          try {
            rmSync(socketPath, { force: true });
          } catch {
            /* ignore */
          }
          resolve();
        });
      }),
  };
}

test('brokerAvailable: true only when BOTH socket + token exist for the scope', async () => {
  const scope = `__brk_avail_test_${process.pid}`;
  const dir = brokerRuntimeDir(scope);
  try {
    assert.equal(await brokerAvailable(scope), false, 'absent → false');
    mkdirSync(dir, { recursive: true });
    writeFileSync(brokerSocketPath(scope), ''); // a plain file stands in for the socket node
    assert.equal(await brokerAvailable(scope), false, 'socket only → false');
    writeFileSync(brokerTokenPath(scope), 'tok');
    assert.equal(await brokerAvailable(scope), true, 'socket + token → true');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('path helpers follow the ~/.lastid-agent/<scope> convention', () => {
  assert.ok(brokerRuntimeDir('main').endsWith('/.lastid-agent/main'));
  assert.ok(brokerSocketPath('alpha').endsWith('/.lastid-agent/alpha/broker.sock'));
  assert.ok(brokerTokenPath('alpha').endsWith('/.lastid-agent/alpha/broker.token'));
});

test('brokerIpcCall: idp_call sends the exact wire shape (kind tag, auth_token, method/path/body)', async () => {
  const srv = await startServer(() => ({ id: 'x', ok: true, status: 200, body: { ok: 1 } }));
  try {
    await brokerIpcCall({
      socketPath: srv.socketPath,
      token: 'tok-123',
      kind: 'idp_call',
      method: 'POST',
      path: '/v1/groups',
      body: { a: 1 },
    });
    const req = srv.received[0];
    assert.equal(req.kind, 'idp_call', 'discriminator field is `kind` (serde tag), not `op`');
    assert.equal(req.auth_token, 'tok-123');
    assert.equal(req.method, 'POST');
    assert.equal(req.path, '/v1/groups');
    assert.deepEqual(req.body, { a: 1 });
    assert.equal(typeof req.id, 'string');
  } finally {
    await srv.close();
  }
});

test('brokerIpcCall: health omits method/path/body', async () => {
  const srv = await startServer(() => ({ id: 'x', ok: true, status: 200, body: { device_provisioned: true } }));
  try {
    const resp = await brokerHealth({ socketPath: srv.socketPath, token: 't' });
    assert.equal(srv.received[0].kind, 'health');
    assert.ok(!('method' in srv.received[0]));
    assert.ok(!('path' in srv.received[0]));
    assert.equal(resp.body.device_provisioned, true);
  } finally {
    await srv.close();
  }
});

test('brokerIdpFetch: 2xx → returns the parsed body', async () => {
  const srv = await startServer(() => ({ id: 'x', ok: true, status: 200, body: { devices: [] } }));
  try {
    const body = await brokerIdpFetch({
      socketPath: srv.socketPath,
      token: 't',
      method: 'GET',
      path: '/v1/identity/devices',
    });
    assert.deepEqual(body, { devices: [] });
  } finally {
    await srv.close();
  }
});

test('brokerIdpFetch: empty 2xx body → {}', async () => {
  const srv = await startServer(() => ({ id: 'x', ok: true, status: 204 }));
  try {
    const body = await brokerIdpFetch({ socketPath: srv.socketPath, token: 't', method: 'DELETE', path: '/v1/x' });
    assert.deepEqual(body, {});
  } finally {
    await srv.close();
  }
});

test('brokerIdpFetch: non-2xx → throws with HTTP status + body text (authedIdpFetch contract)', async () => {
  const srv = await startServer(() => ({ id: 'x', ok: true, status: 404, body: { error: 'not_found' } }));
  try {
    await assert.rejects(
      brokerIdpFetch({ socketPath: srv.socketPath, token: 't', method: 'GET', path: '/v1/groups/zzz' }),
      (err) => {
        assert.match(err.message, /GET \/v1\/groups\/zzz failed: HTTP 404/);
        assert.match(err.message, /not_found/);
        return true;
      },
    );
  } finally {
    await srv.close();
  }
});

test('brokerIdpFetch: broker-layer error → throws with the broker error code', async () => {
  const srv = await startServer(() => ({
    id: 'x',
    ok: false,
    error: { code: 'device_not_provisioned', message: 'no SE key yet' },
  }));
  try {
    await assert.rejects(
      brokerIdpFetch({ socketPath: srv.socketPath, token: 't', method: 'GET', path: '/v1/x' }),
      (err) => {
        assert.match(err.message, /broker device_not_provisioned/);
        return true;
      },
    );
  } finally {
    await srv.close();
  }
});

test('brokerIpcCall: server closes with no response → rejects (transport failure)', async () => {
  const srv = await startServer(() => null); // accept, read, close without replying
  try {
    await assert.rejects(
      brokerIpcCall({ socketPath: srv.socketPath, token: 't', kind: 'health' }),
      /broker ipc: broker closed connection without a response/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerIpcCall: unconnectable socket → rejects (no hang)', async () => {
  await assert.rejects(
    brokerIpcCall({
      socketPath: join(tmpdir(), `lidbrk-nope-${process.pid}.sock`),
      token: 't',
      kind: 'health',
      timeoutMs: 1000,
    }),
    /broker ipc:/,
  );
});

test('brokerSignAgentRecord: sends kind=sign_agent_record + base64url(JSON(claims)), returns the jws', async () => {
  const srv = await startServer((req) => {
    // Echo a fake JWS so we can assert the request shape + return path.
    return { id: req.id, ok: true, status: 200, body: { jws: 'h.p.s' } };
  });
  try {
    const claims = { kind: 'memory', id: 'm1', version: 3 };
    const jws = await brokerSignAgentRecord({ socketPath: srv.socketPath, token: 't', claims });
    assert.equal(jws, 'h.p.s');
    const req = srv.received[0];
    assert.equal(req.kind, 'sign_agent_record');
    // payload_b64 MUST equal node's own base64url(JSON.stringify(claims)) — the
    // broker signs exactly these bytes, so node owns the canonicalization.
    const expected = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
    assert.equal(req.payload_b64, expected);
    assert.ok(!('method' in req), 'no idp_call fields leak in');
  } finally {
    await srv.close();
  }
});

test('brokerSignAgentRecord: accepts a precomputed payloadB64 verbatim', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { jws: 'a.b.c' } }));
  try {
    await brokerSignAgentRecord({ socketPath: srv.socketPath, token: 't', payloadB64: 'PRECOMPUTED' });
    assert.equal(srv.received[0].payload_b64, 'PRECOMPUTED');
  } finally {
    await srv.close();
  }
});

test('brokerSignAgentRecord: broker error → throws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: false, error: { code: 'bad_request', message: 'nope' } }));
  try {
    await assert.rejects(
      brokerSignAgentRecord({ socketPath: srv.socketPath, token: 't', claims: { a: 1 } }),
      /sign_agent_record failed: broker bad_request/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerSignAgentRecord: a non-JWS body → throws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { jws: 'not-a-jws' } }));
  try {
    await assert.rejects(
      brokerSignAgentRecord({ socketPath: srv.socketPath, token: 't', claims: { a: 1 } }),
      /unexpected broker response/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerDecryptContent: slot-tier sends kind=decrypt_agent_content + envelope_b64, returns plaintext Buffer', async () => {
  const pt = Buffer.from('hello plaintext', 'utf8');
  const srv = await startServer((req) => ({
    id: req.id,
    ok: true,
    status: 200,
    body: { plaintext_b64: pt.toString('base64') },
  }));
  try {
    const out = await brokerDecryptContent({ socketPath: srv.socketPath, token: 't', envelopeB64: 'RU5W' });
    assert.ok(Buffer.isBuffer(out));
    assert.equal(out.toString('utf8'), 'hello plaintext');
    const req = srv.received[0];
    assert.equal(req.kind, 'decrypt_agent_content');
    assert.equal(req.envelope_b64, 'RU5W');
    assert.ok(!('project_key' in req), 'no project_key for slot-tier');
  } finally {
    await srv.close();
  }
});

test('brokerDecryptContent: project tier includes routing_id (the wire id, not the repo name)', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { plaintext_b64: '' } }));
  try {
    await brokerDecryptContent({ socketPath: srv.socketPath, token: 't', envelopeB64: 'X', routingId: 'a1b2c3' });
    assert.equal(srv.received[0].routing_id, 'a1b2c3');
    assert.ok(!('project_key' in srv.received[0]), 'repo name never crosses the wire');
  } finally {
    await srv.close();
  }
});

test('brokerDecryptContent: broker error (wrong key / tamper) → throws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: false, error: { code: 'bad_request', message: 'aead failed' } }));
  try {
    await assert.rejects(
      brokerDecryptContent({ socketPath: srv.socketPath, token: 't', envelopeB64: 'X' }),
      /decrypt_agent_content failed: broker bad_request/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerDeriveSubAgentSeed: sends kind+class_slug+index, returns a 32-byte seed Buffer', async () => {
  const seed = Buffer.alloc(32, 7);
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { sub_seed_b64: seed.toString('base64') } }));
  try {
    const out = await brokerDeriveSubAgentSeed({ socketPath: srv.socketPath, token: 't', classSlug: 'refund-bot', index: 3 });
    assert.ok(Buffer.isBuffer(out) && out.length === 32);
    assert.ok(out.equals(seed));
    const req = srv.received[0];
    assert.equal(req.kind, 'derive_sub_agent_seed');
    assert.equal(req.class_slug, 'refund-bot');
    assert.equal(req.index, 3);
  } finally {
    await srv.close();
  }
});

test('brokerDeriveSubAgentSeed: a non-32-byte seed → throws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { sub_seed_b64: Buffer.alloc(8).toString('base64') } }));
  try {
    await assert.rejects(
      brokerDeriveSubAgentSeed({ socketPath: srv.socketPath, token: 't', classSlug: 'x', index: 0 }),
      /unexpected broker response/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerSignParentAuthorization: sends base64url(claimsJson), returns the jws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { jws: 'h.p.s' } }));
  try {
    const claimsJson = JSON.stringify({ iss: 'did:lastid:agent:zP', sub: 'did:lastid:agent:zS' });
    const jws = await brokerSignParentAuthorization({ socketPath: srv.socketPath, token: 't', claimsJson });
    assert.equal(jws, 'h.p.s');
    const req = srv.received[0];
    assert.equal(req.kind, 'sign_parent_authorization');
    assert.equal(req.payload_b64, Buffer.from(claimsJson, 'utf8').toString('base64url'));
  } finally {
    await srv.close();
  }
});

test('brokerSignParentAuthorization: broker error → throws', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: false, error: { code: 'not_implemented', message: 'no parent key' } }));
  try {
    await assert.rejects(
      brokerSignParentAuthorization({ socketPath: srv.socketPath, token: 't', claimsJson: '{}' }),
      /sign_parent_authorization failed: broker not_implemented/,
    );
  } finally {
    await srv.close();
  }
});

// ── MLS-custody: MLS state wrap-key through the broker ──────────────────────

test('brokerDeriveMlsStateKey: sends kind=derive_mls_state_key, returns a 32-byte key Buffer', async () => {
  const key = Buffer.alloc(32, 0x9c);
  const srv = await startServer((req) => ({
    id: req.id,
    ok: true,
    status: 200,
    body: { key_b64: key.toString('base64') },
  }));
  try {
    const out = await brokerDeriveMlsStateKey({ socketPath: srv.socketPath, token: 't' });
    assert.ok(Buffer.isBuffer(out) && out.length === 32);
    assert.ok(out.equals(key));
    assert.equal(srv.received[0].kind, 'derive_mls_state_key');
    assert.ok(!('method' in srv.received[0]), 'no idp_call fields leak in');
  } finally {
    await srv.close();
  }
});

test('brokerDeriveMlsStateKey: a non-32-byte key → throws', async () => {
  const srv = await startServer((req) => ({
    id: req.id,
    ok: true,
    status: 200,
    body: { key_b64: Buffer.alloc(16).toString('base64') },
  }));
  try {
    await assert.rejects(
      brokerDeriveMlsStateKey({ socketPath: srv.socketPath, token: 't' }),
      /unexpected broker response/,
    );
  } finally {
    await srv.close();
  }
});

test('brokerDeriveMlsStateKey: broker error → throws', async () => {
  const srv = await startServer((req) => ({
    id: req.id,
    ok: false,
    error: { code: 'not_implemented', message: 'no slot seed' },
  }));
  try {
    await assert.rejects(
      brokerDeriveMlsStateKey({ socketPath: srv.socketPath, token: 't' }),
      /derive_mls_state_key failed: broker not_implemented/,
    );
  } finally {
    await srv.close();
  }
});

// ── Phase 4: provisioning through the broker ────────────────────────────────

test('brokerProvisionInitiate: sends kind=provision_initiate + optional fields, returns the handle', async () => {
  const srv = await startServer((req) => ({
    id: req.id,
    ok: true,
    status: 200,
    body: { provision_id: 'pv-1', user_code: 'WXYZ-1234', expires_in: 600, verification_uri: null },
  }));
  try {
    const out = await brokerProvisionInitiate({
      socketPath: srv.socketPath,
      token: 't',
      runtimeName: 'test-runtime',
      projectHint: 'repo-x',
    });
    assert.equal(out.provisionId, 'pv-1');
    assert.equal(out.userCode, 'WXYZ-1234');
    assert.equal(out.expiresIn, 600);
    const req = srv.received[0];
    assert.equal(req.kind, 'provision_initiate');
    assert.equal(req.runtime_name, 'test-runtime');
    assert.equal(req.project_hint, 'repo-x');
    assert.ok(!('parent_human_did' in req), 'absent optional omitted');
  } finally {
    await srv.close();
  }
});

test('brokerProvisionPoll: pending → {status:pending}', async () => {
  const srv = await startServer((req) => ({ id: req.id, ok: true, status: 200, body: { status: 'pending' } }));
  try {
    const out = await brokerProvisionPoll({ socketPath: srv.socketPath, token: 't', provisionId: 'pv-1' });
    assert.deepEqual(out, { status: 'pending' });
    assert.equal(srv.received[0].kind, 'provision_poll');
    assert.equal(srv.received[0].provision_id, 'pv-1');
  } finally {
    await srv.close();
  }
});

test('brokerProvisionPoll: complete → carries agentDid/slotIndex/deviceId', async () => {
  const srv = await startServer((req) => ({
    id: req.id,
    ok: true,
    status: 200,
    body: { status: 'complete', agent_did: 'did:lastid:agent:zDnX', slot_index: 3, device_id: 'md-abc' },
  }));
  try {
    const out = await brokerProvisionPoll({ socketPath: srv.socketPath, token: 't', provisionId: 'pv-1' });
    assert.equal(out.status, 'complete');
    assert.equal(out.agentDid, 'did:lastid:agent:zDnX');
    assert.equal(out.slotIndex, 3);
    assert.equal(out.deviceId, 'md-abc');
  } finally {
    await srv.close();
  }
});

test('brokerProvisionPoll: wallet rejection (broker error) → throws', async () => {
  const srv = await startServer((req) => ({
    id: req.id,
    ok: false,
    error: { code: 'bad_request', message: 'provisioning rejected by wallet: rejected_by_operator' },
  }));
  try {
    await assert.rejects(
      brokerProvisionPoll({ socketPath: srv.socketPath, token: 't', provisionId: 'pv-1' }),
      /provision_poll failed: broker bad_request.*rejected by wallet/,
    );
  } finally {
    await srv.close();
  }
});

// ── op 3: BrokerWsTransport (broker-owns-WS streaming proxy) ─────────────────
//
// These drive the STREAMING wire (multiple NDJSON lines both ways on one
// connection), distinct from the single request/response `startServer` above.
// The server speaks the ws_open/ws_open_ok/ws_frame/ws_close/ws_error contract
// the Rust ws_proxy.rs implements, so the transport's framing + event surface
// is pinned exactly as the live broker would exercise it.

/**
 * A streaming unix-socket server: parses every NDJSON line the client sends into
 * `received`, invokes `onLine(msg, sock)` per line (so the test can script the
 * broker's replies), and exposes `push(obj)` to inject broker→node lines.
 */
async function startWsServer(onLine) {
  const socketPath = tmpSock();
  try {
    rmSync(socketPath, { force: true });
  } catch {
    /* ignore */
  }
  const received = [];
  let clientSock;
  const server = net.createServer((sock) => {
    clientSock = sock;
    let buf = '';
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        received.push(msg);
        onLine?.(msg, sock);
      }
    });
    sock.on('error', () => {});
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  return {
    socketPath,
    received,
    push: (obj) => clientSock?.write(`${JSON.stringify(obj)}\n`),
    close: () =>
      new Promise((resolve) => {
        server.close(() => {
          try {
            rmSync(socketPath, { force: true });
          } catch {
            /* ignore */
          }
          resolve();
        });
      }),
  };
}

const ackOpen = (msg, sock) => {
  if (msg.kind === 'ws_open') sock.write(`${JSON.stringify({ kind: 'ws_open_ok' })}\n`);
};

test('BrokerWsTransport: sends a ws_open (with auth_token) and emits open on ws_open_ok', async () => {
  const srv = await startWsServer(ackOpen);
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 'tok-x' });
    await once(t, 'open');
    assert.equal(t.readyState, BrokerWsTransport.OPEN);
    assert.equal(srv.received[0].kind, 'ws_open');
    assert.equal(srv.received[0].auth_token, 'tok-x');
    t.close();
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: inbound ws_frame → message event with base64-decoded bytes', async () => {
  const srv = await startWsServer(ackOpen);
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 't' });
    await once(t, 'open');
    const msgP = once(t, 'message');
    srv.push({ kind: 'ws_frame', data: Buffer.from('{"type":"hi"}', 'utf8').toString('base64'), binary: false });
    const [data] = await msgP;
    assert.ok(Buffer.isBuffer(data));
    assert.equal(data.toString('utf8'), '{"type":"hi"}');
    t.close();
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: send() writes a base64 ws_frame (binary:false) to the broker', async () => {
  const srv = await startWsServer(ackOpen);
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 't' });
    await once(t, 'open');
    const payload = JSON.stringify({ type: 'group_chat.fetch_queue' });
    t.send(payload);
    // Poll for the server to receive the frame line.
    for (let i = 0; i < 100 && !srv.received.some((m) => m.kind === 'ws_frame'); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const frame = srv.received.find((m) => m.kind === 'ws_frame');
    assert.ok(frame, 'broker received a ws_frame');
    assert.equal(frame.binary, false);
    assert.equal(Buffer.from(frame.data, 'base64').toString('utf8'), payload);
    t.close();
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: ws_error with http_status replays unexpected-response (revocation classifier survives the broker) then closes', async () => {
  const body = JSON.stringify({ error: 'invalid_token', error_description: 'Credential has been revoked' });
  const srv = await startWsServer((msg, sock) => {
    if (msg.kind === 'ws_open') {
      sock.write(
        `${JSON.stringify({ kind: 'ws_error', message: 'ws upgrade failed: HTTP 401', http_status: 401, body })}\n`,
      );
    }
  });
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 't' });
    t.on('error', () => {}); // swallow — the close path is what matters
    // Attach the consumer SYNCHRONOUSLY (as ws-client does) so the fake body
    // stream's listeners are wired before its queued data/end fire. Use a manual
    // close listener — `events.once` would reject on the (expected) error emit.
    const chunks = [];
    let status;
    const drained = new Promise((resolve) => {
      t.on('unexpected-response', (_req, res) => {
        status = res.statusCode;
        res.on('data', (c) => chunks.push(c));
        res.on('end', resolve);
      });
    });
    const closeP = new Promise((resolve) => t.on('close', () => resolve()));
    await drained;
    assert.equal(status, 401);
    assert.equal(Buffer.concat(chunks).toString('utf8'), body);
    await closeP;
    assert.equal(t.readyState, BrokerWsTransport.CLOSED);
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: ws_close → close event with code + reason', async () => {
  const srv = await startWsServer((msg, sock) => {
    if (msg.kind === 'ws_open') {
      sock.write(`${JSON.stringify({ kind: 'ws_open_ok' })}\n`);
      sock.write(`${JSON.stringify({ kind: 'ws_close', code: 1011, reason: 'bye' })}\n`);
    }
  });
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 't' });
    const [code, reason] = await once(t, 'close');
    assert.equal(code, 1011);
    assert.equal(reason.toString(), 'bye');
    assert.equal(t.readyState, BrokerWsTransport.CLOSED);
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: close() sends ws_close to the broker', async () => {
  const srv = await startWsServer(ackOpen);
  try {
    const t = new BrokerWsTransport({ socketPath: srv.socketPath, token: 't' });
    await once(t, 'open');
    t.close(1000, 'agent shutting down');
    for (let i = 0; i < 100 && !srv.received.some((m) => m.kind === 'ws_close'); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.ok(srv.received.some((m) => m.kind === 'ws_close'), 'broker received ws_close');
  } finally {
    await srv.close();
  }
});

test('BrokerWsTransport: unconnectable socket → emits close (degrades, never throws)', async () => {
  const t = new BrokerWsTransport({
    socketPath: join(tmpdir(), `lidbrk-none-${process.pid}.sock`),
    token: 't',
  });
  t.on('error', () => {}); // swallow — connect ENOENT is the expected trigger
  // Manual close listener: `events.once` would reject on the error emit.
  await new Promise((resolve) => t.on('close', () => resolve()));
  assert.equal(t.readyState, BrokerWsTransport.CLOSED);
});

test('brokerSocketExistsSync: true only when BOTH socket + token exist', () => {
  const scope = `__brk_sync_${process.pid}`;
  const dir = brokerRuntimeDir(scope);
  try {
    assert.equal(brokerSocketExistsSync(scope), false, 'absent → false');
    mkdirSync(dir, { recursive: true });
    writeFileSync(brokerSocketPath(scope), '');
    assert.equal(brokerSocketExistsSync(scope), false, 'socket only → false');
    writeFileSync(brokerTokenPath(scope), 'tok');
    assert.equal(brokerSocketExistsSync(scope), true, 'socket + token → true');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
