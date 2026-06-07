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
  brokerSocketPath,
  brokerTokenPath,
  brokerRuntimeDir,
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
