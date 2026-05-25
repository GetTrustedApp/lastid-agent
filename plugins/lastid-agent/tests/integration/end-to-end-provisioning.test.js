/**
 * End-to-end provisioning test — real, offline, deterministic.
 *
 * Drives the actual `provisionAgent` orchestrator through the full
 * OID4VCI agent-provisioning round-trip against an IN-PROCESS MOCK IdP
 * (node:http). No network, no native FFI, no skips.
 *
 * Why this is trustworthy and not a hollow fake:
 *   - The mock seals the slot seed to the agent's ephemeral key with
 *     `_internal.sealSlotSeed`, the exact byte-format inverse of the
 *     production `unsealSlotSeed` (same module, same constants — they
 *     cannot drift). So the agent's REAL unseal path is exercised.
 *   - `provisionAgent` independently re-derives the DID from the
 *     unsealed seed and refuses to continue unless it matches the
 *     agent_did the IdP claimed. A green run therefore PROVES the
 *     seal -> unseal -> Ed25519-derive -> DID chain end to end.
 *   - The mock verifies the agent's EdDSA OID4VCI proof JWT (signature
 *     against the embedded jwk + nonce + audience) before issuing,
 *     exercising the real `mintProofJwt` path.
 *
 * What it intentionally does NOT cover: verifying the issued VC's
 * signature against LastID's trust anchors — the provisioning client
 * doesn't do that (it's a separate concern), so faking it here would
 * make green LESS meaningful, not more.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

import {
  provisionAgent,
  _internal,
} from '../../lib/agent-provisioning.js';

const { sealSlotSeed, deriveAgentEd25519Keypair, agentDidFromPublicJwk } = _internal;

function fromB64url(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function didForSeed(slotSeed) {
  return agentDidFromPublicJwk(deriveAgentEd25519Keypair(slotSeed).publicJwk);
}

function readBody(req) {
  return new Promise((resolve) => {
    let buf = '';
    req.on('data', (c) => (buf += c));
    req.on('end', () => resolve(buf));
  });
}

/**
 * In-process mock IdP implementing the four agent-provisioning
 * endpoints. Options:
 *   slotSeed         32-byte Buffer the "wallet" will seal + bind.
 *   slotIndex        BIP85 slot to report (default 0).
 *   credential       the SD-JWT VC string to issue.
 *   pendingPolls     number of /poll calls to answer "pending" before approving.
 *   agentDidOverride return this DID at /poll instead of the seed's real DID
 *                    (to exercise provisionAgent's mismatch guard).
 *   rejectPoll       if true, /poll returns 410 (wallet rejected).
 */
async function startMockIdp(opts) {
  const {
    slotSeed,
    slotIndex = 0,
    credential = 'eyJ.mock-agent-vc.sig',
    pendingPolls = 0,
    agentDidOverride = null,
    rejectPoll = false,
  } = opts;

  const state = { ephemeralPubJwk: null, cNonce: null, issuer: null };
  const calls = { initiate: 0, poll: 0, token: 0, credential: 0 };
  let pollsSeen = 0;

  const server = http.createServer(async (req, res) => {
    const body = await readBody(req);
    const send = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };
    const issuer = `http://${req.headers.host}`;
    state.issuer = issuer;

    if (req.url === '/v1/oid4vci/agent-provision/initiate') {
      calls.initiate += 1;
      const json = JSON.parse(body);
      state.ephemeralPubJwk = json.ephemeral_pubkey_jwk;
      return send(200, {
        user_code: 'WXYZ-1234',
        expires_in: 600,
        device_code: 'device-abc',
      });
    }

    if (req.url === '/v1/oid4vci/agent-provision/poll') {
      calls.poll += 1;
      if (rejectPoll) return send(410, { error: 'rejected_by_operator' });
      if (pollsSeen++ < pendingPolls) return send(200, { status: 'pending' });

      const sealed = sealSlotSeed(slotSeed, state.ephemeralPubJwk);
      const agentDid = agentDidOverride ?? didForSeed(slotSeed);
      const offer = {
        credential_issuer: issuer,
        credential_configuration_ids: ['LastID.Agent.Base'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'pre-auth-xyz',
          },
        },
      };
      const offerUri =
        'openid-credential-offer://?credential_offer=' +
        encodeURIComponent(JSON.stringify(offer));
      return send(200, {
        status: 'approved',
        credential_offer_uri: offerUri,
        sealed_slot_seed: sealed,
        slot_index: slotIndex,
        agent_did: agentDid,
      });
    }

    if (req.url === '/v1/oid4vci/token') {
      calls.token += 1;
      state.cNonce = 'c-nonce-1';
      return send(200, {
        access_token: 'access-token-1',
        c_nonce: state.cNonce,
        c_nonce_expires_in: 120,
      });
    }

    if (req.url === '/v1/oid4vci/credential') {
      calls.credential += 1;
      // Verify the agent's real OID4VCI proof JWT before issuing.
      const { proof } = JSON.parse(body);
      const jwt = proof?.jwt ?? '';
      const [h, p, s] = jwt.split('.');
      const header = JSON.parse(fromB64url(h));
      const payload = JSON.parse(fromB64url(p));
      const sigOk =
        header.typ === 'openid4vci-proof+jwt' &&
        header.alg === 'EdDSA' &&
        cryptoVerify(
          null,
          Buffer.from(`${h}.${p}`, 'utf-8'),
          createPublicKey({ key: header.jwk, format: 'jwk' }),
          fromB64url(s),
        );
      if (!sigOk || payload.nonce !== state.cNonce || payload.aud !== state.issuer) {
        return send(400, { error: 'invalid_proof' });
      }
      return send(200, {
        credential,
        c_nonce: 'c-nonce-2',
        c_nonce_expires_in: 120,
      });
    }

    return send(404, { error: 'not_found' });
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    calls,
    close: () => new Promise((r) => server.close(r)),
  };
}

const FAST = { intervalSeconds: 0.01, timeoutSeconds: 5 };

test('provisions a fresh agent end-to-end against a mock IdP', async () => {
  const slotSeed = Buffer.alloc(32, 0x5a);
  const idp = await startMockIdp({ slotSeed, slotIndex: 3, credential: 'eyJ.real-looking-vc.sig' });
  try {
    const codes = [];
    const result = await provisionAgent({
      idpUrl: idp.url,
      parentHumanDid: 'did:lastid:zHumanOperatorExample',
      runtimeName: 'test-runtime',
      onUserCode: ({ userCode }) => codes.push(userCode),
      ...FAST,
    });

    // The DID the orchestrator returns must be the one derived from the
    // unsealed seed — and equal to what the mock bound.
    assert.equal(result.agentDid, didForSeed(slotSeed));
    assert.match(result.agentDid, /^did:lastid:agent:z/);
    // The unseal path recovered the exact seed the mock sealed.
    assert.ok(result.slotSeed.equals(slotSeed), 'unsealed slot seed must match');
    assert.equal(result.slotIndex, 3);
    assert.equal(result.vcCompact, 'eyJ.real-looking-vc.sig');
    // The operator-facing user code was surfaced exactly once.
    assert.deepEqual(codes, ['WXYZ-1234']);
    // Full protocol dance happened.
    assert.equal(idp.calls.initiate, 1);
    assert.ok(idp.calls.poll >= 1);
    assert.equal(idp.calls.token, 1);
    assert.equal(idp.calls.credential, 1);
  } finally {
    await idp.close();
  }
});

test('refuses to continue when the IdP-claimed agent_did does not match the unsealed seed', async () => {
  const slotSeed = Buffer.alloc(32, 0x11);
  const wrongDid = didForSeed(Buffer.alloc(32, 0x22)); // a different seed's DID
  const idp = await startMockIdp({ slotSeed, agentDidOverride: wrongDid });
  try {
    await assert.rejects(
      provisionAgent({
        idpUrl: idp.url,
        parentHumanDid: 'did:lastid:zHumanOperatorExample',
        onUserCode: () => {},
        ...FAST,
      }),
      /agent_did mismatch/,
    );
    // It must bail at the cross-check, before claiming a credential.
    assert.equal(idp.calls.credential, 0);
  } finally {
    await idp.close();
  }
});

test('drives the poll loop until the wallet approves', async () => {
  const slotSeed = Buffer.alloc(32, 0x3c);
  const idp = await startMockIdp({ slotSeed, pendingPolls: 2 });
  try {
    const result = await provisionAgent({
      idpUrl: idp.url,
      parentHumanDid: 'did:lastid:zHumanOperatorExample',
      onUserCode: () => {},
      ...FAST,
    });
    assert.equal(result.agentDid, didForSeed(slotSeed));
    assert.ok(idp.calls.poll >= 3, `expected >=3 polls, got ${idp.calls.poll}`);
  } finally {
    await idp.close();
  }
});

test('surfaces a wallet rejection (410) as a thrown error', async () => {
  const idp = await startMockIdp({ slotSeed: Buffer.alloc(32, 0x09), rejectPoll: true });
  try {
    await assert.rejects(
      provisionAgent({
        idpUrl: idp.url,
        parentHumanDid: 'did:lastid:zHumanOperatorExample',
        onUserCode: () => {},
        ...FAST,
      }),
      /rejected/,
    );
    assert.equal(idp.calls.credential, 0);
  } finally {
    await idp.close();
  }
});
