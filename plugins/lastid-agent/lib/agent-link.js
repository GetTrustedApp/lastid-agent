/**
 * Agent-link client.
 *
 * Calls the IdP's public `/v1/verify/agent-link/initiate` endpoint,
 * renders the returned presentation-request URI as a QR code, polls
 * `/v1/verify/agent-link/poll/:link_id` until the operator has scanned
 * with their LastID wallet, and decodes the subject DID from the
 * returned SD-JWT presentation. Zero OAuth registration — the IdP shim
 * accepts unauthenticated initiate calls, rate-limited by IP.
 *
 * QR delivery: writes a PNG to a temp file and opens it in the host's
 * default image viewer (macOS Preview, Linux xdg-open, Windows start)
 * so the operator sees a clean, full-size QR even when the launching
 * terminal hides or truncates output. A small ASCII QR is also written
 * to stdout as a fallback, plus the `lastid://` deep link in plain
 * text for taps on the device that holds LastID.
 */
import qrcodeTerminal from 'qrcode-terminal';
import QRCode from 'qrcode';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

// Default to dev while the agent-link routes are pre-production. Flip
// to `https://human.lastid.co` once the IdP changes ship to prod.
// Override per-host with `--idp <url>` or `LASTID_IDP_URL`.
const DEFAULT_IDP = 'https://human.dev.lastid.co';

function b64urlDecode(seg) {
  const padded = seg + '='.repeat((4 - (seg.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Decode the subject DID from a single compact SD-JWT VC string. The
 * issuer JWT is the first `.`-separated segment of whatever sits
 * before the first `~` (disclosures / KB-JWT separator).
 */
function decodeSdJwtVcClaims(compact) {
  const issuerJwt = compact.split('~')[0];
  const parts = issuerJwt.split('.');
  if (parts.length < 2) {
    throw new Error('vp_token element does not look like a JWT');
  }
  const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf-8'));
  return payload;
}

/**
 * Decode the subject DID from an OpenID4VP `vp_token`. The IdP returns
 * a string for single-credential presentations and a JSON array for
 * multi-credential presentations (per OID4VP). We pick the LastID.Base
 * credential when an array is returned — that's the identity-grade
 * credential whose `sub` is the operator's canonical DID; other
 * credential types (Persona, VerifiedEmail, etc.) bind to the same
 * subject so a fallback to the first element is also safe.
 */
function decodeSubjectDidFromVpToken(vpToken) {
  if (!vpToken) {
    throw new Error('vp_token missing from poll response');
  }

  const candidates = Array.isArray(vpToken) ? vpToken : [vpToken];
  if (candidates.length === 0) {
    throw new Error('vp_token array is empty');
  }

  let chosen = null;
  let chosenPayload = null;
  for (const compact of candidates) {
    if (typeof compact !== 'string') continue;
    let payload;
    try {
      payload = decodeSdJwtVcClaims(compact);
    } catch {
      continue;
    }
    if (payload.vct === 'LastID.Base') {
      chosen = compact;
      chosenPayload = payload;
      break;
    }
    if (!chosen) {
      chosen = compact;
      chosenPayload = payload;
    }
  }

  if (!chosen || !chosenPayload) {
    throw new Error('no decodable SD-JWT VC found in vp_token');
  }
  if (typeof chosenPayload.sub !== 'string' || chosenPayload.sub.length === 0) {
    throw new Error('presentation has no sub (subject DID)');
  }
  return {
    subjectDid: chosenPayload.sub,
    iss: chosenPayload.iss,
    vct: chosenPayload.vct,
  };
}

function toWalletDeepLink(requestUri) {
  return `lastid://present?url=${encodeURIComponent(requestUri)}`;
}

/**
 * Try to open `path` with the host's default file/URL opener. Fire and
 * forget — on failure we just skip; the terminal QR + deep link still
 * work as fallback paths.
 */
function openWithDefault(path) {
  const candidates =
    process.platform === 'darwin'
      ? [['open', [path]]]
      : process.platform === 'win32'
        ? [['cmd', ['/c', 'start', '""', path]]]
        : [
            ['xdg-open', [path]],
            ['gio', ['open', path]],
          ];
  for (const [cmd, args] of candidates) {
    try {
      const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
      child.on('error', () => {});
      child.unref();
      return true;
    } catch {
      // try next candidate
    }
  }
  return false;
}

async function renderQrPng(uri) {
  const dir = mkdtempSync(join(tmpdir(), 'lastid-agent-qr-'));
  const path = join(dir, 'lastid-agent-link.png');
  const buf = await QRCode.toBuffer(uri, {
    type: 'png',
    margin: 2,
    width: 480,
    errorCorrectionLevel: 'M',
  });
  writeFileSync(path, buf);
  return path;
}

/**
 * Drive the agent-link flow end-to-end. Renders a QR (opens PNG in
 * default viewer + writes ASCII to stdout), polls until the wallet
 * presents the LastID.Base credential, and returns `{ subjectDid }`.
 * Throws on timeout / denial / expiry.
 */
export async function linkHumanDid({
  idpUrl,
  intervalSeconds = 3,
  timeoutSeconds = 300,
  onPrompt,
} = {}) {
  const idp = idpUrl ?? DEFAULT_IDP;

  const initiate = await fetch(`${idp}/v1/verify/agent-link/initiate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  if (!initiate.ok) {
    throw new Error(
      `agent-link initiate failed: ${initiate.status} ${await initiate.text()}`,
    );
  }
  const { link_id: linkId, request_uri: requestUri, expires_in: expiresIn } =
    await initiate.json();

  const deepLink = toWalletDeepLink(requestUri);

  if (typeof onPrompt === 'function') {
    onPrompt({ requestUri, deepLink, linkId, expiresIn });
  } else {
    console.log('');
    console.log('━━━ Link your LastID ━━━');
    console.log('');
    console.log(`Deep link (tap on phone):  ${deepLink}`);
    console.log(`Expires in:                ${expiresIn}s`);
    console.log('');
    let pngPath = null;
    try {
      pngPath = await renderQrPng(requestUri);
      const opened = openWithDefault(pngPath);
      if (opened) {
        console.log(`QR opened in default viewer: ${pngPath}`);
      } else {
        console.log(`QR saved to: ${pngPath}`);
      }
    } catch (err) {
      console.log(`(could not render QR PNG: ${err.message ?? err})`);
    }
    console.log('');
    console.log('Or scan this QR from the terminal:');
    console.log('');
    await new Promise((resolve) => {
      qrcodeTerminal.generate(requestUri, { small: true }, (out) => {
        console.log(out);
        resolve();
      });
    });
    console.log('Waiting for wallet…');
  }

  const intervalMs = intervalSeconds * 1000;
  const deadlineMs = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadlineMs) {
    const resp = await fetch(
      `${idp}/v1/verify/agent-link/poll/${encodeURIComponent(linkId)}`,
    );
    if (resp.status === 404) {
      throw new Error('agent-link request expired or was never created');
    }
    if (resp.ok) {
      const body = await resp.json();
      switch (body.state) {
        case 'fulfilled': {
          const decoded = decodeSubjectDidFromVpToken(body.vp_token);
          return { subjectDid: decoded.subjectDid, linkId };
        }
        case 'denied':
          throw new Error('operator denied the link request');
        case 'expired':
          throw new Error('agent-link request expired before approval');
        case 'pending':
        default:
          break;
      }
    }
    await delay(intervalMs);
  }
  throw new Error('agent-link timed out waiting for wallet');
}
