/**
 * Bug reporting — the agent relays a plugin bug to the LastID team.
 *
 * Privacy is the whole point: this sends ONLY what the operator agreed to —
 * their `summary`, optional `details`, optional `email` — plus the plugin
 * `version` (the one non-identifying field needed to triage a report to a
 * build). NO files, NO logs, NO system info, NO agent/identity DIDs, NO
 * encryption (it's not secret; it's a plain POST to the IdP). The consent flow
 * (ask before sending, offer email, reassure no system data) lives in the
 * tool's description so the model gates it; this module just builds the minimal
 * payload and posts it.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const BUG_REPORT_PATH = '/v1/bug-report';

const SUMMARY_MAX = 2000;
const DETAILS_MAX = 8000;
const EMAIL_MAX = 320;

/** The plugin's own version (from plugin.json) — the ONLY non-operator field we
 *  attach, so a report maps to a build. Best-effort; null if unreadable. */
export function pluginVersion() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const manifest = JSON.parse(
      readFileSync(join(here, '..', '.claude-plugin', 'plugin.json'), 'utf-8'),
    );
    return typeof manifest.version === 'string' ? manifest.version : null;
  } catch {
    return null;
  }
}

// Self-redaction: we tell the operator "no secrets," but a model or a pasted
// stack trace can still slip one in. So we scrub the text OURSELVES before it
// leaves the device — defense in depth, independent of any synced operator
// rules (a customer hitting a provisioning bug may have none). Known
// secret SHAPES only (labeled key=value + well-known token formats); high
// over-redaction in a bug report is fine, a leaked credential is not.
const REDACTORS = [
  { re: /-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z0-9 ]*PRIVATE KEY-----/g, sub: () => '[REDACTED PRIVATE KEY]' },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, sub: () => '[REDACTED JWT]' }, // JWT / SD-JWT
  { re: /\bAKIA[0-9A-Z]{16}\b/g, sub: () => '[REDACTED]' }, // AWS access key id
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, sub: () => '[REDACTED]' }, // GitHub token
  { re: /\bsk-[A-Za-z0-9]{20,}\b/g, sub: () => '[REDACTED]' }, // sk- style api key
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, sub: () => '[REDACTED]' }, // Slack token
  // Labeled secret=value — keep the label, redact the value.
  {
    re: /((?:bearer|token|secret|password|passwd|pwd|api[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?)([^\s"',;]{6,})/gi,
    sub: (_m, label) => `${label}[REDACTED]`,
  },
];

/** Scrub known secret shapes from free text. Returns { text, count }. */
export function redactSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return { text: text ?? '', count: 0 };
  let count = 0;
  let out = text;
  for (const { re, sub } of REDACTORS) {
    out = out.replace(re, (...args) => {
      count += 1;
      return sub(...args);
    });
  }
  return { text: out, count };
}

/**
 * Build the EXACT payload sent to the IdP from operator-provided fields. Pure +
 * allowlist-only: the returned object can contain nothing but summary, source,
 * the optional details/email/plugin_version, and a redacted_count — there is no
 * path for system or identity data to leak in. Free-text fields are
 * SECRET-SCRUBBED (redactSecrets) before inclusion; email is left intact (it's
 * the operator's chosen contact, not a secret). Trims + length-caps each field.
 * Throws if there is no summary (nothing to report).
 */
export function buildBugReportPayload(report, version) {
  const rawSummary = String(report?.summary ?? '').trim();
  if (!rawSummary) {
    const e = new Error('a bug report needs a summary of what went wrong');
    e.code = 'ENOSUMMARY';
    throw e;
  }
  const s = redactSecrets(rawSummary.slice(0, SUMMARY_MAX));
  const payload = { summary: s.text, source: 'lastid-agent' };
  let redacted = s.count;
  const rawDetails = String(report?.details ?? '').trim();
  if (rawDetails) {
    const d = redactSecrets(rawDetails.slice(0, DETAILS_MAX));
    payload.details = d.text;
    redacted += d.count;
  }
  const email = String(report?.email ?? '').trim();
  if (email) payload.email = email.slice(0, EMAIL_MAX);
  if (version) payload.plugin_version = String(version);
  if (redacted > 0) payload.redacted_count = redacted;
  return payload;
}

/**
 * POST a bug report to the IdP. Plain HTTPS, unauthenticated (a customer who
 * hit a provisioning bug may not even have an agent yet). `fetchImpl` injectable
 * for tests. Returns { ok: true, id? } or throws with the server's reason.
 */
export async function submitBugReport({ idpUrl, report, version, fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('no fetch implementation available');
  if (!idpUrl) throw new Error('no idpUrl for bug report');
  const payload = buildBugReportPayload(report, version ?? pluginVersion());
  let res;
  try {
    res = await fetchImpl(`${idpUrl}${BUG_REPORT_PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      ...(typeof AbortSignal?.timeout === 'function' ? { signal: AbortSignal.timeout(8000) } : {}),
    });
  } catch (err) {
    throw new Error(`bug report failed to send: ${err?.message ?? err}`);
  }
  const okStatus = res?.ok === true || (typeof res?.status === 'number' && res.status >= 200 && res.status < 300);
  if (!okStatus) {
    let detail = '';
    try {
      detail = typeof res?.text === 'function' ? await res.text() : '';
    } catch {
      /* ignore */
    }
    throw new Error(`bug report rejected by server (${res?.status ?? '?'})${detail ? `: ${detail}` : ''}`);
  }
  let id = null;
  try {
    const body = typeof res?.json === 'function' ? await res.json() : null;
    id = body?.id ?? null;
  } catch {
    /* a 2xx with no/odd body is still success */
  }
  return { ok: true, id };
}
