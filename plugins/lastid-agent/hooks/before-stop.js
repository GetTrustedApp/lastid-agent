#!/usr/bin/env node
/**
 * BeforeStop hook.
 *
 * Flushes any buffered audit records to the IdP's audit endpoint
 * before the session terminates. Audit emission is best-effort —
 * failures here MUST NOT block session shutdown.
 */

import { flushAuditLog } from '../lib/audit-log.js';

export default async function beforeStop(_context) {
  try {
    await flushAuditLog();
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] audit-log flush failed: ${err?.message ?? err}\n`
    );
  }
  return { ok: true };
}
