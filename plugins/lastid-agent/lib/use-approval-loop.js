/**
 * Use-approval orchestration.
 *
 * When the desktop's vault_use returns `policy_approval_required`, the
 * plugin drives the cross-device approval flow transparently:
 *
 *   1. Read the structured `approval_request` payload the desktop
 *      built (binds agent_did, parent_human_did, share_id, reason,
 *      session_id, project_fingerprint).
 *   2. POST it to the IdP's /v1/agent-use-approvals (agent VC + DPoP).
 *      The IdP creates a pending row and broadcasts a WS event to
 *      the operator's wallets.
 *   3. Poll GET /v1/agent-use-approvals/:approval_id every few seconds
 *      until status changes, or the pending TTL elapses.
 *   4. Verify the decision_jws_compact locally via wasm (defense in
 *      depth — desktop will re-verify authoritatively).
 *   5. Retry the original vault_use call with approval_id +
 *      decision_jws_compact + operator_delegation_jwk_x/y.
 *
 * The orchestrator hides the round-trip from the LLM. From the agent
 * runtime's view, vault_use just blocks for up to ~5 minutes; either
 * it returns the handle or a structured denial.
 */

import { initializeSdkBindings } from './sdk-bindings.js';
import { authedIdpFetch } from './mls-groups-api.js';

const IDP_BASE_URL = process.env.LASTID_IDP_URL ?? 'https://human.lastid.co';
const POLL_INTERVAL_MS = 3000;
const PENDING_TTL_MS = 5 * 60 * 1000;

/**
 * Detects whether a vault_use MCP result is a structured
 * `policy_approval_required` rejection. Returns the parsed body on
 * yes, null on no. Tolerant of MCP's content/isError result shape.
 */
export function parseApprovalRequiredResult(result) {
  if (!result || !Array.isArray(result.content)) return null;
  const text = result.content.find((c) => c?.type === 'text')?.text;
  if (typeof text !== 'string' || text.length === 0) return null;
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return null;
  }
  if (
    body?.error === 'policy_approval_required' &&
    body?.approval_request &&
    typeof body.approval_request === 'object'
  ) {
    return body;
  }
  return null;
}

/**
 * Create an approval row at the IdP. Returns { approval_id, expires_at,
 * pending_ttl_secs } on success. Throws on any HTTP failure — caller
 * is responsible for surfacing the error to the agent.
 */
async function createApprovalRow({
  request,
  agentDid,
  vcCompact,
  signingKey,
  _authedIdpFetch = authedIdpFetch,
}) {
  if (!vcCompact) {
    throw new Error(
      'use-approval: no agent VC available — agent must be provisioned',
    );
  }
  // Broker-native has null signingKey; the broker mints the DPoP via authedIdpFetch.
  // Shared, broker-aware authedIdpFetch (FORK1): same Bearer + DPoP legacy
  // shaping, broker resource-token when enabled. Throws on non-2xx (caller
  // surfaces it). Scope is ambient (getActiveScope).
  return _authedIdpFetch({
    idpUrl: IDP_BASE_URL,
    method: 'POST',
    path: '/v1/agent-use-approvals',
    body: request,
    agentDid,
    vcCompact,
    signingKey,
  });
}

/**
 * Poll GET /:approval_id until status leaves 'pending'. Returns the
 * row on success. Throws on timeout or HTTP errors.
 */
async function pollApprovalRow({
  approvalId,
  agentDid,
  vcCompact,
  signingKey,
  intervalMs = POLL_INTERVAL_MS,
  timeoutMs = PENDING_TTL_MS,
}) {
  const deadlineMs = Date.now() + timeoutMs;
  const path = `/v1/agent-use-approvals/${encodeURIComponent(approvalId)}`;
  while (Date.now() < deadlineMs) {
    // Shared, broker-aware authedIdpFetch (FORK1) per poll — the legacy path
    // mints a fresh DPoP each time (iat stays in the IdP's ±60s window); the
    // broker path refreshes its resource-token internally. 404 → row vanished.
    let row;
    try {
      row = await authedIdpFetch({
        idpUrl: IDP_BASE_URL,
        method: 'GET',
        path,
        agentDid,
        vcCompact,
        signingKey,
      });
    } catch (e) {
      if (e?.status === 404) throw new Error('use-approval: row vanished mid-poll');
      throw e;
    }
    if (row.status && row.status !== 'pending') {
      return row;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error('use-approval: operator did not decide within the pending window');
}

/**
 * Drive the full approval round-trip. Returns either:
 *   - { retryArgs: {...} }  when the operator approved
 *   - { denied: true, body } when the operator denied
 *   - { expired: true }     when the pending window elapsed
 * Caller (the MCP server's tools/call interceptor) plugs `retryArgs`
 * into a second invocation of the desktop's vault_use.
 */
export async function runApprovalLoop({
  approvalBody,
  originalArgs,
  agentDid,
  vcCompact,
  signingKey,
  _authedIdpFetch = authedIdpFetch,
}) {
  const request = approvalBody.approval_request;
  let created;
  try {
    created = await createApprovalRow({
      request,
      agentDid,
      vcCompact,
      signingKey,
      _authedIdpFetch,
    });
  } catch (err) {
    return {
      denied: true,
      body: {
        error: 'policy_approval_create_failed',
        reason_detail: err.message,
      },
    };
  }
  const approvalId = created.approval_id;

  let row;
  try {
    row = await pollApprovalRow({
      approvalId,
      agentDid,
      vcCompact,
      signingKey,
    });
  } catch (err) {
    if (err.message?.includes('did not decide')) {
      return { expired: true };
    }
    return {
      denied: true,
      body: {
        error: 'policy_approval_poll_failed',
        reason_detail: err.message,
      },
    };
  }

  if (row.status === 'denied') {
    return {
      denied: true,
      body: {
        error: 'policy_approval_denied',
        reason_detail: 'operator denied the approval',
      },
    };
  }
  if (row.status !== 'approved') {
    return {
      denied: true,
      body: {
        error: 'policy_approval_unexpected_status',
        reason_detail: `status=${row.status}`,
      },
    };
  }

  const operatorJwk = row.operator_delegation_jwk;
  if (
    !operatorJwk ||
    typeof operatorJwk.x_b64u !== 'string' ||
    typeof operatorJwk.y_b64u !== 'string'
  ) {
    return {
      denied: true,
      body: {
        error: 'policy_approval_missing_operator_jwk',
        reason_detail:
          'IdP returned an approved row without operator_delegation_jwk',
      },
    };
  }
  if (typeof row.decision_jws_compact !== 'string') {
    return {
      denied: true,
      body: {
        error: 'policy_approval_missing_jws',
        reason_detail:
          'IdP returned an approved row without decision_jws_compact',
      },
    };
  }

  // Defense in depth: verify the JWS locally before forwarding to the
  // desktop. The desktop will re-verify authoritatively; catching a
  // poisoned IdP response here keeps the agent from racing.
  try {
    const sdk = await initializeSdkBindings();
    sdk.verifyDecisionJws({
      jwsCompact: row.decision_jws_compact,
      operatorJwkXB64u: operatorJwk.x_b64u,
      operatorJwkYB64u: operatorJwk.y_b64u,
      nowEpochSec: Math.floor(Date.now() / 1000),
      expectedApprovalId: approvalId,
      expectedParentHumanDid: request.parent_human_did,
      expectedAgentDid: agentDid,
      expectedShareId: request.share_id,
    });
  } catch (err) {
    return {
      denied: true,
      body: {
        error: 'policy_approval_jws_invalid',
        reason_detail: `plugin-side verify failed: ${err.message ?? err}`,
      },
    };
  }

  return {
    retryArgs: {
      ...originalArgs,
      approval_id: approvalId,
      decision_jws_compact: row.decision_jws_compact,
      operator_delegation_jwk_x_b64u: operatorJwk.x_b64u,
      operator_delegation_jwk_y_b64u: operatorJwk.y_b64u,
    },
  };
}
