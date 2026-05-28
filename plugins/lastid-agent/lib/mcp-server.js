/**
 * LastID Agent MCP server.
 *
 * Single MCP surface the agent runtime sees. Owns the always-
 * available identity tools (e.g. `lastid_whoami`) and, when the
 * LastID Desktop wallet is running on the same host, transparently
 * merges in the desktop-published tool set (`vault_list` today;
 * vault_use / http_fetch / spawn_sub_agent later) so the agent only
 * has to think about tools, not transports.
 *
 * Discovery is best-effort: if no desktop is running, the agent
 * simply sees the local tools. The merge is computed on each
 * tools/list call so the desktop coming up later just starts
 * surfacing more tools without restarting the agent runtime.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { DesktopMcpClient } from './desktop-mcp-client.js';
import { deriveAgentEd25519Keypair } from './agent-provisioning.js';
import { loadAgentVc } from './keychain.js';
import { decodeVcClaims, hasCapability } from './vc-claims.js';
import {
  parseApprovalRequiredResult,
  runApprovalLoop,
} from './use-approval-loop.js';
import { reapStaleServers } from './reap-stale-servers.js';
import { MEMORY_TOOLS, MEMORY_TOOL_NAMES, handleMemoryTool } from './memory-tools.js';
import { CORE_REACTION_EMOJIS, isSupportedReaction } from './reactions.js';

const SERVER_INFO = {
  name: 'lastid-agent',
  version: '0.1.0',
};

// Each plugin tool carries a `requiredCapability` annotation: the
// exact { resource, action } pair the agent's VC must grant for the
// call to run. A null annotation means "no capability required" (e.g.
// reading your own identity). The dispatcher enforces this centrally
// — the tool body never has to re-check, and the LLM never gets to
// decide whether it "has" a capability. Add a tool, declare what it
// needs here, and enforcement is automatic.
const PLUGIN_TOOLS = [
  {
    name: 'lastid_whoami',
    description:
      'Return the agent identity provisioned for this host: agent DID, parent human DID, capabilities, expiry. Returns { provisioned: false } when no agent credential is present.',
    requiredCapability: null, // reading your own card needs nothing
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_send_message',
    description:
      'Send a message to the human you work with (your operator). The message is end-to-end encrypted and shows up in their LastID chat — console dock and phone. Just provide the text; you do not need to know anything about groups or keys. Returns once the message is queued for delivery.',
    requiredCapability: { resource: 'message:send', action: 'Send' },
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'What you want to say to your operator.',
        },
      },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_react',
    description:
      "React to your operator's most recent message with an emoji — a real reaction badge on that message in their LastID chat (console + phone), exactly like tapping one in the app. This COUNTS as a reply: use it alone for a quick acknowledgement (👍 got it, 🙏 thanks), or alongside lastid_send_message when a word plus a reaction fits. You don't pick which message or handle any ids — it reacts to the last thing the operator sent you. Pick the emoji that matches your intent: 👍 acknowledge/agree/done · ❤️ love it/thanks · 😂 that was funny · 😮 surprised/unexpected · 😢 found a bug/something's broken · 🙏 thank you/please.",
    requiredCapability: { resource: 'message:send', action: 'Send' },
    inputSchema: {
      type: 'object',
      properties: {
        emoji: {
          type: 'string',
          enum: CORE_REACTION_EMOJIS,
          description: 'The reaction to add: 👍 ❤️ 😂 😮 😢 🙏.',
        },
      },
      required: ['emoji'],
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_report_bug',
    description:
      'Report a bug in the LastID plugin to the LastID team. CONSENT-FIRST — only call this AFTER you have asked the operator: (1) do they want to report this bug, and (2) do they want to include their email for follow-up (optional). Reassure them that ONLY their description (and their email if they opt in), plus the plugin version, are sent — NO files, NO logs, NO system info, NO identity. Write a clear one-line `summary` of what went wrong; put error text / steps / expected-vs-actual in `details`. Never paste secrets, tokens, or system paths. Use when you hit a plugin/agent bug worth surfacing to the maintainers.',
    requiredCapability: null, // anyone can report a bug — even before provisioning
    inputSchema: {
      type: 'object',
      properties: {
        summary: {
          type: 'string',
          description: 'One-line description of the bug, approved by the operator.',
        },
        details: {
          type: 'string',
          description:
            'Optional: steps to reproduce, error text, expected vs actual. No secrets or system paths.',
        },
        email: {
          type: 'string',
          description:
            "Optional: the operator's email for follow-up. Include ONLY if they explicitly agreed.",
        },
      },
      required: ['summary'],
      additionalProperties: false,
    },
  },
  {
    name: 'vault_list',
    description:
      "List the vault credentials your operator has shared with you. Returns metadata ONLY — title, service, host, the injection method, constraints, and whether each requires per-use approval. You NEVER see the secret value: you can USE a shared credential (via the injection path) but never read it. Use this to discover what you can call on the operator's behalf.",
    requiredCapability: { resource: 'vault:use', action: 'Use' },
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_list_subagents',
    description:
      "List the subagents your operator authored under YOU (this parent agent). Returns each subagent's slug, name, scope, mode (stub/signed), and the Claude tool surface they were authored with. A subagent is a peer agent the operator signed into existence — invoking one runs a fresh Claude session bound to that subagent's identity. Use this to discover what subagents you can call via `lastid_invoke_subagent`.",
    requiredCapability: null,
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'lastid_invoke_subagent',
    description:
      "Invoke one of your subagents (find its slug via `lastid_list_subagents`). Spawns a fresh Claude session bound to the subagent's scope + system prompt, passes `input` as the user prompt, and returns the subagent's final assistant text. Use for delegated work where the subagent has tools/grants/capabilities scoped narrower (or sometimes broader) than yours — e.g. operator authored a Deploy Bot with `gh` access you don't have. The subagent's calls are logged under ITS DID in the audit chain, cross-referenced to your invocation. Default timeout 5min; opts.timeout_ms overrides.",
    requiredCapability: null,
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'Subagent slug from `lastid_list_subagents`.' },
        input: { type: 'string', description: 'What you want the subagent to do — passed verbatim as its user prompt.' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 30 * 60_000, description: 'Optional override; default 5 minutes.' },
      },
      required: ['slug', 'input'],
      additionalProperties: false,
    },
  },
  // Memory tools — served locally against the agent's own memory store
  // (lib/memory-store.js). These names override any same-named desktop
  // tools in the tools/list merge below, so memory is local-first.
  ...MEMORY_TOOLS,
];

const PLUGIN_TOOL_NAMES = new Set(PLUGIN_TOOLS.map((t) => t.name));
const PLUGIN_TOOL_CAPS = new Map(
  PLUGIN_TOOLS.map((t) => [t.name, t.requiredCapability ?? null]),
);

// vault_use + http_fetch run against the LOCAL listener (the SaaS / no-desktop
// path): the listener holds slot_seed, mints the handle + its keypair, fetches
// the JIT-wrapped secret from the IdP, opens it, injects, calls, and zeroizes —
// the secret never enters the model's context. Advertised ONLY when a desktop
// isn't already publishing them (a connected desktop wins, so we don't shadow
// its native vault). Routed via the vault unix-socket IPC, not handlePluginTool.
const LOCAL_VAULT_TOOLS = [
  {
    name: 'vault_use',
    description:
      'Mint a single-use, short-lived handle for a vault credential your operator shared with you (find its id via vault_list). Returns the handle + an injection summary + usage context — NEVER the secret value. Pass the handle to http_fetch to make the call. Mint a fresh handle per request.',
    requiredCapability: { resource: 'vault:use', action: 'Use' },
    inputSchema: {
      type: 'object',
      properties: {
        item_id: { type: 'string', description: 'The vault item id from vault_list.' },
        purpose: { type: 'string', description: 'Optional: why you need it (recorded for the operator).' },
      },
      required: ['item_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'http_fetch',
    description:
      'Make an outbound HTTP request with a vault credential attached. Pass the vault_handle from vault_use; the listener injects the credential at the network boundary (you never see it), makes the call, and returns the response. Single-use — the handle is consumed.',
    requiredCapability: { resource: 'vault:use', action: 'Use' },
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The full URL to request.' },
        vault_handle: { type: 'string', description: 'The handle returned by vault_use.' },
        method: { type: 'string', description: 'HTTP method (default GET).' },
        headers: { type: 'object', description: 'Extra request headers; the credential header is added by the listener.' },
        body: { type: 'string', description: 'Request body (POST/PUT/PATCH).' },
      },
      required: ['url', 'vault_handle'],
      additionalProperties: false,
    },
  },
];
const LOCAL_VAULT_TOOL_NAMES = new Set(LOCAL_VAULT_TOOLS.map((t) => t.name));

/**
 * Route vault_use / http_fetch to the LOCAL listener over the vault unix socket.
 * Capability (vault:use) is enforced HERE — the listener trusts this process.
 * vault_use drives the cross-device approval loop transparently when the share
 * requires per-use approval, the same as the desktop path.
 */
export async function handleLocalVault({ name, args, scope, loadedAgent, signingSeed, vaultRequest: injectedVaultRequest } = {}) {
  const wrap = (obj, isError = false) => ({
    content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }],
    ...(isError ? { isError: true } : {}),
  });
  if (!loadedAgent) {
    return wrap({ error: 'not_provisioned', message: 'run `lastid-agent provision` first' }, true);
  }
  const claims = decodeVcClaims(loadedAgent.vcCompact) ?? {};
  if (!hasCapability(claims, 'vault:use', 'Use')) {
    return wrap({ error: 'capability_denied', message: "this agent credential does not grant Use on 'vault:use'" }, true);
  }
  const vaultRequest = injectedVaultRequest ?? (await import('./vault-ipc.js')).vaultRequest;
  try {
    if (name === 'http_fetch') {
      const resp = await vaultRequest(scope, {
        op: 'http_fetch',
        vault_handle: args.vault_handle,
        url: args.url,
        ...(args.method ? { method: args.method } : {}),
        ...(args.headers ? { headers: args.headers } : {}),
        ...(args.body != null ? { body: args.body } : {}),
      });
      return wrap(resp, resp?.error != null);
    }
    // vault_use — pass the clock (time-window constraints) AND the working-
    // context scope map so scope_required constraints can match where the agent
    // is working (repo/cwd/host). Without the scope, a scoped share always
    // denies. Built from the sticky last-project + this cwd's git fingerprint.
    const { buildVaultUseScope } = await import('./vault-scope.js');
    const useScope = buildVaultUseScope({ scope });
    let resp = await vaultRequest(scope, {
      op: 'vault_use',
      item_id: args.item_id,
      ctx: { now_ms: Date.now(), scope: useScope },
    });
    if (resp?.policy_approval_required === true && signingSeed) {
      const outcome = await runApprovalLoop({
        approvalBody: resp,
        originalArgs: args,
        agentDid: loadedAgent.agentDid,
        vcCompact: loadedAgent.vcCompact,
        signingSeed,
      });
      if (outcome.retryArgs) {
        resp = await vaultRequest(scope, {
          op: 'vault_use',
          item_id: args.item_id,
          ctx: { now_ms: Date.now(), scope: useScope },
          approved: true,
          approval_id: outcome.retryArgs.approval_id,
        });
      } else if (outcome.expired) {
        return wrap({ error: 'policy_approval_expired', reason_detail: 'operator did not decide within the pending window' }, true);
      } else if (outcome.denied) {
        return wrap(outcome.body, true);
      }
    }
    return wrap(resp, resp?.error != null);
  } catch (e) {
    return wrap({ error: 'vault_local_failed', tool: name, message: e?.message ?? String(e) }, true);
  }
}

/**
 * Central capability gate. Throws if the tool declares a
 * `requiredCapability` the agent's VC doesn't grant. Called before any
 * plugin tool body runs, so authorization is enforced in one place by
 * code — not by the model's judgement.
 */
function enforceToolCapability(name, claims, loadedAgent) {
  const required = PLUGIN_TOOL_CAPS.get(name) ?? null;
  if (!required) return; // tool needs no capability
  if (!loadedAgent) {
    throw new Error(
      `not provisioned — run \`lastid-agent provision\` before using '${name}'`,
    );
  }
  if (hasCapability(claims, required.resource, required.action)) {
    process.stderr.write(
      `[lastid-agent] capability ok: '${name}' → ${required.action} ` +
        `on '${required.resource}'\n`,
    );
    return;
  }
  const granted = Array.isArray(claims?.capabilities)
    ? claims.capabilities.map((c) => c?.resource).filter(Boolean).join(', ')
    : '(none)';
  process.stderr.write(
    `[lastid-agent] capability DENIED: '${name}' needs ${required.action} ` +
      `on '${required.resource}'; granted: ${granted}\n`,
  );
  throw new Error(
    `capability denied: '${name}' requires ${required.action} on ` +
      `'${required.resource}', which this agent credential does not grant. ` +
      `Granted resources: ${granted}.`,
  );
}

async function handlePluginTool(name, _args, { scope, loadedAgent }) {
  // Decode the VC once, then run the authoritative capability gate
  // before any tool body. Authorization lives here, in code, driven by
  // each tool's `requiredCapability` annotation — never by the model.
  const claims = loadedAgent ? (decodeVcClaims(loadedAgent.vcCompact) ?? {}) : {};
  enforceToolCapability(name, claims, loadedAgent);

  if (MEMORY_TOOL_NAMES.has(name)) {
    return handleMemoryTool({ name, args: _args ?? {}, scope, loadedAgent, claims });
  }

  if (name === 'vault_list') {
    // Decode each SEALED cached share with the agent's slot_seed and return the
    // metadata view (secret stripped by vaultListView). Plaintext exists only
    // transiently here; it is NEVER returned to the model. The credential's
    // actual use (unfurl + inject) happens in the listener at http_fetch time.
    const { decryptedVaultViews } = await import('./vault-cache.js');
    const items = decryptedVaultViews(scope, loadedAgent.slotSeed);
    return { content: [{ type: 'text', text: JSON.stringify({ items }, null, 2) }] };
  }

  if (name === 'lastid_send_message') {
    const text = typeof _args?.text === 'string' ? _args.text : '';
    if (!text) {
      throw new Error('lastid_send_message requires text');
    }
    // Redact secret-shaped content before the message leaves the agent. The
    // operator's chat is end-to-end synced to all their devices, so a raw API
    // key / token the agent emitted must never ride along. This runs
    // server-side in the send handler (not a skippable hook), so it always
    // applies; it reuses the shared redactSecrets scrubber — the same patterns
    // as the audit + bug-report redaction.
    const { redactSecrets } = await import('./bug-report.js');
    const { text: safeText, count: redactedCount } = redactSecrets(text);
    // Resolve the operator (the agent's parent human) from the VC.
    // The LLM never sees a DID or a group id — it just says text.
    // (loadedAgent + message:send already verified by the gate above.)
    const operatorDid = claims.parent_human_did ?? null;
    if (!operatorDid) {
      throw new Error('agent VC has no parent_human_did — cannot resolve operator');
    }
    const { resolveActiveGroupForOperator } = await import('./agent-groups.js');
    const { enqueueSend } = await import('./agent-send.js');
    // No throw when there's no group: enqueue regardless. The listener
    // (single MLS-state writer) self-heals on drain — if no conversation
    // exists it creates one and invites the operator's devices, then
    // delivers this message. Enqueue keyed by operator DID so the drain
    // resolves the live group at send time.
    const group = await resolveActiveGroupForOperator({ scope, operatorDid });
    const id = await enqueueSend({ scope, operatorDid, text: safeText });
    const note = group
      ? 'Encrypted + delivered by your listener within a couple seconds. The operator sees it in their console chat and on their phone.'
      : "No conversation exists yet — your listener will establish one with the operator's devices, then deliver this. (If the listener isn't running, the message waits in the outbox until it is.)";
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              queued: true,
              request_id: id,
              establishing_conversation: !group,
              redacted_count: redactedCount,
              note,
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  if (name === 'lastid_react') {
    const emoji = typeof _args?.emoji === 'string' ? _args.emoji : '';
    // Validate against the shared reaction table (single source mirroring the
    // SDK's ReactionType). The tool's enum already constrains it, but a defensive
    // check keeps a bad value from riding to the listener as an undroppable line.
    if (!isSupportedReaction(emoji)) {
      throw new Error(
        `lastid_react: unsupported emoji ${JSON.stringify(emoji)} — use one of 👍 ❤️ 😂 😮 😢 🙏`,
      );
    }
    const operatorDid = claims.parent_human_did ?? null;
    if (!operatorDid) {
      throw new Error('agent VC has no parent_human_did — cannot resolve operator');
    }
    const { resolveActiveGroupForOperator } = await import('./agent-groups.js');
    const { enqueueReaction } = await import('./agent-send.js');
    const group = await resolveActiveGroupForOperator({ scope, operatorDid });
    const id = await enqueueReaction({ scope, operatorDid, emoji });
    const note = group
      ? 'Reaction queued — your listener will add the badge to the operator’s last message within a couple seconds (console + phone).'
      : "No conversation exists yet, so there's no message to react to — send a message first (lastid_send_message). The reaction is queued and will apply once a conversation exists and the operator has sent something.";
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            { queued: true, request_id: id, emoji, has_conversation: !!group, note },
            null,
            2,
          ),
        },
      ],
    };
  }

  if (name === 'lastid_list_subagents') {
    // Lists subagents installed under THIS scope (parent agent's scope).
    // The local index is the source of truth in stub mode; in signed mode
    // it's hydrated from the IdP on sync.
    const { listSubagents } = await import('./subagents.js');
    const subs = await listSubagents(scope);
    // Public projection — strip filesystem paths and internal bookkeeping
    // before showing to the agent. Path is useful for debugging via the
    // CLI but not something the parent agent should reason about.
    const publicSubs = subs.map((s) => ({
      slug: s.slug,
      name: s.name,
      scope: s.scope,
      mode: s.mode,
      id: s.id,
      installed_at: s.installed_at,
      claude_tools: s.claude_tools,
      mcp_allowed: s.mcp_allowed,
    }));
    return {
      content: [{ type: 'text', text: JSON.stringify({ subagents: publicSubs }, null, 2) }],
    };
  }

  if (name === 'lastid_invoke_subagent') {
    const slug = typeof _args?.slug === 'string' ? _args.slug : '';
    const input = typeof _args?.input === 'string' ? _args.input : '';
    const timeoutMs = Number.isInteger(_args?.timeout_ms) ? _args.timeout_ms : undefined;
    if (!slug) throw new Error('lastid_invoke_subagent: slug required');
    if (!input) throw new Error('lastid_invoke_subagent: input required');
    // SECURITY: defense-in-depth against argv flag smuggling. The current
    // spawn pipes input via stdin (not argv) so this is moot today, but if
    // a future refactor reintroduces a positional path, a leading '-' on
    // input would be parsed as a claude CLI flag (e.g. an input of
    // "--dangerously-skip-permissions" would flip that flag on). Refuse at
    // the boundary. See subagents.js buildSpawnArgs SECURITY comment.
    if (input.startsWith('-')) {
      throw new Error(
        'lastid_invoke_subagent: input must not start with "-" (argv-flag protection). Add a leading space or rephrase.',
      );
    }
    // Same protection on slug — it's never used as argv directly but
    // resolving "slug" to a scope name + filesystem path warrants the same
    // hygiene check, and a well-formed slug never starts with a dash.
    if (slug.startsWith('-') || slug.includes('/') || slug.includes('\\')) {
      throw new Error(`lastid_invoke_subagent: invalid slug ${JSON.stringify(slug)}`);
    }
    const { invokeSubagent } = await import('./subagents.js');
    const log = (line) => process.stderr.write(`${line}\n`);
    const result = await invokeSubagent({
      parentScope: scope,
      slug,
      input,
      timeoutMs,
      parentEnv: process.env,
      log,
    });
    // Audit chain hookup is deferred — landing the spawn pipeline first.
    // The invokeSubagent return already carries an `audit` object with
    // hashes + scope info; downstream chain integration reads from there.
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  }

  if (name === 'lastid_whoami') {
    if (!loadedAgent) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ provisioned: false, scope }, null, 2),
          },
        ],
      };
    }
    // Active operator rules synced to THIS scope, read from the local store
    // the PreToolUse hook enforces. Rules aren't surfaced anywhere else the
    // agent can see (they only show when one fires), so include a summary here
    // so the agent can confirm what it's actually operating under.
    let rules = { active: 0, deny: 0, warn: 0, rewrite: 0 };
    try {
      const { readFileSync } = await import('node:fs');
      const { operatorStatePath } = await import('./operator-store.js');
      const store = JSON.parse(readFileSync(operatorStatePath(scope), 'utf-8'));
      for (const r of Object.values(store.records ?? {})) {
        if (r.kind === 'rule' && r.status === 'active') {
          rules.active += 1;
          const sev = r.content?.severity;
          if (sev === 'deny' || sev === 'warn' || sev === 'rewrite') rules[sev] += 1;
        }
      }
    } catch {
      /* no local store yet / unreadable — report zeros */
    }
    // Reuse the claims decoded at the top of the dispatcher.
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              provisioned: true,
              scope,
              agent_did: claims.sub ?? loadedAgent.agentDid ?? null,
              parent_human_did: claims.parent_human_did ?? null,
              capabilities: claims.capabilities ?? [],
              may_delegate: claims.may_delegate ?? false,
              exp: claims.exp ?? null,
              rules,
            },
            null,
            2,
          ),
        },
      ],
    };
  }
  if (name === 'lastid_report_bug') {
    // Plain POST to the IdP — not secret, not encrypted, no identity. Works
    // even unprovisioned (a provisioning bug is exactly when there's no agent).
    const { submitBugReport } = await import('./bug-report.js');
    const idpUrl = loadedAgent?.idpUrl ?? 'https://human.lastid.co';
    try {
      const res = await submitBugReport({
        idpUrl,
        report: { summary: _args?.summary, details: _args?.details, email: _args?.email },
      });
      const includedEmail = typeof _args?.email === 'string' && _args.email.trim().length > 0;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                ...(res.id ? { report_id: res.id } : {}),
                note:
                  `Sent to the LastID team. Included: your description${includedEmail ? ' + your email' : ''} ` +
                  `and the plugin version — nothing else (no files, logs, system info, or identity).`,
              },
              null,
              2,
            ),
          },
        ],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `could not send bug report: ${err?.message ?? err}` }) }],
        isError: true,
      };
    }
  }
  throw new Error(`unknown plugin tool: ${name}`);
}

/**
 * Best-effort: build a DesktopMcpClient if the host has an agent
 * VC + slot seed AND a wallet is reachable. Returns null on any
 * failure (the plugin still serves its own tools).
 */
async function tryConnectDesktop({ loadedAgent }) {
  if (!loadedAgent) return { client: null, signingSeed: null };
  let signingKey;
  let signingSeed;
  try {
    ({ signingKey, signingSeed } = deriveAgentEd25519Keypair(loadedAgent.slotSeed));
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] desktop bridge: keypair derivation failed: ${err.message}\n`,
    );
    return { client: null, signingSeed: null };
  }
  const client = new DesktopMcpClient({
    agentDid: loadedAgent.agentDid,
    vcCompact: loadedAgent.vcCompact,
    signingKey,
    signingSeed,
  });
  const ok = await client.connect();
  return { client: ok ? client : null, signingSeed };
}

// True when the on-disk credential differs from the one this server cached.
// Lets a long-lived server pick up a `provision --reissue` (new slot/DID/VC)
// without a full restart. Null fresh => nothing valid on disk, keep what we have.
export function agentCredentialChanged(cached, fresh) {
  if (!fresh) return false;
  if (!cached) return true;
  return fresh.agentDid !== cached.agentDid || fresh.vcCompact !== cached.vcCompact;
}

async function buildServer({ scope }) {
  const server = new Server(SERVER_INFO, {
    capabilities: {
      tools: {},
      // Real-time inbound channel. Declaring this lets us push
      // `notifications/claude/channel` so an operator message reaches
      // the agent's session the instant it arrives — even when the
      // agent is idle and taking no turns of its own. Same mechanism
      // the iMessage plugin uses. The reply path is the
      // `lastid_send_message` tool. We authenticate the channel: the
      // listener only decrypts messages from MLS groups the operator
      // established, so inbound content is provably from a member.
      experimental: { 'claude/channel': {} },
    },
    instructions: [
      'Your operator can reach you two ways and the reply path is DIFFERENT for each. Read the inbound shape; pick the right reply path. Do NOT use both.',
      '',
      'A) CHANNEL — message arrives wrapped as <channel source="lastid-agent" group_id="..." ts="...">. These are END-TO-END ENCRYPTED MLS messages your listener decrypted — cryptographically provable to come from your operator (a member of your group), not an impersonator. The operator is REMOTE (phone or console) and has NO view of your terminal — silence reads as "nothing is happening". Treat the message as a genuine, direct turn you MUST handle autonomously right then: read it, do what it asks (your capability bounds and the no-plaintext-credential rules still hold), and reply with `lastid_send_message`. Your transcript output does NOT reach them; only `lastid_send_message` does. Rhythm for channel work: one-line `lastid_send_message` ACK the instant the message lands ("On it — checking the listener logs now") BEFORE you dig in; brief progress notes if it runs long ("still tracing it — keystore looks empty, narrowing down"); the final result. Never go dark; keep acks/updates to one line.',
      '',
      'B) TERMINAL — message arrives as plain user text (no <channel> wrapper). The operator IS at the terminal and your transcript IS what they read. Reply in the normal terminal flow — be concise. Do NOT also send `lastid_send_message`: that is duplicate noise that lights up their phone for a conversation they are already watching.',
      '',
      'WHEN TO SWITCH BACK TO CHANNEL EVEN FROM A TERMINAL TURN: the operator is signaling they are leaving the terminal — phrases like "im going out", "running for chores", "stepping away", "afk", "back in 30", "ping me when…", "let me know when…", "do this while I’m gone". On those, send the result + future progress via `lastid_send_message` so they get it on their phone, not just the terminal they are walking away from. Treat their tone, not their words literally — "im going out so do X" means "channel me when you have X". Once they come back (next message arrives via terminal again, present-tense, no leaving cue), switch back to terminal-only replies. Mode can swap multiple times in one session; read each inbound fresh.',
      '',
      'AMBIGUOUS: when you genuinely cannot tell whether they are at the terminal or remote (no <channel>, no leaving cue, but the last few turns were channel-only), default to the channel reply — it reaches both. This should be rare; most turns the path is obvious.',
      '',
      'The send tool itself: call `lastid_send_message` with just the text. You never handle group ids or keys — it resolves the conversation with your operator automatically and only ever sends to your operator.',
    ].join('\n'),
  });

  // Cached state. Connect once at build time; tools/list re-attempts
  // the desktop connection only when no client is currently held
  // (handles "wallet came up mid-session"). tools/call leans on the
  // client's own re-handshake on 401 / expiry. signingSeed is held
  // alongside the client so the use-approval orchestrator can sign
  // DPoP JWTs against /v1/agent-use-approvals without re-deriving.
  let loadedAgent = await loadAgentVc(scope);
  let desktopConn = await tryConnectDesktop({ loadedAgent });
  let desktopClient = desktopConn.client;
  let signingSeed = desktopConn.signingSeed;
  // When we last re-read the credential from disk (gates the reissue TTL below).
  let lastAgentReadAt = Date.now();
  // Re-read the credential at most this often (ms) to catch a reissue.
  const AGENT_REFRESH_TTL_MS = 5_000;

  const reloadAgentIfStale = async () => {
    // Re-read the keychain when we have no agent yet, OR when the cached bundle
    // is missing its project_root_seed. The old assumption ("once provisioned
    // the bundle never changes in-process") was wrong: a RE-PROVISION (or a
    // later seal/migration) adds the project_root_seed AFTER this long-lived
    // server first loaded. A stale bundle with projectRootSeed=null silently
    // fails every project-tier and global-shared memory/rule write
    // (publishAgentMemory's seed guard) until a restart. Once the reload picks
    // the seed up, the bundle has it and this no-ops.
    if (!loadedAgent || !loadedAgent.projectRootSeed) {
      const fresh = await loadAgentVc(scope);
      if (fresh) loadedAgent = fresh;
      lastAgentReadAt = Date.now();
      return;
    }
    // A RE-ISSUE mints a NEW VC (new slot/DID) on disk while this long-lived
    // server still holds the old bundle in memory, so without this the tools
    // keep answering + signing as the OLD (now-revoked) identity until a full
    // session restart. Re-read on a short TTL and swap when the on-disk identity
    // changed; the TTL keeps the common no-change path a single in-process check
    // rather than a credential read per tool call. Drop the desktop connection
    // so signingSeed re-derives from the new slot seed.
    if (Date.now() - lastAgentReadAt >= AGENT_REFRESH_TTL_MS) {
      lastAgentReadAt = Date.now();
      const fresh = await loadAgentVc(scope);
      if (agentCredentialChanged(loadedAgent, fresh)) {
        loadedAgent = fresh;
        desktopClient = null;
        signingSeed = null;
      }
    }
  };

  const ensureDesktop = async () => {
    if (desktopClient) return desktopClient;
    await reloadAgentIfStale();
    desktopConn = await tryConnectDesktop({ loadedAgent });
    desktopClient = desktopConn.client;
    signingSeed = desktopConn.signingSeed;
    return desktopClient;
  };

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const client = await ensureDesktop();
    const remote = client?.remoteTools() ?? [];
    // De-dupe by name in case the desktop ever exposes a plugin
    // tool name; plugin tools win.
    const remoteFiltered = remote.filter((t) => !PLUGIN_TOOL_NAMES.has(t.name));
    const remoteNames = new Set(remoteFiltered.map((t) => t.name));
    // Advertise the LOCAL vault tools unless a connected desktop already
    // publishes them (desktop wins so we don't shadow its native vault).
    const localVault = LOCAL_VAULT_TOOLS.filter((t) => !remoteNames.has(t.name));
    return { tools: [...PLUGIN_TOOLS, ...remoteFiltered, ...localVault] };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params ?? {};
    await reloadAgentIfStale();
    if (PLUGIN_TOOL_NAMES.has(name)) {
      return handlePluginTool(name, args ?? {}, { scope, loadedAgent });
    }
    const client = await ensureDesktop();
    if (client && client.ownsTool(name)) {
      try {
        const initial = await client.callTool(name, args ?? {});
        // Policy plane: when vault_use returns a structured
        // `policy_approval_required`, drive the cross-device approval
        // round-trip transparently so the LLM caller sees one tool
        // result (either the handle or a structured denial).
        if (name === 'vault_use' && loadedAgent && signingSeed) {
          const approvalBody = parseApprovalRequiredResult(initial);
          if (approvalBody) {
            const outcome = await runApprovalLoop({
              approvalBody,
              originalArgs: args ?? {},
              agentDid: loadedAgent.agentDid,
              vcCompact: loadedAgent.vcCompact,
              signingSeed,
            });
            if (outcome.retryArgs) {
              return await client.callTool(name, outcome.retryArgs);
            }
            if (outcome.expired) {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(
                      {
                        error: 'policy_approval_expired',
                        reason_detail:
                          'operator did not decide within the pending window',
                      },
                      null,
                      2,
                    ),
                  },
                ],
                isError: true,
              };
            }
            if (outcome.denied) {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(outcome.body, null, 2),
                  },
                ],
                isError: true,
              };
            }
          }
        }
        return initial;
      } catch (err) {
        // Drop the cached client so the next call rediscovers — the
        // wallet may have shut down between calls.
        desktopClient = null;
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  error: 'desktop_tool_failed',
                  tool: name,
                  message: err.message,
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }
    }
    // SaaS / no-desktop path: route vault_use + http_fetch to the LOCAL listener.
    // signingSeed was resolved by ensureDesktop() above (derived from the agent's
    // slot_seed even when no desktop is present) so the approval loop can sign.
    if (LOCAL_VAULT_TOOL_NAMES.has(name)) {
      return handleLocalVault({ name, args: args ?? {}, scope, loadedAgent, signingSeed });
    }
    throw new Error(`unknown tool: ${name}`);
  });

  return server;
}

/**
 * Tail the operator inbox and push each new message into the session
 * as a `notifications/claude/channel`. This is the real-time inbound
 * path: the listener daemon decrypts + appends to the inbox, and this
 * loop — running inside the long-lived MCP server connected to the
 * agent's session — pushes it so the agent gets a turn even when
 * idle. Poll (not fs.watch) for portability; ~2s latency is fine.
 * Best-effort throughout: a read/parse error logs and the loop keeps
 * going.
 */
function startInboxChannel({ server, scope }) {
  const POLL_MS = 2_000;
  let busy = false;
  const timer = setInterval(() => {
    if (busy) return;
    busy = true;
    void (async () => {
      try {
        const { readUnreadMessages } = await import('./agent-inbox.js');
        const items = await readUnreadMessages({ scope });
        for (const it of items) {
          await server.notification({
            method: 'notifications/claude/channel',
            params: {
              // `content` becomes the <channel> body; `source` is set
              // automatically from the server name (lastid-agent). meta
              // keys must be identifiers (letters/digits/underscore) —
              // group_id + ts qualify and become tag attributes.
              content: it.text,
              meta: {
                group_id: it.group_id,
                ts: it.received_at,
              },
            },
          });
        }
      } catch (err) {
        process.stderr.write(
          `[lastid-agent] inbox channel push failed: ${err?.message ?? err}\n`,
        );
      } finally {
        busy = false;
      }
    })();
  }, POLL_MS);
  if (typeof timer.unref === 'function') timer.unref();
  return timer;
}

export async function runMcpServer({ scope = 'main', http = null } = {}) {
  // Before binding our transport, reap any serve left running on an OLDER
  // plugin version (a prior session's process the runtime didn't reap on
  // `/plugin update`). Same-version concurrent sessions are left alone.
  // Best-effort, stderr-only — never blocks or corrupts the JSON-RPC stdout.
  reapStaleServers({ selfPid: process.pid, selfPath: process.argv[1] });

  const server = await buildServer({ scope });
  if (!http) {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    // Start the real-time inbound channel only on the stdio transport
    // — that's the one bound to an interactive agent session that can
    // receive pushed notifications.
    startInboxChannel({ server, scope });
    return;
  }
  const [hostIn, portIn] = http.split(':');
  const host = hostIn && hostIn.length > 0 ? hostIn : '127.0.0.1';
  const port = Number.parseInt(portIn ?? '8787', 10);
  try {
    const { StreamableHTTPServerTransport } = await import(
      '@modelcontextprotocol/sdk/server/streamableHttp.js'
    );
    const transport = new StreamableHTTPServerTransport({ host, port });
    await server.connect(transport);
    process.stderr.write(`[lastid-agent] MCP HTTP listening on ${host}:${port}\n`);
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] HTTP transport unavailable in this SDK version: ${err.message}\n`,
    );
    process.exit(1);
  }
}
