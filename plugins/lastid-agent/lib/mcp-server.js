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
import { decodeVcClaims } from './vc-claims.js';
import {
  parseApprovalRequiredResult,
  runApprovalLoop,
} from './use-approval-loop.js';

const SERVER_INFO = {
  name: 'lastid-agent',
  version: '0.1.0',
};

const PLUGIN_TOOLS = [
  {
    name: 'lastid_whoami',
    description:
      'Return the agent identity provisioned for this host: agent DID, parent human DID, capabilities, expiry. Returns { provisioned: false } when no agent credential is present.',
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
];

const PLUGIN_TOOL_NAMES = new Set(PLUGIN_TOOLS.map((t) => t.name));

async function handlePluginTool(name, _args, { scope, loadedAgent }) {
  if (name === 'lastid_send_message') {
    const text = typeof _args?.text === 'string' ? _args.text : '';
    if (!text) {
      throw new Error('lastid_send_message requires text');
    }
    if (!loadedAgent) {
      throw new Error(
        'not provisioned — run `lastid-agent provision` before sending messages',
      );
    }
    // Resolve the operator (the agent's parent human) from the VC.
    // The LLM never sees a DID or a group id — it just says text.
    const claims = decodeVcClaims(loadedAgent.vcCompact) ?? {};
    const operatorDid = claims.parent_human_did ?? null;
    if (!operatorDid) {
      throw new Error('agent VC has no parent_human_did — cannot resolve operator');
    }
    const { resolveActiveGroupForOperator } = await import('./agent-groups.js');
    const { enqueueSend } = await import('./agent-send.js');
    const group = await resolveActiveGroupForOperator({ scope, operatorDid });
    if (!group) {
      // No conversation yet. Agent-initiated group creation (fetch
      // the operator's KeyPackage, create + invite) is a follow-up
      // that must run in the listener (single MLS-state writer) and
      // needs the create/export/add wrappers on the legacy client.
      // Until then, the operator opens the chat first.
      throw new Error(
        'no active conversation with your operator yet — ask them to open the LastID chat with you first, then reply',
      );
    }
    const id = await enqueueSend({ scope, idpGroupId: group.idpGroupId, text });
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              queued: true,
              request_id: id,
              note: 'Encrypted + delivered by your listener within a couple seconds. The operator sees it in their console chat and on their phone.',
            },
            null,
            2,
          ),
        },
      ],
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
    const claims = decodeVcClaims(loadedAgent.vcCompact) ?? {};
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
            },
            null,
            2,
          ),
        },
      ],
    };
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
      'Messages from the human you work with arrive as <channel source="lastid-agent" group_id="..." ts="...">. They are end-to-end encrypted MLS group messages your listener decrypted — provably from a member of your group.',
      '',
      'To reply, call the `lastid_send_message` tool with just the text. You never handle group ids or keys — the tool resolves the conversation with your operator automatically and will ONLY ever send to your operator. Your transcript output does NOT reach the operator; only `lastid_send_message` does.',
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

  const reloadAgentIfStale = async () => {
    // Re-read keychain only when we don't have one yet. Once the
    // agent is provisioned the bundle doesn't change in-process.
    if (!loadedAgent) {
      loadedAgent = await loadAgentVc(scope);
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
    return { tools: [...PLUGIN_TOOLS, ...remoteFiltered] };
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
