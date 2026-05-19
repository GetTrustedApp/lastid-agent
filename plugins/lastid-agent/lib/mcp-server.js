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
];

const PLUGIN_TOOL_NAMES = new Set(PLUGIN_TOOLS.map((t) => t.name));

async function handlePluginTool(name, _args, { scope, loadedAgent }) {
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
  if (!loadedAgent) return null;
  let signingKey;
  let signingSeed;
  try {
    ({ signingKey, signingSeed } = deriveAgentEd25519Keypair(loadedAgent.slotSeed));
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] desktop bridge: keypair derivation failed: ${err.message}\n`,
    );
    return null;
  }
  const client = new DesktopMcpClient({
    agentDid: loadedAgent.agentDid,
    vcCompact: loadedAgent.vcCompact,
    signingKey,
    signingSeed,
  });
  const ok = await client.connect();
  return ok ? client : null;
}

async function buildServer({ scope }) {
  const server = new Server(SERVER_INFO, {
    capabilities: { tools: {} },
  });

  // Cached state. Connect once at build time; tools/list re-attempts
  // the desktop connection only when no client is currently held
  // (handles "wallet came up mid-session"). tools/call leans on the
  // client's own re-handshake on 401 / expiry.
  let loadedAgent = await loadAgentVc(scope);
  let desktopClient = await tryConnectDesktop({ loadedAgent });

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
    desktopClient = await tryConnectDesktop({ loadedAgent });
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
        return await client.callTool(name, args ?? {});
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

export async function runMcpServer({ scope = 'main', http = null } = {}) {
  const server = await buildServer({ scope });
  if (!http) {
    const transport = new StdioServerTransport();
    await server.connect(transport);
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
