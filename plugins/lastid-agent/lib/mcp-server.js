/**
 * LastID Agent MCP server.
 *
 * Exposes the agent's identity + (later) memory/sign/message tools over
 * the Model Context Protocol. Speaks stdio by default (Claude Code,
 * Codex CLI, OpenAI Agents SDK stdio mode). With `--http <host:port>`
 * it listens on Streamable HTTP for ChatGPT Custom Connector and the
 * Responses API hosted-MCP path.
 *
 * The first iteration surfaces a single tool, `lastid_whoami`, which
 * reports the agent's DID + capability summary. The full
 * memory/sign/message surface composes onto this same server as
 * separate `server.tool(...)` registrations.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadAgentVc } from './keychain.js';

const SERVER_INFO = {
  name: 'lastid-agent',
  version: '0.1.0',
};

function decodeVcClaims(vcCompact) {
  if (!vcCompact || typeof vcCompact !== 'string') return null;
  const parts = vcCompact.split('~')[0]?.split('.');
  if (!parts || parts.length < 2) return null;
  try {
    return JSON.parse(
      Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString(
        'utf-8',
      ),
    );
  } catch {
    return null;
  }
}

function buildToolList() {
  return {
    tools: [
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
    ],
  };
}

async function handleToolCall(name, _args, { scope }) {
  if (name === 'lastid_whoami') {
    const loaded = await loadAgentVc(scope);
    if (!loaded) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ provisioned: false, scope }, null, 2),
          },
        ],
      };
    }
    const claims = decodeVcClaims(loaded.vcCompact) ?? {};
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              provisioned: true,
              scope,
              agent_did: claims.sub ?? loaded.agentDid ?? null,
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
  throw new Error(`unknown tool: ${name}`);
}

async function buildServer({ scope }) {
  const server = new Server(SERVER_INFO, {
    capabilities: { tools: {} },
  });
  server.setRequestHandler({ method: 'tools/list' }, async () => buildToolList());
  server.setRequestHandler({ method: 'tools/call' }, async (request) => {
    const { name, arguments: args } = request.params ?? {};
    return handleToolCall(name, args ?? {}, { scope });
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
