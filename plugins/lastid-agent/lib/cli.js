#!/usr/bin/env node
/**
 * lastid-agent — CLI runner for the LastID agent provisioning loop.
 *
 *   npx lastid-agent provision \
 *     --parent-human-did did:lastid:z<base58> \
 *     [--idp https://human.lastid.co] \
 *     [--runtime "lastid-agent-cli"] \
 *     [--scope main]
 *
 * Prints the verification URL + user code for the operator to open in
 * their wallet, polls until the wallet approves, claims the SD-JWT VC,
 * and persists (seed, VC) to the host keychain. Exit 0 on success.
 */

import { argv, exit, env } from 'node:process';
import { provisionAgent } from '../lib/agent-provisioning.js';
import { persistAgentVc, loadAgentVc } from '../lib/keychain.js';
import { linkHumanDid } from '../lib/agent-link.js';
import { runMcpServer } from '../lib/mcp-server.js';
import { decodeVcClaims } from '../lib/vc-claims.js';

function parseFlags(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        out[key] = next;
        i++;
      } else {
        out[key] = true;
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

async function cmdProvision(flags) {
  const scope = flags.scope ?? 'main';
  const existing = await loadAgentVc(scope);
  if (existing && !flags.force) {
    console.error(
      `agent scope=${scope} already provisioned. Re-run with --force to overwrite.`,
    );
    exit(3);
  }

  const idpUrl = flags.idp ?? env.LASTID_IDP_URL;

  // Discover the operator's LastID DID. Pre-supplied flag or env var
  // wins (useful for scripting / CI). Otherwise drive the agent-link
  // QR flow: render a QR + lastid:// deep link, operator scans with
  // their LastID wallet and presents their LastID.Base credential, we
  // decode the subject DID from the returned SD-JWT.
  let parentHumanDid =
    flags['parent-human-did'] ?? env.LASTID_PARENT_HUMAN_DID;
  if (!parentHumanDid) {
    console.log('Link your LastID to provision this agent.');
    const { subjectDid } = await linkHumanDid({ idpUrl });
    parentHumanDid = subjectDid;
    console.log('');
    console.log(`Linked LastID: ${parentHumanDid}`);
    console.log('');
  }

  console.log('Starting agent provisioning…');
  const provisioned = await provisionAgent({
    idpUrl,
    parentHumanDid,
    runtimeName: flags.runtime ?? 'lastid-agent-cli',
    projectHint: flags['project-hint'] ?? env.LASTID_PROJECT_HINT,
    onUserCode: ({ userCode, expiresIn }) => {
      console.log('');
      console.log(`User code:  ${userCode}`);
      console.log(`Expires in: ${expiresIn}s`);
      console.log('');
      console.log('Check your LastID wallet — the approval screen pops automatically');
      console.log('on any device the wallet is open on (phone or desktop). Cross-check');
      console.log('the user code above matches the one shown in the wallet, approve');
      console.log('with biometric + master password, and keep this process running.');
      console.log('');
      console.log('Your wallet derives this agent\'s identity from your BIP85 tree.');
      console.log('The agent\'s DID will be derived from the slot it allocates and');
      console.log('shown below once approval completes.');
    },
  });

  await persistAgentVc(provisioned, scope);
  console.log('');
  console.log('✅ Agent provisioned and persisted to keychain.');
  console.log(`   scope:      ${scope}`);
  console.log(`   slot:       ${provisioned.slotIndex}`);
  console.log(`   agent_did:  ${provisioned.agentDid}`);
  console.log(`   vc length:  ${provisioned.vcCompact.length} chars`);
}

async function cmdShow(flags) {
  const scope = flags.scope ?? 'main';
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    console.error(`no agent provisioned for scope=${scope}`);
    exit(1);
  }
  console.log(`scope:     ${scope}`);
  console.log(`slot:      ${loaded.slotIndex ?? '(unknown)'}`);
  console.log(`agent_did: ${loaded.agentDid ?? '(unknown)'}`);
  console.log(`vc:        ${loaded.vcCompact}`);
}

/**
 * Print a one-line provisioning status. Used by SessionStart hook and
 * by anything else that wants a machine-readable check. `--json` emits
 * structured output; without it, the text form goes to stdout.
 */
async function cmdStatus(flags) {
  const scope = flags.scope ?? 'main';
  const loaded = await loadAgentVc(scope);
  const claims = loaded ? decodeVcClaims(loaded.vcCompact) ?? {} : {};
  const report = loaded
    ? {
        provisioned: true,
        scope,
        slot_index: loaded.slotIndex,
        agent_did: claims.sub ?? loaded.agentDid ?? null,
        parent_human_did: claims.parent_human_did ?? null,
        parent_agent_did: claims.parent_agent_did ?? null,
        sub_agent_class: claims.sub_agent_class ?? null,
        capabilities: claims.capabilities ?? [],
        may_delegate: claims.may_delegate ?? false,
        iat: claims.iat ?? null,
        exp: claims.exp ?? null,
        audit_endpoint: claims.audit_endpoint ?? null,
        vc_length: loaded.vcCompact?.length ?? 0,
      }
    : { provisioned: false, scope };
  if (flags.json) {
    console.log(JSON.stringify(report));
  } else if (report.provisioned) {
    console.log(
      `provisioned (scope=${scope} slot=${report.slot_index ?? '?'}) agent_did=${report.agent_did ?? '?'}`,
    );
  } else {
    console.log(`not_provisioned (scope=${scope})`);
  }
}

async function main() {
  const [, , cmd, ...rest] = argv;
  const flags = parseFlags(rest);
  switch (cmd) {
    case 'provision':
      await cmdProvision(flags);
      break;
    case 'show':
      await cmdShow(flags);
      break;
    case 'status':
      await cmdStatus(flags);
      break;
    case 'serve':
      await runMcpServer({
        scope: flags.scope ?? 'main',
        http: typeof flags.http === 'string' ? flags.http : flags.http === true ? ':8787' : null,
      });
      break;
    case 'help':
    case '--help':
    case undefined:
      console.log('lastid-agent <command> [flags]');
      console.log('');
      console.log('Commands:');
      console.log('  provision  Run the agent provisioning flow end-to-end.');
      console.log('  status     Report whether an agent is provisioned (--json for machine output).');
      console.log('  show       Print the stored agent VC (debug).');
      console.log('  serve      Run the MCP server exposing the agent tools.');
      console.log('             Default: stdio (Claude Code, Codex, Agents SDK).');
      console.log('             --http [host:port] for HTTP transport (ChatGPT Custom Connector).');
      console.log('');
      console.log('provision flags:');
      console.log(
        '  --parent-human-did did:lastid:z…  Optional. Defaults to QR-scan link flow.',
      );
      console.log('  --idp <url>                       Default: https://human.dev.lastid.co (pre-prod)');
      console.log('  --runtime <name>                  Default: lastid-agent-cli');
      console.log('  --project-hint <hex>              Optional SHA-256 prefix');
      console.log('  --scope <slug>                    Default: main');
      console.log('  --force                           Overwrite existing keychain entry');
      break;
    default:
      console.error(`unknown command: ${cmd}`);
      exit(2);
  }
}

main().catch((err) => {
  console.error(err?.stack ?? String(err));
  exit(1);
});
