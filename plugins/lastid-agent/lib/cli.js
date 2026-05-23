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

import { argv, exit, env, platform, stdin, stdout } from 'node:process';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import qrcodeTerminal from 'qrcode-terminal';
import { provisionAgent } from '../lib/agent-provisioning.js';
import { persistAgentVc, loadAgentVc } from '../lib/keychain.js';
import { linkHumanDid } from '../lib/agent-link.js';
import { runMcpServer } from '../lib/mcp-server.js';
import { decodeVcClaims } from '../lib/vc-claims.js';

/**
 * Interactive prompt at provision time — where does the operator's
 * LastID live? Two equally-valid paths:
 *
 *   - phone: QR + `lastid://` deep link, operator scans with the
 *     mobile wallet (or taps the link on the device that holds
 *     LastID). Right answer for operators who provisioned via
 *     iOS/Android first.
 *
 *   - browser: print the lastid.co console URL + auto-open the
 *     default browser. Right answer for operators who signed up
 *     directly at lastid.co/signup and have their identity sealed
 *     in IndexedDB.
 *
 * Returns 'phone' | 'browser'. The CLI flags `--link` / `--browser`
 * and env vars `LASTID_LINK=1` / `LASTID_BROWSER=1` still override
 * for scripting / CI; the prompt only fires when nothing forced a
 * choice.
 */
async function promptIdentityLocation() {
  if (!stdin.isTTY) {
    // No TTY (e.g. Claude Code's bash tool, CI, piped). Don't force
    // a choice — emit BOTH surfaces and let whichever device the
    // operator has handy resolve first. The IdP attaches the
    // operator's DID at the first authenticated /pending GET, so
    // wallet deep-link tap and browser console click both work
    // against the same user_code.
    return 'both';
  }
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    while (true) {
      const answer = await new Promise((resolve) => {
        rl.question(
          'Where is your LastID? [p]hone (scan QR) or [b]rowser (open console): ',
          resolve,
        );
      });
      const choice = String(answer ?? '').trim().toLowerCase();
      if (choice === 'p' || choice === 'phone') return 'phone';
      if (choice === 'b' || choice === 'browser') return 'browser';
      console.log("  (please answer 'p' for phone or 'b' for browser)");
    }
  } finally {
    rl.close();
  }
}

/**
 * Map an IdP URL to its sibling console host. The IdP runs on
 * `human.lastid.co` (prod) or `human.dev.lastid.co` (dev); the
 * console runs on `lastid.co` / `dev.lastid.co`. Both pairs share
 * the same identity store, so the operator's already-logged-in
 * console session at the same env can attach to a pending row that
 * the plugin just opened on the matching IdP.
 */
function consoleHostFor(idpUrl) {
  try {
    const url = new URL(idpUrl);
    const host = url.host;
    if (host.includes('.dev.')) return 'dev.lastid.co';
    if (host.includes('-dev.') || host === 'localhost') return 'localhost:3000';
    return 'lastid.co';
  } catch {
    return 'lastid.co';
  }
}

/**
 * Best-effort cross-platform "open this URL in the operator's
 * browser". Uses the OS-native opener (`open` on macOS, `xdg-open`
 * on Linux, `start` on Windows). Fails silently if the host has no
 * such command (headless servers, sandboxed environments) — the
 * operator still has the printed URL to paste manually.
 */
function tryOpenInBrowser(url) {
  return new Promise((resolve, reject) => {
    let cmd;
    let args;
    if (platform === 'darwin') {
      cmd = 'open';
      args = [url];
    } else if (platform === 'win32') {
      // `start` is a cmd builtin so we go through cmd.exe with /c.
      // The empty "" is the window title arg `start` requires when
      // the first quoted arg is the URL.
      cmd = 'cmd';
      args = ['/c', 'start', '""', url];
    } else {
      cmd = 'xdg-open';
      args = [url];
    }
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', reject);
    // Detach so the plugin's process can exit independently if the
    // operator closes the terminal before approving in browser.
    child.unref();
    resolve();
  });
}

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

  // Resolve which IdP to bind this agent to:
  //   1. `--idp <url>` flag (explicit, wins)
  //   2. `LASTID_IDP_URL` env (per-host override)
  //   3. `https://human.lastid.co` (production default)
  // The chosen URL is persisted to the keychain on successful
  // provision so every subsequent session of THIS agent routes
  // to the same env automatically — no need to re-pass the flag.
  const idpUrl =
    flags.idp ?? env.LASTID_IDP_URL ?? 'https://human.lastid.co';

  // Operator identity-location discovery — three paths in priority
  // order:
  //   1. --parent-human-did flag or LASTID_PARENT_HUMAN_DID env var
  //      (scripting / CI / explicit override). DID known, no prompt.
  //   2. --link / LASTID_LINK=1  → force phone (QR) flow
  //      --browser / LASTID_BROWSER=1 → force browser flow
  //   3. Interactive prompt: "phone or browser?"
  //
  // Browser flow: POST /initiate without parent_human_did; the IdP
  // binds the operator's DID at the browser console's first
  // authenticated /pending GET (OAuth device-code semantics).
  //
  // Phone flow: QR + `lastid://` deep link, operator scans with
  // mobile wallet, plugin extracts DID from returned LastID.Base.
  let parentHumanDid =
    flags['parent-human-did'] ?? env.LASTID_PARENT_HUMAN_DID;
  // `phone` if the operator's wallet is on a separate device (QR
  // scan); `browser` if their identity lives in this machine's
  // lastid.co console session. Defaults to 'phone' when DID is
  // pre-supplied because passing a DID is the QR-result shape.
  let location = parentHumanDid ? 'phone' : null;
  if (!parentHumanDid) {
    const forcePhone = flags.link === true || env.LASTID_LINK === '1';
    const forceBrowser =
      flags.browser === true || env.LASTID_BROWSER === '1';
    location = forcePhone
      ? 'phone'
      : forceBrowser
      ? 'browser'
      : await promptIdentityLocation();

    if (location === 'phone') {
      console.log('');
      console.log('Link your LastID to provision this agent.');
      const { subjectDid } = await linkHumanDid({ idpUrl });
      parentHumanDid = subjectDid;
      console.log('');
      console.log(`Linked LastID: ${parentHumanDid}`);
      console.log('');
    } else if (location === 'browser') {
      // Browser path — IdP attaches the operator's DID at first
      // authenticated /pending GET. No DID needed from the plugin.
      console.log('');
      console.log(
        'Browser flow — your already-signed-in console session will approve this agent.',
      );
      console.log('');
    } else {
      // 'both' — non-TTY context (Claude Code bash tool, CI, piped).
      // Skip linkHumanDid (it blocks on a separate QR-for-VC-
      // presentation step) and initiate provisioning without
      // parent_human_did. The IdP attaches the operator's DID at the
      // first authenticated /pending GET — works for either a phone
      // wallet that tapped the `lastid://agent-approve` deep link OR
      // a browser console at lastid.co/console/agents/approve. Both
      // surfaces are emitted in the onUserCode callback below.
      console.log('');
      console.log(
        'No TTY — printing both phone deep link and browser URL. Use whichever device has your LastID.',
      );
      console.log('');
    }
  }

  console.log('Starting agent provisioning…');
  const provisioned = await provisionAgent({
    idpUrl,
    parentHumanDid,
    runtimeName: flags.runtime ?? 'lastid-agent-cli',
    projectHint: flags['project-hint'] ?? env.LASTID_PROJECT_HINT,
    onUserCode: async ({ userCode, expiresIn }) => {
      console.log('');
      console.log(`User code:  ${userCode}`);
      console.log(`Expires in: ${expiresIn}s`);
      console.log('');
      if (location === 'phone') {
        // Wallet flow — /initiate carried parent_human_did, so the
        // IdP's broadcaster has already pushed the agent_provisioning
        // event to every device the operator has connected. The
        // wallet's approval screen pops automatically.
        console.log('Check your LastID wallet — the approval screen pops automatically');
        console.log('on whichever device the wallet is open on. Cross-check the user');
        console.log('code matches, then approve.');
      } else if (location === 'browser') {
        // Browser flow — print the console URL + auto-open. The
        // operator's already-signed-in lastid.co console session
        // holds the identity that signs human_authorization.
        const consoleHost = consoleHostFor(idpUrl);
        const approveUrl =
          `https://${consoleHost}/console/agents/approve?user_code=` +
          encodeURIComponent(userCode);
        console.log('Approve in your LastID console:');
        console.log(`  ${approveUrl}`);
        console.log('');
        console.log('Opening it for you now…');
        void tryOpenInBrowser(approveUrl).catch((err) => {
          console.log(
            `  (couldn't auto-open: ${
              err instanceof Error ? err.message : String(err)
            })`,
          );
          console.log('  Paste the URL above into your browser instead.');
        });
      } else {
        // 'both' — non-TTY. Emit phone deep link + QR + browser URL.
        // /initiate ran without parent_human_did; the IdP will attach
        // the operator's DID at whichever device's authenticated
        // /pending GET lands first.
        const consoleHost = consoleHostFor(idpUrl);
        const approveUrl =
          `https://${consoleHost}/console/agents/approve?user_code=` +
          encodeURIComponent(userCode);
        const walletDeepLink =
          `lastid://agent-approve?user_code=${encodeURIComponent(userCode)}` +
          `&idp=${encodeURIComponent(idpUrl)}`;
        console.log('Approve in your LastID — pick whichever has the wallet:');
        console.log('');
        console.log('  Phone (tap deep link OR scan QR below):');
        console.log(`    ${walletDeepLink}`);
        console.log('');
        console.log('  Browser console:');
        console.log(`    ${approveUrl}`);
        console.log('');
        // QR of the deep link so an operator on a different device
        // can scan from their phone camera. Small variant keeps the
        // stdout block tight in narrow terminals.
        await new Promise((resolve) => {
          qrcodeTerminal.generate(walletDeepLink, { small: true }, (out) => {
            console.log(out);
            resolve();
          });
        });
      }
      console.log('');
      console.log('Waiting for you to approve…');
    },
  });

  // Stamp the chosen IdP onto the provisioned bundle so the
  // keychain records which env this agent is bound to.
  provisioned.idpUrl = idpUrl;
  await persistAgentVc(provisioned, scope);
  console.log('');
  console.log('✅ Agent provisioned and persisted to keychain.');
  console.log(`   scope:      ${scope}`);
  console.log(`   slot:       ${provisioned.slotIndex}`);
  console.log(`   agent_did:  ${provisioned.agentDid}`);
  console.log(`   idp_url:    ${idpUrl}`);
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
  console.log(`idp_url:   ${loaded.idpUrl ?? '(not recorded — pre-env-bind agent)'}`);
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
        idp_url: loaded.idpUrl ?? null,
      }
    : { provisioned: false, scope };
  if (flags.json) {
    console.log(JSON.stringify(report));
  } else if (report.provisioned) {
    const envHint = report.idp_url
      ? ` idp=${report.idp_url.replace(/^https?:\/\//, '')}`
      : ' idp=(not recorded)';
    console.log(
      `provisioned (scope=${scope} slot=${report.slot_index ?? '?'}${envHint}) agent_did=${report.agent_did ?? '?'}`,
    );
  } else {
    console.log(`not_provisioned (scope=${scope})`);
  }
}

/**
 * `lastid-agent memory-retrieve --prompt "..."` — called by the
 * UserPromptSubmit hook. Discovers the desktop, handshakes a
 * session, POSTs to /memory/retrieve, prints `packet_markdown` on
 * stdout (empty when no memories). Errors print to stderr and
 * exit non-zero so the hook can soft-fail without injecting.
 */
async function cmdMemoryRetrieve(flags) {
  const prompt =
    typeof flags.prompt === 'string' ? flags.prompt : '';
  if (prompt.trim().length === 0) {
    process.stderr.write('memory-retrieve: --prompt required\n');
    process.exit(2);
  }
  const { DesktopMcpClient } = await import('./desktop-mcp-client.js');
  const { loadAgentVc } = await import('./keychain.js');
  const { deriveAgentEd25519Keypair } = await import('./agent-provisioning.js');
  const loaded = await loadAgentVc(flags.scope ?? 'main');
  if (!loaded) {
    // Not provisioned — no memories possible.
    process.exit(0);
  }
  const { signingKey, signingSeed } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const client = new DesktopMcpClient({
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    signingSeed,
  });
  const ok = await client.connect().catch(() => false);
  if (!ok) {
    // Desktop unavailable — soft-fail with no output.
    process.exit(0);
  }
  try {
    const res = await client.postJson('/memory/retrieve', {
      prompt,
      agent_dids: [loaded.agentDid],
    });
    if (res && typeof res.packet_markdown === 'string') {
      process.stdout.write(res.packet_markdown);
    }
  } catch (e) {
    process.stderr.write(`memory-retrieve: ${e?.message ?? e}\n`);
    process.exit(1);
  }
}

/**
 * `lastid-agent memory-search --prompt "..." [--exclude-bedrock]`
 *
 * Pure topical semantic search — different from `memory-retrieve`
 * which composes bedrock + topical into a single Markdown packet.
 * The PreToolUse hook uses `--exclude-bedrock` to avoid re-surfacing
 * memories already injected into the agent's prompt context via
 * UserPromptSubmit. Renders hits as a Markdown `<lastid-memory>`
 * block on stdout when there's signal; silent when there's nothing
 * relevant.
 *
 * Soft-fail posture matches memory-retrieve: any error → exit 0
 * with no stdout so the hook treats this as "no ambient context"
 * and the tool proceeds.
 */
async function cmdMemorySearch(flags) {
  const prompt =
    typeof flags.prompt === 'string' ? flags.prompt : '';
  if (prompt.trim().length === 0) {
    process.stderr.write('memory-search: --prompt required\n');
    process.exit(2);
  }
  const excludeBedrock = flags['exclude-bedrock'] === true;
  const limit = Number.parseInt(flags.limit ?? '5', 10) || 5;
  const { DesktopMcpClient } = await import('./desktop-mcp-client.js');
  const { loadAgentVc } = await import('./keychain.js');
  const { deriveAgentEd25519Keypair } = await import('./agent-provisioning.js');
  const loaded = await loadAgentVc(flags.scope ?? 'main');
  if (!loaded) {
    process.exit(0);
  }
  const { signingKey, signingSeed } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const client = new DesktopMcpClient({
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    signingSeed,
  });
  const ok = await client.connect().catch(() => false);
  if (!ok) {
    // Desktop unreachable. Stay silent so the calling hook treats
    // this as no ambient context and lets the tool proceed.
    process.exit(0);
  }
  try {
    const res = await client.postJson('/memory/search', {
      query: prompt,
      agent_dids: [loaded.agentDid],
      limit,
      exclude_bedrock: excludeBedrock,
    });
    if (!res || !Array.isArray(res.hits) || res.hits.length === 0) {
      process.exit(0);
    }
    // Render as a compact <lastid-memory> block. Each hit cites
    // its id + score so the agent can audit what was injected.
    const lines = ['<lastid-memory source="ambient">'];
    for (const hit of res.hits) {
      const score = typeof hit.score === 'number'
        ? ` [match ${hit.score.toFixed(2)}]`
        : '';
      const subject = Array.isArray(hit.subject) ? hit.subject.join(', ') : '';
      lines.push(
        `- [${hit.memory_id}] ${hit.claim}${score}` +
          (subject ? ` (subject: ${subject})` : ''),
      );
      if (hit.summary && typeof hit.summary === 'string' && hit.summary.trim().length > 0) {
        // Indent the summary on its own line.
        lines.push(`  ${hit.summary.trim()}`);
      }
    }
    lines.push('</lastid-memory>');
    process.stdout.write(lines.join('\n') + '\n');
  } catch (e) {
    process.stderr.write(`memory-search: ${e?.message ?? e}\n`);
    process.exit(0);
  }
}

/**
 * `lastid-agent policy-check --tool <name> --input <str>` — called
 * by the PreToolUse hook on every tool invocation. POSTs to the
 * desktop's /policy/check endpoint, prints the decision JSON on
 * stdout. Fail-open on any error so a desktop outage doesn't brick
 * every tool call: the hook treats parse failure as "no opinion".
 */
async function cmdPolicyCheck(flags) {
  const tool = typeof flags.tool === 'string' ? flags.tool : '';
  const input = typeof flags.input === 'string' ? flags.input : '';
  if (tool.trim().length === 0) {
    process.stderr.write('policy-check: --tool required\n');
    process.exit(2);
  }
  const { DesktopMcpClient } = await import('./desktop-mcp-client.js');
  const { loadAgentVc } = await import('./keychain.js');
  const { deriveAgentEd25519Keypair } = await import('./agent-provisioning.js');
  const loaded = await loadAgentVc(flags.scope ?? 'main');
  if (!loaded) {
    // Not provisioned — fail open. The plugin acts only on
    // explicitly-authored rules; without an agent there is no
    // way to look them up.
    process.exit(0);
  }
  const { signingKey, signingSeed } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const client = new DesktopMcpClient({
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    signingSeed,
  });
  const ok = await client.connect().catch(() => false);
  if (!ok) {
    process.exit(0);
  }
  try {
    const res = await client.postJson('/policy/check', {
      tool,
      input,
      agent_dids: [loaded.agentDid],
    });
    if (res) {
      process.stdout.write(JSON.stringify(res));
    }
  } catch (e) {
    process.stderr.write(`policy-check: ${e?.message ?? e}\n`);
    process.exit(1);
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
    case 'memory-retrieve':
      await cmdMemoryRetrieve(flags);
      break;
    case 'memory-search':
      await cmdMemorySearch(flags);
      break;
    case 'policy-check':
      await cmdPolicyCheck(flags);
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
      console.log('  --idp <url>                       Default: https://human.lastid.co (production). Use https://human.dev.lastid.co for dev.');
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
