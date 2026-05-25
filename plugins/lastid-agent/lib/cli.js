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
import { hostname } from 'node:os';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import qrcodeTerminal from 'qrcode-terminal';

/**
 * Detect the agent runtime the operator is running this from, so the
 * wallet approval screen shows something concrete ("Claude Code on
 * matt's laptop") rather than a hardcoded generic label.
 *
 * We probe env vars the popular agent runtimes set. No hardcoded
 * fallback to any specific runtime name — if nothing matches we just
 * report the hostname; the operator still sees which device the
 * request is from.
 *
 * Sources, in priority order:
 *   - Claude Code plugin runtime: CLAUDECODE / CLAUDE_PLUGIN_ROOT
 *   - OpenAI Codex CLI:           CODEX_* env (e.g. CODEX_HOME, CODEX_TUI)
 *   - Google Gemini CLI:          GEMINI_CLI / GEMINI_CODE_ASSIST
 *   - Anthropic SDK in scripts:   ANTHROPIC_API_KEY without Claude markers
 *   - OpenAI Assistants:          OPENAI_ASSISTANT_ID
 *
 * Anything not matched falls through to `lastid-agent on <host>`.
 */
function detectRuntimeName() {
  const host = (() => {
    try {
      return hostname();
    } catch {
      return null;
    }
  })();
  const here = host ? ` on ${host}` : '';
  if (env.CLAUDECODE || env.CLAUDE_PLUGIN_ROOT) return `Claude Code${here}`;
  if (env.CODEX_HOME || env.CODEX_TUI || env.CODEX_CLI) return `Codex${here}`;
  if (env.GEMINI_CLI || env.GEMINI_CODE_ASSIST) return `Gemini${here}`;
  if (env.OPENAI_ASSISTANT_ID) return `OpenAI Assistant${here}`;
  return `lastid-agent${here}`;
}
import { provisionAgent } from '../lib/agent-provisioning.js';
import { persistAgentVc, loadAgentVc } from '../lib/keychain.js';
import { publishAgentKeyPackage } from '../lib/mls-publish.js';
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
    runtimeName: flags.runtime ?? detectRuntimeName(),
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
        // 'both' — non-TTY (Claude Code bash tool, CI, piped). The
        // operator never sees stdout from a subprocess unless the
        // calling agent reads it back, AND there's no terminal to
        // host an interactive QR scan. So we lean on the browser
        // path: spawn the OS opener so the approve page pops in
        // the operator's actual default browser (works regardless
        // of stdin/stdout — `open` / `xdg-open` / `start` is fire-
        // and-forget against the windowing system, not the calling
        // TTY). The URL is also printed for the case where the
        // opener can't reach a display (SSH session, headless CI)
        // and the operator has to copy/paste manually.
        //
        // Phone deep link + QR stay printed below as a fallback —
        // useful when the operator's LastID lives on their phone
        // and they're working at a different workstation than the
        // one running Claude Code. The browser auto-open just
        // covers the common case painlessly.
        const consoleHost = consoleHostFor(idpUrl);
        const approveUrl =
          `https://${consoleHost}/console/agents/approve?user_code=` +
          encodeURIComponent(userCode);
        const walletDeepLink =
          `lastid://agent-approve?user_code=${encodeURIComponent(userCode)}` +
          `&idp=${encodeURIComponent(idpUrl)}`;
        console.log('Approve this agent in your LastID:');
        console.log('');
        console.log(`  ${approveUrl}`);
        console.log('');
        console.log('Opening it in your browser now…');
        void tryOpenInBrowser(approveUrl).catch((err) => {
          console.log(
            `  (couldn't auto-open: ${
              err instanceof Error ? err.message : String(err)
            })`,
          );
          console.log('  Paste the URL above into your browser instead.');
        });
        console.log('');
        console.log('Or, if your LastID is on your phone:');
        console.log(`  tap: ${walletDeepLink}`);
        console.log('  or scan the QR below from your phone camera:');
        console.log('');
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

  // Publish the agent's MLS KeyPackage so the operator's console
  // can chat with it immediately. Non-fatal — if this fails the
  // operator can still chat once the agent's runtime is up and
  // retries the publish.
  try {
    await publishAgentKeyPackage({
      idpUrl,
      agentDid: provisioned.agentDid,
      vcCompact: provisioned.vcCompact,
      slotSeed: provisioned.slotSeed,
      scope,
    });
    console.log('   mls keypkg: published');
  } catch (err) {
    console.error(
      `   mls keypkg: publish failed (${
        err instanceof Error ? err.message : String(err)
      })`,
    );
    console.error(
      '   You can retry later — the chat dock will fall back to a retry attempt.',
    );
  }
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
  const scope = flags.scope ?? 'main';
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    // Not provisioned — no memories possible.
    process.exit(0);
  }

  // Local-first: compose the bedrock + topical packet from the agent's own
  // memory store + the synced operator-store, the same way policy-check
  // resolves rules locally. The desktop /memory/retrieve is the transition
  // fallback only (before any local memories exist).
  try {
    const { decodeVcClaims } = await import('./vc-claims.js');
    const { retrievePacket } = await import('./memory-retrieve.js');
    const { OperatorStore } = await import('./operator-store.js');
    const { makeEmbedder } = await import('./embeddings.js').catch(() => ({}));
    const claims = decodeVcClaims(loaded.vcCompact) ?? {};
    const embedder = typeof makeEmbedder === 'function' ? makeEmbedder() : null;
    const { markdown } = await retrievePacket({
      scope,
      agentDid: claims.sub ?? loaded.agentDid ?? null,
      parentHumanDid: claims.parent_human_did ?? null,
      prompt,
      operatorStore: new OperatorStore(scope),
      embedder,
    });
    if (markdown && markdown.trim().length > 0) {
      process.stdout.write(markdown);
      process.exit(0);
    }
  } catch (e) {
    process.stderr.write(`memory-retrieve(local): ${e?.message ?? e}\n`);
    // fall through to desktop
  }

  // Desktop fallback (transition): the old TCB still holds memories until
  // they're migrated. Soft-fail to no output if unreachable.
  const { DesktopMcpClient } = await import('./desktop-mcp-client.js');
  const { deriveAgentEd25519Keypair } = await import('./agent-provisioning.js');
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
  const scope = flags.scope ?? 'main';
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    process.exit(0);
  }

  // Local-first: topical hits from the agent's own memory store. Desktop is
  // the transition fallback only.
  try {
    const { decodeVcClaims } = await import('./vc-claims.js');
    const { retrieveSearchBlock } = await import('./memory-retrieve.js');
    const { makeEmbedder } = await import('./embeddings.js').catch(() => ({}));
    const claims = decodeVcClaims(loaded.vcCompact) ?? {};
    const embedder = typeof makeEmbedder === 'function' ? makeEmbedder() : null;
    const block = await retrieveSearchBlock({
      scope,
      agentDid: claims.sub ?? loaded.agentDid ?? null,
      parentHumanDid: claims.parent_human_did ?? null,
      query: prompt,
      limit,
      excludeBedrock,
      embedder,
    });
    if (block && block.trim().length > 0) {
      process.stdout.write(`${block}\n`);
      process.exit(0);
    }
    // No local hits: if we have ANY local memories, that's a definitive
    // "nothing relevant" — stay silent rather than asking the desktop.
    const { MemoryStore } = await import('./memory-store.js');
    if (new MemoryStore(scope).all().length > 0) {
      process.exit(0);
    }
  } catch (e) {
    process.stderr.write(`memory-search(local): ${e?.message ?? e}\n`);
    // fall through to desktop
  }

  const { DesktopMcpClient } = await import('./desktop-mcp-client.js');
  const { deriveAgentEd25519Keypair } = await import('./agent-provisioning.js');
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
 * `lastid-agent memory-setup` — opt-in install of the local-embeddings stack
 * (@xenova/transformers + all-MiniLM-L6-v2). Deliberately NOT part of the
 * fast first-run bootstrap (the ~137MB dep would stall the MCP server past
 * the runtime's connect timeout). Until this runs, memory search degrades to
 * keyword scoring. Installs the dep into the plugin dir, downloads + warms
 * the model, then backfills embeddings for the agent's local memories.
 */
async function cmdMemorySetup(flags) {
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { spawnSync } = await import('node:child_process');
  const pluginRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

  const { embeddingsInstalled } = await import('./embeddings.js');
  if (!(await embeddingsInstalled())) {
    process.stdout.write('Installing local embeddings (@xenova/transformers, ~137MB)…\n');
    const r = spawnSync(
      'npm',
      ['install', '@xenova/transformers', '--omit=dev', '--no-audit', '--no-fund'],
      { cwd: pluginRoot, stdio: ['ignore', process.stderr, process.stderr] },
    );
    if (r.status !== 0) {
      process.stderr.write(`memory-setup: dependency install failed (exit ${r.status ?? 'n/a'})\n`);
      process.exit(1);
    }
  } else {
    process.stdout.write('Embeddings dependency already installed.\n');
  }

  // Warm the model (downloads on first use, caches under ~/.lastid-agent/models).
  process.stdout.write('Downloading + warming the embedding model…\n');
  const { makeEmbedder, EMBED_DIM } = await import('./embeddings.js');
  const embedder = makeEmbedder();
  const probe = await embedder('warm up the embedding model');
  if (!Array.isArray(probe) || probe.length !== EMBED_DIM) {
    process.stderr.write('memory-setup: model failed to produce an embedding. Memory search will use keyword fallback.\n');
    process.exit(1);
  }
  process.stdout.write(`Model ready (${EMBED_DIM}-dim).\n`);

  // Backfill embeddings for the agent's existing memories so the first real
  // search is fast.
  const scope = flags.scope ?? 'main';
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(scope);
  if (loaded) {
    const { decodeVcClaims } = await import('./vc-claims.js');
    const { MemoryStore } = await import('./memory-store.js');
    const { backfillEmbeddings } = await import('./embeddings.js');
    const claims = decodeVcClaims(loaded.vcCompact) ?? {};
    const store = new MemoryStore(scope, undefined, {
      agentDid: claims.sub ?? loaded.agentDid ?? null,
      parentHumanDid: claims.parent_human_did ?? null,
    });
    const n = await backfillEmbeddings(store, embedder);
    process.stdout.write(`Backfilled embeddings for ${n} existing memor${n === 1 ? 'y' : 'ies'}.\n`);
  }
  process.stdout.write('Done. Semantic memory search is now active.\n');
  process.exit(0);
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

  // Local-first: the synced operator-store IS the operator's rule set
  // once we've pulled any state, so a SaaS-fed agent enforces rules with
  // nothing else running. The desktop /policy/check below is the fallback
  // only before the first sync (cold start / transition). See
  // saas-migration.md §2.3.
  try {
    const { OperatorStore } = await import('./operator-store.js');
    const local = new OperatorStore(flags.scope ?? 'main').policyDecision(tool, input);
    if (local) {
      process.stdout.write(JSON.stringify(local));
      process.exit(0);
    }
  } catch (e) {
    // Local store unreadable — fall through to the desktop.
    process.stderr.write(`policy-check(local): ${e?.message ?? e}\n`);
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

/**
 * Pull the operator's rules/memories from the IdP agent-state store and
 * apply them to the local operator-store (saas-migration.md §6). Shared
 * by `cmdSync` (CLI / session-start kick) and the listener's doorbell +
 * on-connect triggers. Returns the sync result; throws on transport
 * errors (callers fail open).
 */
async function runAgentStateSync(loaded, scope) {
  const [{ deriveAgentEd25519Keypair }, { OperatorStore }, { syncAgentState }] =
    await Promise.all([
      import('./agent-provisioning.js'),
      import('./operator-store.js'),
      import('./agent-state-sync.js'),
    ]);
  const idpUrl = loaded.idpUrl ?? env.LASTID_IDP_URL ?? 'https://human.lastid.co';
  const { signingKey } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const store = new OperatorStore(scope);
  return syncAgentState({
    idpUrl,
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    slotSeed: loaded.slotSeed,
    store,
    fetchImpl: globalThis.fetch,
  });
}

/**
 * `lastid-agent sync [--scope main]` — pull operator rules/memories now.
 * Invoked by the SessionStart hook (so a fresh session has current
 * state) and available for manual/debug use. Fail-open: any error exits
 * 0 with a stderr note so it never blocks a session.
 */
async function cmdSync(flags) {
  const scope = flags.scope ?? 'main';
  const loaded = await loadAgentVc(scope);
  if (!loaded) process.exit(0); // not provisioned — nothing to sync
  try {
    const res = await runAgentStateSync(loaded, scope);
    process.stderr.write(
      `[lastid-agent] sync: applied ${res.applied} (fetched ${res.fetched}, rejected ${res.rejected}), cursor ${res.cursor}\n`,
    );
  } catch (e) {
    process.stderr.write(`[lastid-agent] sync failed: ${e?.message ?? e}\n`);
  }
  process.exit(0);
}

/**
 * `lastid-agent listen [--scope main]`
 *
 * Opens a persistent WebSocket to the IdP, joins MLS Welcomes the
 * operator sent us, decrypts inbound application messages, and
 * appends them to the agent's local inbox. Runs until SIGINT.
 *
 * Publishes a fresh MLS KeyPackage on first start if one isn't
 * already known to be live IdP-side — `--publish-keypackage` forces
 * a re-publish. Posts to /v1/mls/keypackages using the agent's
 * VC + a DPoP proof minted from the slot-derived signing key (same
 * auth shape every other agent-side REST call uses).
 */
async function cmdListen(flags) {
  const scope = flags.scope ?? 'main';
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    process.stderr.write(`not_provisioned (scope=${scope}) — run \`lastid-agent provision\` first\n`);
    exit(3);
  }
  const idpUrl = loaded.idpUrl ?? env.LASTID_IDP_URL ?? 'https://human.lastid.co';

  const [
    { deriveAgentEd25519Keypair },
    { MlsClient },
    { LastIdWsClient },
    { MlsDispatcher },
    { drainOutbox },
    { makeDoorbellHandler },
  ] = await Promise.all([
    import('./agent-provisioning.js'),
    import('./mls-client.js'),
    import('./ws-client.js'),
    import('./mls-dispatch.js'),
    import('./agent-send.js'),
    import('./agent-state-sync.js'),
  ]);

  // Agent-state doorbell: a content-free `rules.changed` / `memory.changed`
  // WS event triggers a (debounced) incremental pull from the IdP into the
  // local operator-store, so a published rule reaches this agent without a
  // restart. Best-effort + fail-open — a failed sync never disrupts the
  // listener. (saas-migration.md §6.)
  const onDoorbell = makeDoorbellHandler(() => {
    runAgentStateSync(loaded, scope)
      .then((r) =>
        process.stderr.write(
          `[lastid-agent] doorbell sync: applied ${r.applied}, cursor ${r.cursor}\n`,
        ),
      )
      .catch((err) =>
        process.stderr.write(`[lastid-agent] doorbell sync failed: ${err?.message ?? err}\n`),
      );
  });

  const { signingKey } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const mls = await MlsClient.open({
    agentDid: loaded.agentDid,
    slotSeed: loaded.slotSeed,
    scope,
  });

  if (flags['publish-keypackage'] || flags['publish-keypackage'] === undefined) {
    // Maintenance pass — fetch current inventory, top up only if
    // below the threshold. Avoids re-publishing on every session
    // start while still keeping enough KPs on file for the operator
    // to add the agent to a group.
    const { maintainAgentKeyPackages } = await import('./mls-publish.js');
    try {
      const result = await maintainAgentKeyPackages({
        idpUrl,
        agentDid: loaded.agentDid,
        vcCompact: loaded.vcCompact,
        slotSeed: loaded.slotSeed,
        scope,
      });
      if (result.replenished) {
        process.stderr.write(
          `[lastid-agent] keypackage inventory: ${result.available} on file — replenished (${result.refs?.length ?? 0} new)\n`,
        );
      } else {
        process.stderr.write(
          `[lastid-agent] keypackage inventory: ${result.available} on file — no top up needed\n`,
        );
      }
    } catch (err) {
      process.stderr.write(
        `[lastid-agent] keypackage maintenance failed: ${err.message}\n`,
      );
    }
  }

  // Forward dispatcher-originated frames (per-group fetch_queue,
  // committer reassignment commits) through the WS once it's open.
  // The cycle (dispatcher → ws.send → ws → dispatcher.onEvent) is
  // broken because each leg is async; no recursion concerns.
  let wsRef;
  const dispatcher = new MlsDispatcher({
    mls,
    scope,
    requestSend: (frame) => {
      if (!wsRef) return;
      // The WS handler normalizes top-level envelope vs payload, so
      // send the dispatcher's events with the canonical shape.
      const envelope = {
        type: frame.type,
        correlation_id:
          typeof globalThis.crypto?.randomUUID === 'function'
            ? globalThis.crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: new Date().toISOString(),
        target: { kind: 'self' },
        payload: frame.payload ?? {},
      };
      wsRef.send(envelope);
    },
  });
  // WS-open gate for the outbox drain. We only encrypt + send queued
  // replies while the socket is up; a down socket pauses the drain
  // so we don't burn MLS message generations into the void. Set true
  // on every (re)connect, cleared when a send finds the socket gone.
  let wsOpen = false;
  const ws = new LastIdWsClient({
    idpUrl,
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    onOpen: ({ ws_url }) => {
      wsOpen = true;
      process.stderr.write(`[lastid-agent] ws connected: ${ws_url}\n`);
      // Replay-on-connect: drain whatever the IdP queued for each of
      // our groups while this listener was offline. Without this, a
      // message sent while we were down stays in the IdP queue and the
      // agent never sees it. Fire-and-forget; it logs its own progress.
      void dispatcher.fetchQueues().catch((err) =>
        process.stderr.write(
          `[lastid-agent] fetchQueues on connect failed: ${err?.message ?? err}\n`,
        ),
      );
      // Catch-up: pull current operator rules/memories on (re)connect, so
      // a freshly-provisioned or long-offline agent gets up to date.
      void runAgentStateSync(loaded, scope)
        .then((r) =>
          process.stderr.write(
            `[lastid-agent] agent-state sync on connect: applied ${r.applied}, cursor ${r.cursor}\n`,
          ),
        )
        .catch((err) =>
          process.stderr.write(`[lastid-agent] agent-state sync on connect failed: ${err?.message ?? err}\n`),
        );
    },
    // Doorbell events trigger a sync and are not MLS frames; everything
    // else goes to the MLS dispatcher.
    onEvent: (evt) => {
      if (onDoorbell(evt)) return;
      dispatcher.onEvent(evt);
    },
    onError: (err) => process.stderr.write(`[lastid-agent] ws error: ${err.message}\n`),
  });
  wsRef = ws;

  process.stderr.write(`[lastid-agent] listening as ${loaded.agentDid} on ${idpUrl}\n`);
  ws.start();

  // Outbox drain loop. The listener is the single MLS-state writer,
  // so it is the only process that encrypts + sends. Claude's
  // `lastid_send_message` tool (a separate MCP process) only appends
  // to the outbox; we drain it here. Poll (rather than fs.watch) for
  // portability + simplicity — a 2s reply latency on an agent message
  // is imperceptible.
  const OUTBOX_POLL_MS = 2_000;
  let draining = false;
  const drainTimer = setInterval(() => {
    if (!wsOpen || draining) return;
    draining = true;
    void drainOutbox({
      scope,
      mls,
      agentDid: loaded.agentDid,
      send: (frame) => {
        const ok = ws.send(frame);
        if (!ok) {
          wsOpen = false;
          throw new Error('ws not open');
        }
      },
    })
      .catch((err) =>
        process.stderr.write(`[lastid-agent] outbox drain failed: ${err.message}\n`),
      )
      .finally(() => {
        draining = false;
      });
  }, OUTBOX_POLL_MS);
  if (typeof drainTimer.unref === 'function') drainTimer.unref();

  const shutdown = () => {
    process.stderr.write('[lastid-agent] shutting down\n');
    clearInterval(drainTimer);
    ws.stop();
    try { mls.free(); } catch { /* ignore */ }
    exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Resolve never — the WS client + signal handlers keep the
  // process alive.
  await new Promise(() => {});
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
    case 'listen':
      await cmdListen(flags);
      break;
    case 'sync':
      await cmdSync(flags);
      break;
    case 'memory-retrieve':
      await cmdMemoryRetrieve(flags);
      break;
    case 'memory-search':
      await cmdMemorySearch(flags);
      break;
    case 'memory-setup':
      await cmdMemorySetup(flags);
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
      console.log('  listen     Open the WS to the IdP, publish an MLS KeyPackage,');
      console.log('             and receive operator messages into the local inbox.');
      console.log('             --no-publish-keypackage to skip the publish step.');
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
