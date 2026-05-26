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
import { resolveScope } from '../lib/scope.js';
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
 * Provision-time prompt: enable semantic memory? Recommended (Enter = yes).
 * The model is a one-time ~137MB download shared by every agent on this host.
 * TTY only — returns true/false from the operator, or `null` when there's no
 * TTY (Claude Code's bash tool, CI) so the caller falls back to a printed
 * recommendation instead of silently doing nothing or auto-installing.
 */
async function promptEnableEmbeddings() {
  if (!stdin.isTTY) return null;
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await new Promise((resolve) => {
      rl.question(
        'Enable semantic memory now? One-time ~137MB model download (shared by all ' +
          'your agents on this host), then verified. [Y/n]: ',
        resolve,
      );
    });
    const c = String(answer ?? '').trim().toLowerCase();
    return c === '' || c === 'y' || c === 'yes';
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
  const scope = resolveScope(flags);
  const existing = await loadAgentVc(scope);
  // Replacing an existing identity is a REISSUE, not a "force". (`--force`
  // stays as a back-compat alias, but it's also matched by the operator's own
  // dangerous-flags rule — `--reissue` is the verb to use.) A reissue mints a
  // new identity, so afterwards we tear down the old listener + local state and
  // reconnect on the new one (see the reset at the end of this function).
  const reissue = flags.reissue === true || flags.force === true;
  if (existing && !reissue) {
    console.error(
      `agent scope=${scope} already provisioned. Re-run with --reissue to replace it ` +
        `(mints a new identity, clears local state, and reconnects).`,
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

  // Reissue reset. We just minted a NEW identity (the keychain now holds it).
  // The running listener still has a WebSocket bound to the OLD agent DID, and
  // the local store is full of records sealed to the old slot_seed / signed by
  // the old key (a stale sync cursor + undecryptable MLS state). Close the old
  // connection, wipe that state, and bring the listener back up so it
  // reconnects + syncs from scratch on the new identity.
  if (reissue && existing) {
    const { stopListener, clearScopeState, ensureListenerRunning } = await import(
      './listener-daemon.js'
    );
    const { fileURLToPath } = await import('node:url');
    console.log('');
    console.log('Reissue — resetting local state for the new identity…');
    try {
      const stopped = await stopListener({ scope });
      console.log(`   listener:   ${stopped.status} (old WebSocket closed)`);
      await clearScopeState(scope);
      console.log('   state:      cleared (old rules, memories, MLS, inbox, cursor)');
      const cliPath = fileURLToPath(new URL('../bin/lastid-agent.js', import.meta.url));
      const started = await ensureListenerRunning({ scope, cliPath });
      console.log(`   listener:   ${started.status} — reconnecting on the new identity`);
    } catch (err) {
      console.error(
        `   reset:      partial — ${err instanceof Error ? err.message : String(err)}`,
      );
      console.error(
        `   If state looks stale, stop Claude Code and run: rm -rf ~/.lastid-agent/${scope}`,
      );
    }
  } else {
    // Fresh provision (no prior identity for this scope). SessionStart skipped
    // the listener because the scope wasn't provisioned at launch — so without
    // this, the WebSocket + MLS channel + rule/memory sync don't come up until
    // the operator restarts Claude. Start the listener NOW so the channel is
    // active immediately (no restart needed).
    try {
      const { ensureListenerRunning } = await import('./listener-daemon.js');
      const { fileURLToPath } = await import('node:url');
      const cliPath = fileURLToPath(new URL('../bin/lastid-agent.js', import.meta.url));
      const started = await ensureListenerRunning({ scope, cliPath });
      console.log(`   listener:   ${started.status} — channel + sync now active (no restart needed)`);
    } catch (err) {
      console.error(
        `   listener:   start failed (${err instanceof Error ? err.message : String(err)}) — ` +
          'restart Claude to activate the channel.',
      );
    }
  }

  // Semantic memory onboarding. The embedding model (~137MB) + dep install ONCE
  // per host and are SHARED across every agent/scope (only the memories are
  // per-identity), so we only prompt when this host has no model yet. Asked,
  // never silently auto-installed; best-effort, so it never fails provisioning.
  try {
    const { embeddingsInstalled } = await import('./embeddings.js');
    if (await embeddingsInstalled()) {
      console.log('   semantic mem: enabled (shared model already on this host)');
    } else {
      const choice = await promptEnableEmbeddings();
      if (choice === true) {
        const { spawnSync } = await import('node:child_process');
        const { fileURLToPath } = await import('node:url');
        const cliPath = fileURLToPath(new URL('../bin/lastid-agent.js', import.meta.url));
        console.log('');
        const r = spawnSync('node', [cliPath, 'memory-setup', '--scope', scope], {
          stdio: 'inherit',
        });
        console.log(
          r.status === 0
            ? '   semantic mem: enabled + verified'
            : '   semantic mem: setup did not finish — retry with `lastid-agent memory-setup`',
        );
      } else if (choice === false) {
        console.log('   semantic mem: skipped — enable later with `lastid-agent memory-setup`');
      } else {
        // No TTY (Claude Code's bash tool, CI): can't prompt — recommend, and
        // let the operator (or the agent on their behalf) run it.
        console.log('');
        console.log('Recommended next: enable semantic memory — run `lastid-agent memory-setup`.');
        console.log('   One-time ~137MB model, shared by all your agents on this host, then verified.');
        console.log('   Until then, memory search uses keyword matching.');
      }
    }
  } catch {
    /* embeddings onboarding is best-effort — never fail provisioning on it */
  }
}

async function cmdShow(flags) {
  const scope = resolveScope(flags);
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
  const scope = resolveScope(flags);
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
  const scope = resolveScope(flags);
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
    const embedder = typeof makeEmbedder === 'function' ? makeEmbedder({ scope }) : null;
    const { markdown } = await retrievePacket({
      scope,
      agentDid: claims.sub ?? loaded.agentDid ?? null,
      parentHumanDid: claims.parent_human_did ?? null,
      prompt,
      operatorStore: new OperatorStore(scope),
      embedder,
      // Repo the agent is working in (normalized git remote), resolved by the
      // hook from the operative path / sticky last-project. Gates project-tier
      // memory injection; null → global+agent only.
      projectKey: typeof flags['project-key'] === 'string' ? flags['project-key'] : null,
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
  const scope = resolveScope(flags);
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
    const embedder = typeof makeEmbedder === 'function' ? makeEmbedder({ scope }) : null;
    const block = await retrieveSearchBlock({
      scope,
      agentDid: claims.sub ?? loaded.agentDid ?? null,
      parentHumanDid: claims.parent_human_did ?? null,
      query: prompt,
      limit,
      excludeBedrock,
      embedder,
      // Repo the agent is operating in, resolved by the PreToolUse hook from
      // the tool's operative path. Surfaces THIS repo's project memories
      // ambiently; null → none.
      projectKey: typeof flags['project-key'] === 'string' ? flags['project-key'] : null,
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
  const { spawnSync } = await import('node:child_process');
  const { mkdirSync } = await import('node:fs');

  const { embeddingsInstalled, embeddingsRuntimeDir } = await import('./embeddings.js');
  // Install into a STABLE, version-independent dir (~/.lastid-agent/
  // embeddings-runtime), NOT the per-version plugin node_modules — otherwise
  // every `/plugin update` orphans the dep and silently drops semantic memory
  // to keyword until this re-runs. The dir + the global model cache both
  // survive updates, so semantic memory keeps working across versions.
  if (!(await embeddingsInstalled())) {
    const runtimeDir = embeddingsRuntimeDir();
    mkdirSync(runtimeDir, { recursive: true });
    process.stdout.write(
      `Installing local embeddings (@xenova/transformers, ~137MB) into ${runtimeDir}…\n`,
    );
    const r = spawnSync(
      'npm',
      ['install', '@xenova/transformers', '--prefix', runtimeDir, '--omit=dev', '--no-audit', '--no-fund'],
      { stdio: ['ignore', process.stderr, process.stderr] },
    );
    if (r.status !== 0) {
      process.stderr.write(`memory-setup: dependency install failed (exit ${r.status ?? 'n/a'})\n`);
      process.exit(1);
    }
  } else {
    process.stdout.write('Embeddings dependency already installed (survives plugin updates).\n');
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
  const scope = resolveScope(flags);
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
  const loaded = await loadAgentVc(resolveScope(flags));
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
    // Pass this agent's own DID so per-agent rule EXEMPTIONS are honored — a
    // global rule the operator opted THIS agent out of won't fire here.
    const local = new OperatorStore(resolveScope(flags)).policyDecision(tool, input, {
      selfDid: loaded.agentDid,
    });
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
  const [
    { deriveAgentEd25519Keypair },
    { OperatorStore },
    { syncAgentState },
    { MemoryStore },
    { decodeVcClaims },
  ] = await Promise.all([
    import('./agent-provisioning.js'),
    import('./operator-store.js'),
    import('./agent-state-sync.js'),
    import('./memory-store.js'),
    import('./vc-claims.js'),
  ]);
  const idpUrl = loaded.idpUrl ?? env.LASTID_IDP_URL ?? 'https://human.lastid.co';
  const { signingKey } = deriveAgentEd25519Keypair(loaded.slotSeed);
  const store = new OperatorStore(scope);
  // Memory store for cross-session/host reconcile: agent-authored memories
  // (and memory revokes) from the IdP land here, so a memory written on
  // another host/session shows up locally.
  const claims = decodeVcClaims(loaded.vcCompact) ?? {};
  const memoryStore = new MemoryStore(scope, undefined, {
    agentDid: claims.sub ?? loaded.agentDid ?? null,
    parentHumanDid: claims.parent_human_did ?? null,
  });
  return syncAgentState({
    idpUrl,
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    slotSeed: loaded.slotSeed,
    // Lets the sync decrypt shared project-tier records (target='project').
    // Null for agents provisioned before project memories → those records are
    // skipped as undecryptable (they still get global+agent).
    projectRootSeed: loaded.projectRootSeed ?? null,
    store,
    memoryStore,
    scope, // vault shares cache per scope
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
  const scope = resolveScope(flags);
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
  const scope = resolveScope(flags);
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
    { acquireListenerLock, releaseListenerLock },
  ] = await Promise.all([
    import('./agent-provisioning.js'),
    import('./mls-client.js'),
    import('./ws-client.js'),
    import('./mls-dispatch.js'),
    import('./agent-send.js'),
    import('./agent-state-sync.js'),
    import('./listener-daemon.js'),
  ]);

  // Single-instance enforcement. The listener is the single MLS-state writer
  // and the sole owner of the agent-state sync cursor for this scope; a second
  // listener races the shared cursor and silently drops rules/memories (see
  // acquireListenerLock). Become the sole listener before opening MLS state —
  // evict any other live listener (manual or daemon-spawned) and claim the lock.
  const lock = await acquireListenerLock({ scope });
  if (lock.evicted) {
    process.stderr.write(
      `[lastid-agent] evicted a pre-existing listener (pid ${lock.evicted}) on scope=${scope} — single MLS writer enforced\n`,
    );
  }

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

  // Drain the audit spool into the signed chain, then ship it to the IdP
  // (operator-visible cross-device). The listener is the SINGLE chain writer:
  // every other process (the MCP tool server's memory CUD, the
  // PreToolUse/PostToolUse hooks' tool events) only ENQUEUES to the spool, so
  // the hash chain can't fork under parallel tool calls. We drain in order
  // here, sign + hash-link each event, then ship. Offline-safe via the ship
  // cursor; the `auditFlushing` guard keeps two ticks from draining at once.
  let auditFlushing = false;
  const shipAuditBestEffort = async () => {
    if (auditFlushing) return;
    auditFlushing = true;
    try {
      try {
        const { drainAuditSpool } = await import('./audit-spool.js');
        const chained = drainAuditSpool({ scope, signingKey, agentDid: loaded.agentDid });
        if (chained > 0) process.stderr.write(`[lastid-agent] chained ${chained} spooled audit event(s)\n`);
      } catch (e) {
        process.stderr.write(`[lastid-agent] audit spool drain failed: ${e?.message ?? e}\n`);
      }
      const { shipMemoryAudit } = await import('./memory-audit-ship.js');
      const n = await shipMemoryAudit({
        idpUrl,
        scope,
        agentDid: loaded.agentDid,
        vcCompact: loaded.vcCompact,
        signingKey,
      });
      if (n > 0) process.stderr.write(`[lastid-agent] shipped ${n} audit record(s) to IdP\n`);
    } catch {
      /* best-effort */
    } finally {
      auditFlushing = false;
    }
  };

  // Ship locally-recorded rule-hit metrics (the PreToolUse hook appends them).
  // Best-effort + off the latency path; the ship cursor only advances on a 2xx.
  const shipRuleHitsBestEffort = () =>
    import('./rule-metrics-ship.js')
      .then((m) =>
        m.shipRuleMetrics({
          idpUrl,
          scope,
          agentDid: loaded.agentDid,
          vcCompact: loaded.vcCompact,
          signingKey,
        }),
      )
      .then((n) => {
        if (n > 0) process.stderr.write(`[lastid-agent] shipped ${n} rule-hit metric(s) to IdP\n`);
      })
      .catch(() => {});

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
      // Ship any unshipped local memory-audit records to the IdP so the
      // operator can view the agent's memory CUD from browser/desktop/mobile.
      // Offline-safe — the ship cursor only advances on success.
      void shipAuditBestEffort();
      void shipRuleHitsBestEffort();
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

  // Event-loop liveness monitor. A blocked event loop is exactly what kills
  // this listener: a synchronous CPU burst (MLS wasm, embedding model) delays
  // the WS ping/pong, the IdP liveness check (server.ts: isAlive===false →
  // terminate, every ~30s) fires, and the socket drops 1006. So measure it
  // directly — schedule a 1s tick and report how far PAST schedule it actually
  // fired. `lag` ≈ how long the loop was blocked. Watch this over several
  // minutes (longer than the ~30s terminate window): healthy = lag near 0;
  // any multi-second lag is a stall that can cost us the connection.
  const LOOP_TICK_MS = 1_000;
  let loopTicks = 0;
  let lastTick = Date.now();
  let maxLag = 0;
  const loopMonitor = setInterval(() => {
    const now = Date.now();
    const lag = now - lastTick - LOOP_TICK_MS;
    lastTick = now;
    loopTicks += 1;
    if (lag > maxLag) maxLag = lag;
    // Heartbeat every 60s (liveness + cumulative max lag), plus an immediate
    // line whenever a single tick slips >200ms — a real event-loop stall, the
    // condition that can delay the WS pong and cost us the connection.
    if (loopTicks % 60 === 0 || lag > 200) {
      process.stderr.write(
        `[lastid-agent] loop tick #${loopTicks} lag=${lag}ms (max ${maxLag}ms) ws=${wsOpen ? 'up' : 'down'}\n`,
      );
    }
  }, LOOP_TICK_MS);
  if (typeof loopMonitor.unref === 'function') loopMonitor.unref();

  // Embedding daemon: load the memory-search model ONCE here (warm) and serve
  // it over a unix socket so per-prompt CLI spawns (memory-retrieve/-search)
  // get fast embeddings instead of re-initializing. No-op when the opt-in
  // embeddings dep isn't installed (clients fall back to in-process/keyword).
  let embedServer = null;
  try {
    const { startEmbeddingServer } = await import('./embedding-listener.js');
    const r = await startEmbeddingServer({ scope });
    embedServer = r.server ?? null;
    process.stderr.write(`[lastid-agent] embedding daemon: ${r.status}\n`);
  } catch (err) {
    process.stderr.write(`[lastid-agent] embedding daemon failed (non-fatal): ${err?.message ?? err}\n`);
  }

  // Vault daemon: the local trusted inject boundary. The listener is the ONLY
  // process that holds slot_seed + the handle store + unfurls a secret, so the
  // MCP tool process (a separate, untrusted-by-design surface the model drives)
  // forwards vault_use / http_fetch here over the unix socket and never touches
  // plaintext. resolveShare decrypts + verifies the operator signature per call
  // (reading the freshly-pinned delegation key), so a forged/unverified share
  // is refused. Best-effort: a vault socket error never disrupts MLS/channel.
  let vaultServer = null;
  try {
    const [{ startVaultServer }, { resolveVaultShare }, { VaultHandleStore }, { OperatorStore }] =
      await Promise.all([
        import('./vault-ipc.js'),
        import('./vault-cache.js'),
        import('./vault-handle-store.js'),
        import('./operator-store.js'),
      ]);
    const vaultHandles = new VaultHandleStore();
    const r = await startVaultServer({
      scope,
      deps: {
        agentDid: loaded.agentDid,
        handles: vaultHandles,
        // Fresh OperatorStore per call so we use the latest pinned delegation
        // key (it may get pinned by a sync after the listener started).
        resolveShare: (itemId) =>
          resolveVaultShare(scope, itemId, {
            slotSeed: loaded.slotSeed,
            operatorJwk: new OperatorStore(scope).pinnedDelegationJwk,
            onReject: (id, why) =>
              process.stderr.write(`[lastid-agent] vault share ${id} refused: ${why}\n`),
          }),
        fetchImpl: globalThis.fetch,
        now: () => Date.now(),
        recordUse: (kind, h) =>
          process.stderr.write(
            `[lastid-agent] vault ${kind}: item=${h.itemId} approved=${h.wasApproved}\n`,
          ),
      },
    });
    vaultServer = r.server ?? null;
    process.stderr.write(`[lastid-agent] vault daemon: ${r.status}\n`);
  } catch (err) {
    process.stderr.write(`[lastid-agent] vault daemon failed (non-fatal): ${err?.message ?? err}\n`);
  }

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
    // Piggyback: drain+chain+ship any audit events spooled by the MCP tool or
    // the Pre/PostToolUse hooks, plus rule-hit metrics, since the last tick.
    // Cheap when the spool/queue is empty.
    void shipAuditBestEffort();
    void shipRuleHitsBestEffort();
  }, OUTBOX_POLL_MS);
  if (typeof drainTimer.unref === 'function') drainTimer.unref();

  const shutdown = () => {
    process.stderr.write('[lastid-agent] shutting down\n');
    clearInterval(drainTimer);
    clearInterval(loopMonitor);
    ws.stop();
    if (embedServer) { try { embedServer.close(); } catch { /* ignore */ } }
    if (vaultServer) { try { vaultServer.close(); } catch { /* ignore */ } }
    try { mls.free(); } catch { /* ignore */ }
    // Release the single-instance lock if it's still ours (a listener that
    // took over from us already claimed it — don't delete a live owner's pid).
    void releaseListenerLock({ scope }).catch(() => {});
    exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Parent-session watchdog. The detached listener is tied to the Claude Code
  // session that spawned it: the SessionStart hook resolves that session's PID
  // and passes it as --parent-pid. Poll it; when the session is gone — INCLUDING
  // the Ctrl-C-twice / hard-kill cases where SessionEnd never fires — self-exit
  // gracefully so we never linger as a stray racing the next session's listener
  // on the scope's MLS state. Fail-safe: only arms for a valid pid; if none was
  // passed we simply don't watchdog (reap-on-SessionStart + SessionEnd still
  // clean up).
  const parentPid = Number.parseInt(String(flags['parent-pid'] ?? ''), 10);
  if (Number.isInteger(parentPid) && parentPid > 1) {
    process.stderr.write(`[lastid-agent] parent-session watchdog armed: pid ${parentPid}\n`);
    const WATCHDOG_MS = 5_000;
    const watchdog = setInterval(() => {
      let alive = true;
      try {
        process.kill(parentPid, 0); // signal 0 = existence probe, no signal sent
      } catch (err) {
        alive = err.code === 'EPERM'; // exists but not ours = still alive
      }
      if (!alive) {
        process.stderr.write(
          `[lastid-agent] owning session (pid ${parentPid}) is gone — self-terminating\n`,
        );
        clearInterval(watchdog);
        shutdown();
      }
    }, WATCHDOG_MS);
    if (typeof watchdog.unref === 'function') watchdog.unref();
  }

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
        scope: resolveScope(flags),
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
