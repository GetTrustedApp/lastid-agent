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
import {
  provisionAgent,
  provisionAgentViaBroker,
  resolveAgentDeviceId,
} from '../lib/agent-provisioning.js';
import { recordGroup } from '../lib/agent-groups.js';
import { resolveScope } from '../lib/scope.js';
import { setActiveScope } from '../lib/active-scope.js';
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
  const runtimeName = flags.runtime ?? detectRuntimeName();
  const projectHint = flags['project-hint'] ?? env.LASTID_PROJECT_HINT;
  // Shared operator-facing UX — surfaced identically whether provisioning runs
  // in node (legacy) or inside the signed broker (Phase 4 broker-credential-custody).
  const onUserCode = async ({ userCode, expiresIn }) => {
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
  };

  // Reissue — retire the OLD identity BEFORE we provision. ORDER IS LOAD-BEARING
  // for a broker-native agent: the old-device revoke needs the old agent key,
  // which lives ONLY in the old broker's protected store, and the provisioning
  // broker (--reprovision) is about to OVERWRITE that seed. The sequence:
  //   1. revoke the old device THROUGH the still-running listener broker (race-
  //      free — reuse the live agent-mode broker, do NOT start a fresh one; a
  //      fresh broker races the listener-broker's socket teardown → ECONNREFUSED);
  //   2. stop the old listener (its shutdown SIGTERMs the broker);
  //   3. wait for that broker to fully EXIT before the provisioning broker starts
  //      — stopListener returns before the broker dies, and starting the
  //      --reprovision broker into that window races the socket.
  // (clearScopeState runs AFTER provisioning, before the new KeyPackage publish —
  // see below.) A revoke failure is logged loudly but never blocks the reissue;
  // the stale device otherwise lapses at the old VC's expiry.
  if (reissue && existing) {
    console.log('');
    console.log('Reissue — retiring the old identity…');
    // 1. Revoke FIRST, through the live broker (must precede stopListener).
    try {
      const { revokeOldAgentDeviceForReissue } = await import('./agent-reissue.js');
      const oldDeviceId = await revokeOldAgentDeviceForReissue({
        existing,
        scope,
        idpUrl,
        log: (l) => process.stderr.write(`${l}\n`),
      });
      console.log(`   old device: revoked ${oldDeviceId} (evicted from groups, KeyPackages purged)`);
    } catch (err) {
      console.error(
        `   old device: revoke FAILED — ${err instanceof Error ? err.message : String(err)}`,
      );
      console.error('   (continuing the reissue; the stale device lapses at the old VC expiry)');
    }
    // 2. Stop the old listener.
    const { stopListener } = await import('./listener-daemon.js');
    try {
      const stopped = await stopListener({ scope });
      console.log(`   listener:   ${stopped.status} (old WebSocket closed)`);
    } catch (err) {
      console.error(
        `   listener:   stop failed — ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    // 3. Wait for the old broker to fully exit before the provisioning broker
    //    starts (so it binds a clean socket — no race with the dying broker).
    try {
      const { waitForBrokerDown } = await import('./broker-supervisor.js');
      const down = await waitForBrokerDown({ scope });
      if (!down) {
        console.error('   broker:     still answering after wait — provisioning may retry');
      }
    } catch {
      /* best-effort — startBrokerSupervisor's own socket-removal is the backstop */
    }
  }

  // Route provisioning through the signed broker when enabled (Phase 4): the
  // broker generates the ephemeral, unseals the slot seed, claims the VC, and
  // persists everything itself — the slot seed never enters this process. The
  // broker must run UNPROVISIONED for this; on success it has persisted, so we
  // stop it and the listener restarts it agent-mode (supervisor-restart model).
  // Falls back to the legacy in-node provisionAgent when the broker path is off
  // / not on macOS / the broker doesn't come up — no-flag-day.
  let provisioned = null;
  // Broker-native by DEFAULT on macOS (brokerIdpEnabled() is true unless the
  // LASTID_BROKER_IDP kill-switch is set / non-macOS). A fresh agent is born in
  // the broker's protected store with the seed never entering node; if the signed
  // broker can't start we fall through to the legacy in-node provisionAgent below.
  const { startBrokerSupervisor, brokerIdpEnabled } = await import('./broker-supervisor.js');
  if (brokerIdpEnabled()) {
    const provBroker = await startBrokerSupervisor({
      scope,
      idpUrl,
      // Reissue: force the broker provisioning-only so it mints a NEW identity
      // that overwrites the old protected-store seed. Without this the broker
      // boots agent-mode off the existing seed and ProvisionInitiate fails
      // (not_implemented — already provisioned).
      reprovision: reissue && !!existing,
      log: (l) => process.stderr.write(`${l}\n`),
    });
    if (provBroker?.ready) {
      try {
        console.log('Provisioning via the signed broker (the slot seed stays in the broker)…');
        provisioned = await provisionAgentViaBroker({
          scope,
          runtimeName,
          projectHint,
          parentHumanDid,
          onUserCode,
        });
      } finally {
        provBroker.stop?.();
      }
    } else {
      provBroker?.stop?.();
    }
  }
  if (!provisioned) {
    provisioned = await provisionAgent({
      idpUrl,
      parentHumanDid,
      runtimeName,
      projectHint,
      onUserCode,
    });
  }

  // Stamp the chosen IdP onto the provisioned bundle so the
  // keychain records which env this agent is bound to.
  provisioned.idpUrl = idpUrl;
  // The broker path already persisted (and node holds no slot seed to write);
  // only the legacy node path writes the keychain here.
  if (!provisioned.persistedByBroker) {
    await persistAgentVc(provisioned, scope);
  } else {
    // The broker BORN the seed + persisted it; load the bundle back so the
    // post-provision MLS KeyPackage publish (still in node for now) has the
    // material. NOTE: this transiently reads the slot seed in node — acceptable
    // under P4's dual-read keychain. P5's ACL lock-down closes this (the publish
    // would then route through the broker too). Birth custody is already won:
    // node never saw the seed during provisioning itself.
    const fromKeychain = await loadAgentVc(scope);
    if (fromKeychain) {
      provisioned.slotSeed = fromKeychain.slotSeed;
      provisioned.vcCompact = fromKeychain.vcCompact;
      provisioned.projectRootSeed = fromKeychain.projectRootSeed;
    }
  }
  console.log('');
  console.log('✅ Agent provisioned and persisted to keychain.');
  console.log(`   scope:      ${scope}`);
  console.log(`   slot:       ${provisioned.slotIndex}`);
  console.log(`   agent_did:  ${provisioned.agentDid}`);
  console.log(`   idp_url:    ${idpUrl}`);
  console.log(
    `   vc length:  ${
      provisioned.vcCompact ? `${provisioned.vcCompact.length} chars` : '(persisted in broker)'
    }`,
  );

  // Reissue local-state wipe — MUST run BEFORE publishing the new KeyPackage. We
  // just minted a NEW identity; the local store still holds records sealed to the
  // OLD slot_seed / signed by the OLD key (a stale sync cursor + undecryptable MLS
  // state). The old listener + its WebSocket and the old-device IdP revoke were
  // already handled BEFORE provisioning (see above — the revoke needs the old seed
  // the provisioning broker just overwrote). Here we only clear local state.
  //
  // ORDER IS LOAD-BEARING: clearScopeState deletes mls-state.b64. If the publish
  // ran first, the clear would throw away the private keys for the KeyPackages we
  // just registered on the IdP, and every inbound welcome would fail
  // `NoMatchingKeyPackage` (the operator's messages reach the agent but it can't
  // open them). So: clear → publish → start.
  if (reissue && existing) {
    const { clearScopeState } = await import('./listener-daemon.js');
    try {
      await clearScopeState(scope);
      console.log('   state:      cleared (old rules, memories, MLS, inbox, cursor)');
    } catch (err) {
      console.error(
        `   reset:      partial — ${err instanceof Error ? err.message : String(err)}`,
      );
      console.error(
        `   If state looks stale, stop Claude Code and run: rm -rf ~/.lastid-agent/${scope}`,
      );
    }
  }

  // Publish the agent's MLS KeyPackage so the operator's console can chat with
  // it immediately. Runs AFTER the reissue reset above so the persisted keystore
  // (mls-state.b64, holding the KeyPackage private keys) survives. Non-fatal —
  // if this fails the operator can still chat once the runtime is up and retries.
  //
  // CUSTODY (mem_01KTQK1E): only a legacy Ed25519 agent holds a node seed to mint
  // the throwaway publish client here. A P-256 agent has NO seed in node — its
  // KeyPackage publish runs in the listener (started moments below) via the shared
  // MLS handle + broker-authed IdP POST, where no seed is needed. So we DEFER
  // rather than call publishAgentKeyPackage seedless (which would throw the
  // "slotSeed or shared mls handle required" error and read as a scary failure).
  if (Buffer.isBuffer(provisioned.slotSeed) && provisioned.slotSeed.length === 32) {
    try {
      await publishAgentKeyPackage({
        idpUrl,
        agentDid: provisioned.agentDid,
        vcCompact: provisioned.vcCompact,
        slotSeed: provisioned.slotSeed,
        scope,
        // The device_id pinned at provisioning (`md-…` when machine-bound) so the
        // first KeyPackages publish under the machine device, matching the
        // credential the throwaway client stamps. null for a legacy agent → the
        // client derives the legacy `ad-…`.
        deviceId: provisioned.deviceId,
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
  } else {
    console.log('   mls keypkg: deferred to listener (broker-native, no node seed)');
  }

  // Bring the listener up — it loads the keystore the publish just persisted and
  // reconnects + syncs from scratch. Needed for BOTH a reissue (old listener was
  // stopped above) and a fresh provision (the SessionStart hook skipped the
  // listener because the scope wasn't provisioned at launch).
  try {
    const { ensureListenerRunning } = await import('./listener-daemon.js');
    const { fileURLToPath } = await import('node:url');
    const cliPath = fileURLToPath(new URL('../bin/lastid-agent.js', import.meta.url));
    const started = await ensureListenerRunning({ scope, cliPath });
    console.log(
      reissue && existing
        ? `   listener:   ${started.status} — reconnecting on the new identity`
        : `   listener:   ${started.status} — channel + sync now active (no restart needed)`,
    );
  } catch (err) {
    console.error(
      `   listener:   start failed (${err instanceof Error ? err.message : String(err)}) — ` +
        'restart Claude to activate the channel.',
    );
  }

  // Semantic memory onboarding. The embedding model (~137MB) + dep install ONCE
  // per host and are SHARED across every agent/scope (only the memories are
  // per-identity), so we only prompt when this host has no model yet. Asked,
  // never silently auto-installed; best-effort, so it never fails provisioning.
  try {
    const { embeddingsInstalled, modelInstalled, ensureEmbeddingsRuntime } = await import('./embeddings.js');
    if (await embeddingsInstalled()) {
      console.log('   semantic mem: enabled (shared model already on this host)');
    } else if (modelInstalled()) {
      // Opted in before (the model is cached) but the runtime dep was orphaned
      // by a plugin update — reinstall it. No prompt, no re-download: they
      // already chose semantic memory, so keep them in.
      const res = await ensureEmbeddingsRuntime({ log: (l) => console.log(`   ${l}`) });
      console.log(
        res.ok
          ? '   semantic mem: re-enabled (runtime reinstalled, kept you opted in)'
          : `   semantic mem: reinstall ${res.action} — run \`lastid-agent memory-setup\``,
      );
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
  }
  // Local-first only (the desktop fallback was removed — the agent uses the IdP
  // + stdin). No local hit → emit nothing so the hook injects no ambient context.
  process.exit(0);
}

/**
 * `lastid-agent vault-list --json` — called by the SessionStart and
 * UserPromptSubmit hooks to surface the credentials the operator has shared with
 * this agent (so it knows its vault access up front, not only via a mid-task
 * tool call). Decodes the LOCAL synced vault cache with the agent's slot_seed,
 * strips the secret (vaultListView → compactCredential), and prints
 * `{ "items": [...] }` on stdout. NEVER prints a secret. Soft-fail: any error /
 * not provisioned → `{ "items": [] }` and exit 0 so the hook injects nothing.
 */
async function cmdVaultList(flags) {
  const scope = resolveScope(flags);
  const emitEmpty = () => {
    process.stdout.write(JSON.stringify({ items: [] }));
    process.exit(0);
  };
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(scope);
  if (!loaded) emitEmpty();
  try {
    const { decryptedVaultViews } = await import('./vault-cache.js');
    const { compactCredential } = await import('./credential-awareness.js');
    const { items: decoded } = await decryptedVaultViews(scope, loaded.slotSeed);
    const items = decoded.map(compactCredential);
    process.stdout.write(JSON.stringify({ items }));
    process.exit(0);
  } catch (e) {
    process.stderr.write(`vault-list: ${e?.message ?? e}\n`);
    emitEmpty();
  }
}

/**
 * `lastid-agent install-stub-sub --slug X --name "..." --body-file path.md [opts]`
 *
 * Install a subagent locally in STUB mode (no IdP, no signature). Writes the
 * sub-scope dir + agent.md + updates the parent's index. The spawned Claude
 * session will run with just Claude tools (no LastID MCP tools — the scope
 * is unprovisioned). Useful for: testing the invocation pipeline, scripted
 * subagent installs from the console before IdP integration lands, and
 * one-off scratch subagents.
 *
 * Required: --slug, --name, --body-file (or --body "..." inline).
 * Optional: --scope <parent_scope>, --allowed-tools "a,b,c", --disallowed-tools "x,y",
 *           --mcp-allowed "lastid_send_message,lastid_memory_read".
 */
async function cmdInstallStubSub(flags) {
  const parentScope = resolveScope(flags);
  const slug = typeof flags.slug === 'string' ? flags.slug : '';
  const name = typeof flags.name === 'string' ? flags.name : '';
  let body = typeof flags.body === 'string' ? flags.body : null;
  if (!body && typeof flags['body-file'] === 'string') {
    const { readFile } = await import('node:fs/promises');
    body = await readFile(flags['body-file'], 'utf-8');
  }
  if (!slug || !name || !body) {
    process.stderr.write(
      'install-stub-sub: --slug, --name, and (--body-file or --body) are all required.\n',
    );
    process.exit(2);
  }
  const splitCsv = (s) => (typeof s === 'string' && s.length > 0 ? s.split(',').map((x) => x.trim()).filter(Boolean) : []);
  const { installStubSub } = await import('./subagents.js');
  try {
    const entry = await installStubSub({
      parentScope,
      slug,
      name,
      body,
      claudeTools: {
        allowed: splitCsv(flags['allowed-tools']),
        disallowed: splitCsv(flags['disallowed-tools']),
      },
      mcpAllowed: splitCsv(flags['mcp-allowed']),
    });
    process.stdout.write(`${JSON.stringify({ ok: true, entry }, null, 2)}\n`);
    process.exit(0);
  } catch (e) {
    process.stderr.write(`install-stub-sub: ${e?.message ?? e}\n`);
    process.exit(1);
  }
}

/** `lastid-agent list-subagents` — print installed subagents under the parent scope. */
async function cmdListSubagents(flags) {
  const parentScope = resolveScope(flags);
  const { listSubagents } = await import('./subagents.js');
  const subs = await listSubagents(parentScope);
  process.stdout.write(`${JSON.stringify({ parent_scope: parentScope, subagents: subs }, null, 2)}\n`);
  process.exit(0);
}

/**
 * `lastid-agent install-from-bundle <path>` — install a subagent from a
 * downloaded agent.md bundle. Reads the file, parses the frontmatter for
 * slug/name + the body for system prompt + claude_tools, and writes the
 * sub-scope locally.
 *
 * DEV-ONLY rail. The eventual install path is doorbell-driven (operator
 * publishes from the console → IdP → WS doorbell → listener pickup, same
 * shape vault/memory sync uses today). This command exists so the runtime
 * can be tested before that sync rail is wired. Once doorbell sync lands,
 * a dev can still use this to seed a subagent from a hand-edited agent.md
 * for local iteration.
 */
async function cmdInstallFromBundle(flags) {
  const parentScope = resolveScope(flags);
  // Positionals land in flags._ per parseFlags(). Path can also be passed
  // via --path for shell scripts that prefer named args.
  const bundlePath =
    (typeof flags.path === 'string' && flags.path) ||
    (Array.isArray(flags._) && flags._[0]) ||
    '';
  if (!bundlePath) {
    process.stderr.write(
      'install-from-bundle: pass the bundle path as a positional or --path.\n  Example: lastid-agent install-from-bundle ~/Downloads/echobot.agent.md\n',
    );
    process.exit(2);
  }
  const { readFile } = await import('node:fs/promises');
  let raw;
  try {
    raw = await readFile(bundlePath, 'utf-8');
  } catch (e) {
    process.stderr.write(`install-from-bundle: read ${bundlePath} failed: ${e?.message ?? e}\n`);
    process.exit(1);
  }
  const { parseAgentMd, installStubSub } = await import('./subagents.js');
  let parsed;
  try {
    parsed = parseAgentMd(raw);
  } catch (e) {
    process.stderr.write(`install-from-bundle: ${e?.message ?? e}\n`);
    process.exit(1);
  }
  const fm = parsed.frontmatter ?? {};
  if (!fm.slug || !fm.name) {
    process.stderr.write('install-from-bundle: bundle frontmatter missing slug or name.\n');
    process.exit(1);
  }
  // Trust the bundle's own parent_scope if it carries one (console embeds it
  // at authoring time). Otherwise fall back to the CLI-resolved scope so the
  // operator can install into whichever primary they choose.
  const effectiveParent =
    typeof fm.parent_scope === 'string' && fm.parent_scope.trim().length > 0
      ? fm.parent_scope.trim()
      : parentScope;
  try {
    const entry = await installStubSub({
      parentScope: effectiveParent,
      slug: fm.slug,
      name: fm.name,
      body: parsed.body,
      claudeTools: {
        allowed: Array.isArray(fm.claude_tools?.allowed) ? fm.claude_tools.allowed : [],
        disallowed: Array.isArray(fm.claude_tools?.disallowed) ? fm.claude_tools.disallowed : [],
      },
      mcpAllowed: Array.isArray(fm.mcp_allowed) ? fm.mcp_allowed : [],
    });
    process.stdout.write(`${JSON.stringify({ ok: true, parent_scope: effectiveParent, entry }, null, 2)}\n`);
    process.exit(0);
  } catch (e) {
    process.stderr.write(`install-from-bundle: ${e?.message ?? e}\n`);
    process.exit(1);
  }
}

/** `lastid-agent uninstall-sub --slug X` — remove a subagent + its scope dir. */
async function cmdUninstallSub(flags) {
  const parentScope = resolveScope(flags);
  const slug = typeof flags.slug === 'string' ? flags.slug : '';
  if (!slug) {
    process.stderr.write('uninstall-sub: --slug is required.\n');
    process.exit(2);
  }
  const { uninstallSub } = await import('./subagents.js');
  const r = await uninstallSub({ parentScope, slug });
  process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  process.exit(r.ok ? 0 : 1);
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
  }
  // Local-first only (the desktop fallback was removed — the agent uses the IdP
  // + stdin). Nothing local → emit nothing so the hook injects no context.
  process.exit(0);
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
  // Install into a STABLE, version-independent dir (~/.lastid-agent/
  // embeddings-runtime), NOT the per-version plugin node_modules — otherwise
  // every `/plugin update` orphans the dep and silently drops semantic memory
  // to keyword until this re-runs. The dir + the global model cache both
  // survive updates, so semantic memory keeps working across versions. The
  // listener self-heals this automatically when the model is already cached;
  // this command is the explicit first-time (or forced) path.
  const { embeddingsInstalled, installEmbeddingsRuntime } = await import('./embeddings.js');
  if (!(await embeddingsInstalled())) {
    const { status, locked } = installEmbeddingsRuntime({
      log: (l) => process.stdout.write(`${l}\n`),
      stdio: ['ignore', process.stderr, process.stderr],
    });
    if (locked) {
      process.stderr.write('memory-setup: another install is in progress — retry shortly.\n');
      process.exit(1);
    }
    if (status !== 0) {
      process.stderr.write(`memory-setup: dependency install failed (exit ${status})\n`);
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
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(resolveScope(flags));
  if (!loaded) {
    // Not provisioned — fail open. The plugin acts only on
    // explicitly-authored rules; without an agent there is no
    // way to look them up.
    process.exit(0);
  }

  // Local-first: the synced operator-store IS the operator's rule set once we've
  // pulled any state, so a SaaS-fed agent enforces rules with nothing else
  // running. (The desktop /policy/check fallback was removed — IdP + stdin only.)
  try {
    const { OperatorStore, deriveOperatorStateMacKey } = await import('./operator-store.js');
    // Pass this agent's own DID so per-agent rule EXEMPTIONS are honored — a
    // global rule the operator opted THIS agent out of won't fire here. Key the
    // store so a tampered operator-state.json (deleted deny rule, flipped
    // exemption) fails the integrity check and we fail open to safe defaults
    // rather than enforcing the agent's own edit.
    const local = new OperatorStore(resolveScope(flags), undefined, {
      macKey: deriveOperatorStateMacKey(loaded.slotSeed),
    }).policyDecision(tool, input, {
      selfDid: loaded.agentDid,
    });
    if (local) {
      process.stdout.write(JSON.stringify(local));
      process.exit(0);
    }
  } catch (e) {
    process.stderr.write(`policy-check(local): ${e?.message ?? e}\n`);
  }
  // No local decision → fail open (the plugin acts only on explicitly-authored
  // rules; absent a hit there is nothing to enforce).
  process.exit(0);
}

/**
 * `lastid-agent self-protection-status` — prints `{"enabled":bool}` for whether
 * agent self-protection is currently ON, honoring the SAME MAC-verified keyed
 * operator-store the PreToolUse deny path uses: a delegation-signed,
 * integrity-verified opt-out disables it; an unsigned disk edit is ignored. The
 * PostToolUse output-net calls this on a key-material hit so it goes quiet when
 * the operator has turned self-protection off. Fails SAFE — not provisioned or
 * any error → enabled (protect by default).
 */
async function cmdSelfProtectionStatus(flags) {
  let enabled = true;
  try {
    const { loadAgentVc } = await import('./keychain.js');
    const scope = resolveScope(flags);
    const loaded = await loadAgentVc(scope);
    if (loaded) {
      const { OperatorStore, deriveOperatorStateMacKey } = await import('./operator-store.js');
      enabled = new OperatorStore(scope, undefined, {
        macKey: deriveOperatorStateMacKey(loaded.slotSeed),
      }).selfProtectionEnabled();
    }
    // Not provisioned → keep the default-on protection.
  } catch (e) {
    process.stderr.write(`self-protection-status: ${e?.message ?? e}\n`);
    enabled = true; // fail safe → protected
  }
  process.stdout.write(JSON.stringify({ enabled }));
  process.exit(0);
}

/**
 * Pull the operator's rules/memories from the IdP agent-state store and
 * apply them to the local operator-store (saas-migration.md §6). Shared
 * by `cmdSync` (CLI / session-start kick) and the listener's doorbell +
 * on-connect triggers. Returns the sync result; throws on transport
 * errors (callers fail open).
 */
async function runAgentStateSync(loaded, scope, opts = {}) {
  const [
    { deriveAgentKeypair },
    { OperatorStore, deriveOperatorStateMacKey },
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
  // MLS-custody: a broker-native agent has no seed in node — the operator-store
  // MAC key comes from the broker (byte-identical to deriveOperatorStateMacKey),
  // and signingKey stays null (syncAgentState's IdP auth + content decrypt route
  // through the broker via authedIdpFetch + brokerDecryptContent). Legacy agents
  // derive both from the seed as before.
  const brokerNative = loaded.brokerNative === true;
  let signingKey = null;
  let macKey = null;
  if (brokerNative) {
    const { brokerDeriveOperatorStoreMacKey } = await import('./broker-ipc.js');
    macKey = await brokerDeriveOperatorStoreMacKey({ scope });
  } else {
    ({ signingKey } = deriveAgentKeypair(loaded.slotSeed, loaded.agentDid));
    macKey = deriveOperatorStateMacKey(loaded.slotSeed);
  }
  // The listener is the SINGLE writer of operator-state — key it so every save
  // stamps the anti-tamper MAC (off the slot_seed, which isn't in the file).
  const store = new OperatorStore(scope, undefined, { macKey });
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
    ...(typeof opts.onReject === 'function' ? { onReject: opts.onReject } : {}),
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
  // Record this process's scope so the shared authedIdpFetch broker dispatch
  // (FORK1) can locate ~/.lastid-agent/<scope>/broker.{sock,token} without
  // threading scope through every list-A call site.
  setActiveScope(scope);
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    process.stderr.write(`not_provisioned (scope=${scope}) — run \`lastid-agent provision\` first\n`);
    exit(3);
  }
  const idpUrl = loaded.idpUrl ?? env.LASTID_IDP_URL ?? 'https://human.lastid.co';

  const [
    { deriveAgentKeypair },
    { MlsClient },
    { LastIdWsClient, brokerWsEligible },
    { MlsDispatcher },
    { drainOutbox },
    { makeDoorbellHandler },
    { acquireListenerLock, releaseListenerLock },
    { reconcileConversationDevices },
    { PresenceEmitter },
    { readActivityTs, readSignalTs },
    { getOrchestrator, disposeOrchestrator },
    { startBrokerSupervisor },
  ] = await Promise.all([
    import('./agent-provisioning.js'),
    import('./mls-client.js'),
    import('./ws-client.js'),
    import('./mls-dispatch.js'),
    import('./agent-send.js'),
    import('./agent-state-sync.js'),
    import('./listener-daemon.js'),
    import('./reconcile-conversation.js'),
    import('./presence-emitter.js'),
    import('./presence-activity.js'),
    import('./mls-orchestrator.js'),
    import('./broker-supervisor.js'),
  ]);

  // The agent's operator (parent human) — the only peer it reconciles against.
  const operatorDid = decodeVcClaims(loaded.vcCompact)?.parent_human_did ?? null;

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

  // The listener owns the signed broker's lifecycle. A BROKER-NATIVE agent (seed
  // in the protected store, absent from node) REQUIRES the broker to serve every
  // op, so we start it (enabled:true — a broker-native agent must run its broker
  // even if the kill-switch is set; the switch only governs fresh provisioning).
  // A LEGACY agent (seed in the keychain) keeps the node path and never starts a
  // broker — existing agents are byte-unchanged. Torn down in shutdown().
  const broker = loaded.brokerNative === true
    ? await startBrokerSupervisor({
        scope,
        idpUrl,
        enabled: true,
        log: (l) => process.stderr.write(`${l}\n`),
      })
    : null;
  if (broker) {
    process.stderr.write(
      `[lastid-agent] signed broker supervised (scope=${scope} ready=${broker.ready} pid=${broker.pid ?? '?'})\n`,
    );
  }

  // Agent-state doorbell: a content-free `rules.changed` / `memory.changed`
  // WS event triggers a (debounced) incremental pull from the IdP into the
  // local operator-store, so a published rule reaches this agent without a
  // restart. Best-effort + fail-open — a failed sync never disrupts the
  // listener. (saas-migration.md §6.)
  const onDoorbell = makeDoorbellHandler(() => {
    runAgentStateSync(loaded, scope, {
      onReject: (rec, reason) =>
        process.stderr.write(
          `[lastid-agent] agent-state sync reject: kind=${rec?.kind ?? '?'} id=${rec?.id ?? '?'} reason=${reason}\n`,
        ),
    })
      .then((r) =>
        process.stderr.write(
          `[lastid-agent] doorbell sync: applied ${r.applied}, cursor ${r.cursor}\n`,
        ),
      )
      .catch((err) =>
        process.stderr.write(`[lastid-agent] doorbell sync failed: ${err?.message ?? err}\n`),
      );
  });

  // MLS-custody: a BROKER-NATIVE agent has no slot seed in node — it lives only
  // in the broker's protected store. The MLS at-rest wrap key + the audit-chain
  // signatures come from the broker (the agent identity key never enters node).
  // A LEGACY agent (seed in the keychain) is byte-unchanged.
  const brokerNative = loaded.brokerNative === true;
  let signingKey = null;
  let signingSeed = null;
  let mlsWrapKey = null;
  if (brokerNative) {
    const { brokerDeriveMlsStateKey } = await import('./broker-ipc.js');
    mlsWrapKey = await brokerDeriveMlsStateKey({ scope });
    process.stderr.write(
      '[lastid-agent] broker-native: MLS wrap key + audit signing via the broker; the slot seed never enters node\n',
    );
  } else {
    ({ signingKey, signingSeed } = deriveAgentKeypair(loaded.slotSeed, loaded.agentDid));
  }
  // The audit-chain signer: the legacy in-process key (a node KeyObject) for a
  // legacy agent, or an async broker signer (raw-ES256 over the record core,
  // validated broker-side as an audit record) for a broker-native agent. Either
  // way the chain stays signed by the agent identity key.
  const auditSigner = brokerNative
    ? async (bytes) => {
        const { brokerSignAuditRecord } = await import('./broker-ipc.js');
        return brokerSignAuditRecord({ scope, coreBytes: bytes });
      }
    : signingKey;

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
      // RANDOM self-verification (~1 in 5 flushes): the append-time self-heal
      // only catches a broken TAIL; this catches a DEEP break and re-roots a
      // clean generation BEFORE we drain new events onto it. Cheap + best-effort.
      if (Math.random() < 0.2) {
        try {
          const { auditSelfCheck, publicKeyFor } = await import('./memory-audit.js');
          // auditSigner signs (legacy key or broker); publicKey verifies — only
          // available in node for a legacy agent (broker-native skips the in-node
          // signature check; the IdP verifies it server-side).
          const r = await auditSelfCheck({
            scope,
            signingKey: auditSigner,
            agentDid: loaded.agentDid,
            publicKey: signingKey ? publicKeyFor(signingKey) : null,
          });
          if (r.healed) process.stderr.write(`[lastid-agent] audit chain healed (was broken at seq ${r.firstFailure?.seq})\n`);
        } catch (e) {
          process.stderr.write(`[lastid-agent] audit self-check failed: ${e?.message ?? e}\n`);
        }
      }
      try {
        const { drainAuditSpool } = await import('./audit-spool.js');
        const chained = await drainAuditSpool({ scope, signingKey: auditSigner, agentDid: loaded.agentDid });
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
        // Records are already signed; signingKey here is only the IdP-call auth,
        // which the broker covers for a broker-native agent (authedIdpFetch).
        signingKey: brokerNative ? null : signingKey,
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

  // B1 convergence: ONE MLS instance for the whole listener. We build the
  // shared wasm orchestrator (disk-backed via diskKvCallbacks) once, then wrap
  // it as the MlsClient the dispatcher + send path use. The SAME ctx object is
  // threaded into drainOutbox → ensureConversation and reconcileConversationDevices
  // below, so getOrchestrator returns this same cached handle to them — no
  // second openmls instance. Previously the dispatcher/send opened a disk
  // client while ensure/reconcile built a SEPARATE orchestrator on a phantom
  // IndexedDB backend, so a group one created was invisible to the other — the
  // multi-device welcome bug (mem_01KSNXSY4TY7DK7EJTREPNY5RH).
  // L5: resolve this agent's MLS device_id ONCE — the keychain-pinned `md-…`
  // for a machine-bound (reissued) agent, else the legacy `ad-…` derivation
  // (no-flag-day; existing agents unchanged). The SAME value is threaded into
  // the orchestrator handle (via ctx.deviceId) and the MlsClient wrapper, so
  // the credential the shared handle stamps and the device_id KeyPackage
  // publish reports can never disagree (the multi-device two-sources class).
  // A broker-native agent is always machine-bound → its device_id is the pinned
  // md- (no seed needed to resolve it); a legacy agent derives from the seed.
  const resolvedDeviceId =
    Buffer.isBuffer(loaded.slotSeed) && loaded.slotSeed.length === 32
      ? resolveAgentDeviceId({
          persistedDeviceId: loaded.deviceId,
          slotSeed: loaded.slotSeed,
          agentDid: loaded.agentDid,
        })
      : (loaded.deviceId ?? null);
  const listenerCtx = {
    scope,
    agentDid: loaded.agentDid,
    operatorDid,
    idpUrl,
    vcCompact: loaded.vcCompact,
    signingKey,
    // Legacy: the raw seed (getOrchestrator derives the MLS wrap key in node).
    // Broker-native: slotSeed is null and wrapKey is the broker-derived at-rest
    // key, so node never holds the seed to seal/open the MLS keystore.
    slotSeed: loaded.slotSeed,
    wrapKey: mlsWrapKey,
    deviceId: resolvedDeviceId,
    log: (l) => process.stderr.write(`${l}\n`),
  };
  // MLS-into-broker (unit B3): a BROKER-NATIVE P-256 (`zDn…`) agent drives MLS
  // THROUGH the broker — which now serves the openmls primitives — so node holds
  // ZERO MLS key material. We MUST NOT build the node wasm orchestrator for that
  // case: getOrchestrator opens a node openmls instance, and a second instance
  // over the same identity would split MLS state with the broker's (the
  // multi-instance class). The Ed25519/legacy path is byte-identical (still the
  // node orchestrator + fromOrchestrator). brokerWsEligible is the EXACT same
  // discriminator the WS path uses (brokerNative && did starts with
  // `did:lastid:agent:zDn`), so the chat channel and the MLS engine agree on
  // which agents the broker serves.
  const useBrokerMls = brokerWsEligible({
    brokerNative: loaded.brokerNative === true,
    agentDid: loaded.agentDid,
  });
  let orchestrator = null;
  let mls;
  if (useBrokerMls) {
    const { makeMlsBrokerClient } = await import('./mls-broker-client.js');
    mls = makeMlsBrokerClient({
      scope,
      agentDid: loaded.agentDid,
      deviceId: resolvedDeviceId,
    });
    process.stderr.write(
      '[lastid-agent] broker-native: MLS served by the signed broker; no node openmls instance\n',
    );
  } else {
    orchestrator = await getOrchestrator(listenerCtx);
    mls = MlsClient.fromOrchestrator(orchestrator, loaded.agentDid, resolvedDeviceId);
  }

  // One-time repair of the persisted group map: re-seed the idp→openmls
  // mapping for every valid group into the live MLS client (the agent only
  // recorded these to groups.json, never into the wasm client — so on a fresh
  // process reconcile(idpUuid) couldn't resolve them and crashed), and drop
  // records whose group_id_b64 is a base64'd UUID (unrecoverable, from before
  // the create-path fix). Best-effort; logs its own outcome.
  try {
    const { repairGroupIdMappings } = await import('./agent-groups.js');
    await repairGroupIdMappings({
      scope,
      mls,
      log: (l) => process.stderr.write(`${l}\n`),
    });
  } catch (err) {
    process.stderr.write(
      `[lastid-agent] groups repair failed (non-fatal): ${err?.message ?? err}\n`,
    );
  }

  // Multi-device reconcile for a BROKER-NATIVE agent (unit B2): instead of the
  // node-side wasm reconcile (which a broker agent never builds), drive the
  // reconcile for EACH of the agent's operator groups THROUGH THE BROKER. The
  // broker runs the shared lastid-mls-core reconcile loop over its own IdP-call
  // seam — discovering the operator's other devices (e.g. a newly-added phone)
  // and adding their leaves. Guarded by the same `reconciling` mutex + `wsOpen`
  // as the legacy path; declared here (before the WS block) so the on-connect
  // pass can call it. Best-effort: each group's result is logged; one group's
  // error never blocks the others. Ed25519/legacy agents never reach this — they
  // keep the node-side reconcile below.
  let reconciling = false;
  const reconcileBrokerGroups = async (trigger) => {
    if (!useBrokerMls) return;
    if (!wsOpen || reconciling || !operatorDid) return;
    if (typeof mls.reconcileGroup !== 'function') return;
    reconciling = true;
    try {
      const { listGroups } = await import('./agent-groups.js');
      const groups = await listGroups({ scope });
      // SECURITY: only the agent's OWN operator's groups (exact operator_did
      // match) — never reconcile a group whose peer isn't the operator.
      const operatorGroups = groups.filter(
        (g) => g.operatorDid === operatorDid && g.idpGroupId,
      );
      for (const g of operatorGroups) {
        try {
          const changed = await mls.reconcileGroup(g.idpGroupId);
          process.stderr.write(
            `[lastid-agent] broker reconcile (${trigger}) ${g.idpGroupId}: ${changed ? 'changed' : 'no-op'}\n`,
          );
        } catch (err) {
          process.stderr.write(
            `[lastid-agent] broker reconcile (${trigger}) ${g.idpGroupId} failed: ${err?.message ?? err}\n`,
          );
        }
      }
    } catch (err) {
      process.stderr.write(
        `[lastid-agent] broker reconcile (${trigger}) enumerate failed: ${err?.message ?? err}\n`,
      );
    } finally {
      reconciling = false;
    }
  };

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
        deviceId: loaded.deviceId,
        // Mint into the listener's ONE shared MLS instance, NOT a competing
        // client — otherwise the KP private parts the operator's welcome needs
        // get clobbered by the orchestrator's next flush → NoMatchingKeyPackage
        // (mem_01KSNXSY4TY7DK7EJTREPNY5RH). B1 convergence.
        mls,
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
  // Presence (received + typing) emitter — assigned once the WS exists below.
  // The dispatcher fires onOperatorMessage when it decrypts an inbound operator
  // chat message; presence is set by then (inbound only arrives post-connect).
  let presence;
  const dispatcher = new MlsDispatcher({
    mls,
    scope,
    onOperatorMessage: (groupId, info) => {
      // Diagnostic (listener.log): the read receipt fires ONLY when the inbound
      // carried BOTH a message_id and the operator's sender_did — log which we
      // got so a missing field is visible instead of a silent read SKIP.
      try {
        const mid = info && typeof info.messageId === 'string' ? info.messageId : null;
        const sdid = info && typeof info.senderDid === 'string' ? info.senderDid : null;
        process.stderr.write(
          `[lastid-agent] presence onOperatorMessage group=${groupId} ` +
            `msgId=${mid ?? 'MISSING'} sender=${sdid ? sdid.slice(0, 24) + '…' : 'MISSING'} ` +
            `→ read ${mid && sdid ? 'EMIT' : 'SKIP'}\n`,
        );
      } catch {
        /* diagnostic only — never affects messaging */
      }
      try {
        presence?.onOperatorMessage(groupId, info);
      } catch {
        /* best-effort — presence never affects messaging */
      }
      // Bump this group's activity so resolveActiveGroupForOperator (max
      // updated_at) sends replies into the conversation the operator is
      // ACTIVELY using — the group they just messaged from — not the
      // newest-CREATED group. Native model: one thread per DID; the backing
      // group can rotate, replies follow the live thread. recordGroup with no
      // groupIdB64 preserves the existing mapping and only refreshes
      // operator_did + updated_at. Fire-and-forget; never blocks messaging.
      try {
        const sdid = info && typeof info.senderDid === 'string' ? info.senderDid : null;
        if (sdid && groupId) {
          recordGroup({ scope, idpGroupId: groupId, operatorDid: sdid }).catch(() => {});
        }
      } catch {
        /* best-effort — activity bump never affects messaging */
      }
    },
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
  // Broker-owns-WS (Phase 3 op 3): route the /v1/ws channel through the signed
  // broker for a BROKER-NATIVE agent (P-256 zDn… DID — the broker is P-256-only;
  // Ed25519 z6Mk… agents keep the direct node WS). A broker-native agent has NO
  // node signing key (the seed lives only in the broker), so it MUST get its WS
  // upgrade auth from the broker — node cannot mint the DPoP (signingKey null →
  // a null-key crypto throw). Discriminated by where the seed lives, NOT the
  // legacy LASTID_BROKER_IDP opt-in (now only a kill-switch). ws-client also
  // re-checks per connect that a broker is actually up, so this only ever ADDS
  // the broker path, never removes the legacy fallback for seed-in-node agents.
  const brokerWs = brokerWsEligible({
    brokerNative: loaded.brokerNative === true,
    agentDid: loaded.agentDid,
  });
  const ws = new LastIdWsClient({
    idpUrl,
    agentDid: loaded.agentDid,
    vcCompact: loaded.vcCompact,
    signingKey,
    brokerWs,
    scope,
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
      // Multi-device reconcile on (re)connect (unit B2): a broker-native agent
      // reconciles its operator groups through the broker the moment the socket
      // comes up, so a newly-added device (e.g. the operator's phone) is welcomed
      // PROMPTLY rather than waiting up to 5 minutes for the next timer tick.
      // No-op for Ed25519/legacy agents (reconcileBrokerGroups self-skips).
      void reconcileBrokerGroups('on-connect');
      // Catch-up: pull current operator rules/memories on (re)connect, so
      // a freshly-provisioned or long-offline agent gets up to date.
      void runAgentStateSync(loaded, scope)
        .then(async (r) => {
          process.stderr.write(
            `[lastid-agent] agent-state sync on connect: applied ${r.applied}, cursor ${r.cursor}\n`,
          );
          // Subagent self-heal: walk the installed subagents index and
          // run provisionSubagent for any without a VC. Handles the case
          // where the doorbell-driven apply wrote the scope dir but the
          // OID4VCI round-trip silently failed (the doorbell sync path
          // discards rejections via safely(undefined, ...)). Idempotent —
          // provisionSubagent short-circuits when a VC already exists.
          try {
            const { selfHealSubagents } = await import('./subagent-provisioning.js');
            const heal = await selfHealSubagents({
              idpUrl,
              parentSlotSeed: loaded.slotSeed,
              parentSigningKey: signingKey,
              parentDid: loaded.agentDid,
              parentVcCompact: loaded.vcCompact,
              parentScope: scope,
              parentProjectRootSeed: loaded.projectRootSeed,
            });
            if (heal.attempted > 0) {
              process.stderr.write(
                `[lastid-agent] subagent self-heal: attempted=${heal.attempted} provisioned=${heal.ok} already-ok=${heal.alreadyOk} failed=${heal.failed}\n`,
              );
            }
          } catch (err) {
            process.stderr.write(
              `[lastid-agent] subagent self-heal failed: ${err?.message ?? err}\n`,
            );
          }
        })
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
    onEvent: async (evt) => {
      // TEMP DIAGNOSTIC: log every WS event type the listener sees so we can
      // disambiguate "IdP not broadcasting" vs "listener dropping events".
      // Remove once the doorbell sync flow is confirmed reliable.
      try {
        process.stderr.write(
          `[lastid-agent] ws event: type=${evt?.type ?? '?'} recipient_did=${evt?.target?.recipient_did ?? '?'} ts=${evt?.timestamp ?? '?'}\n`,
        );
      } catch { /* never break the dispatch on a log */ }
      if (onDoorbell(evt)) return;
      // Await the dispatcher so the ws-client layer's own try/catch can
      // trap any rejection — without an await the rejection becomes an
      // unhandledRejection on the loop tick (Node v15+ kills the process).
      // The dispatcher already serializes internally via its single-flight
      // chain (mls-dispatch.js:#chain), so awaits here don't change ordering.
      try {
        await dispatcher.onEvent(evt);
      } catch (err) {
        process.stderr.write(
          `[lastid-agent] dispatcher.onEvent threw (caught): ${
            err instanceof Error ? err.message : String(err)
          }\n`,
        );
      }
    },
    onError: (err) => process.stderr.write(`[lastid-agent] ws error: ${err.message}\n`),
    // Auto-cleanup when the IdP rejects the upgrade with the SPECIFIC
    // "Credential has been revoked" signal: the listener has nothing
    // useful left to do (a revoked VC can't be un-revoked), so wipe
    // local state and exit cleanly. Stops the dead-reconnect spam that
    // hammered prod /v1/ws every ~10s for hours when an old sub-agent
    // scope was orphaned by an edit-caps revoke + reissue cycle
    // (validated live 2026-05-29 — `dev-testy-mctestface` listener
    // attempt #871).
    onAuthRevoked: async (detail) => {
      process.stderr.write(
        `[lastid-agent] auth revoked (${detail.httpStatus} ${detail.errorCode}): ${detail.errorDescription} — wiping scope ${scope}\n`,
      );
      try {
        const { cleanupRevokedScope } = await import('./scope-cleanup.js');
        const summary = await cleanupRevokedScope(scope);
        process.stderr.write(
          `[lastid-agent] scope-cleanup summary: ${JSON.stringify(summary)}\n`,
        );
      } catch (err) {
        process.stderr.write(
          `[lastid-agent] scope-cleanup orchestration failed: ${err?.message ?? err}\n`,
        );
      }
      // Exit clean — no exception trace, just done. Anything supervising
      // this listener (launchd, claude code's spawn, etc.) won't restart
      // it because there's no scope dir left to bind to anyway.
      process.exit(0);
    },
  });
  wsRef = ws;

  process.stderr.write(`[lastid-agent] listening as ${loaded.agentDid} on ${idpUrl}\n`);
  ws.start();

  // Presence: the operator-facing "received + typing" indicator. The listener
  // is the sole WS writer, so it owns this. A window opens only when the
  // dispatcher decrypts an inbound operator chat message (onOperatorMessage
  // above) — CLI work never opens one, so it can't leak typing. The tick reads
  // the activity heartbeat (PostToolUse → presence-activity file): a fresh
  // timestamp means the agent is working, which keeps the typing indicator
  // alive; idle/cap timeouts fade it. Best-effort — never touches messaging.
  presence = new PresenceEmitter({
    send: (frame) => {
      try {
        ws.send(frame);
      } catch {
        /* a typing frame that fails to send is harmless — clients auto-clear */
      }
    },
    userDid: loaded.agentDid,
  });
  let lastActivitySeen = 0;
  let lastSendingSeen = 0;
  let lastTurnEndSeen = 0;
  // 2s (was 4s): catches the brief send-tool "sending" signal promptly enough
  // for the typing dots, and keeps "working" alive within the client's
  // few-second indicator TTL.
  const PRESENCE_TICK_MS = 2_000;
  const presenceTimer = setInterval(() => {
    if (!wsOpen) return; // don't emit into a down socket; client TTL clears it
    try {
      const a = readActivityTs(scope);
      if (a > lastActivitySeen) {
        lastActivitySeen = a;
        presence.noteActivity(); // any tool ran → keep "working" alive
      }
      // Send-message tool fired (pre-tool-use) → show typing until it lands.
      const s = readSignalTs(scope, 'sending');
      if (s > lastSendingSeen) {
        lastSendingSeen = s;
        presence.onSending();
      }
      // The agent's turn ended (before-stop) → clear working/typing precisely.
      const e = readSignalTs(scope, 'turn_end');
      if (e > lastTurnEndSeen) {
        lastTurnEndSeen = e;
        presence.onTurnEnd();
      }
      presence.tick();
    } catch {
      /* best-effort */
    }
  }, PRESENCE_TICK_MS);
  if (typeof presenceTimer.unref === 'function') presenceTimer.unref();

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
    const [
      { startVaultServer },
      { resolveVaultShare, resolveVaultSecret },
      { fetchWrappedVaultSecret },
      { publishCredentialedUse },
      { genVaultHandleKeypair, openWithHandle },
      { VaultHandleStore },
      { OperatorStore },
      { enqueueAuditEvent },
    ] = await Promise.all([
      import('./vault-ipc.js'),
      import('./vault-cache.js'),
      import('./vault-secret-fetch.js'),
      import('./vault-use-metrics.js'),
      import('./sdk-bindings.js'),
      import('./vault-handle-store.js'),
      import('./operator-store.js'),
      import('./audit-spool.js'),
    ]);
    const vaultHandles = new VaultHandleStore();
    const { spawn: childSpawn } = await import('node:child_process');
    const r = await startVaultServer({
      scope,
      deps: {
        agentDid: loaded.agentDid,
        // signingKey (a Node KeyObject — Ed25519 or P-256) + vcCompact let
        // the listener run the cross-device approval loop INSIDE vault_use
        // (single dispatch site — see vault-ipc.js). Dual-algo: the
        // KeyObject's asymmetricKeyType picks the DPoP alg, so an Ed25519
        // agent doesn't 401 on an ES256 proof. Callers don't need to know
        // about the loop; they just await vault_use and get back ok+handle
        // or a clean error. signingSeed stays in deps for the secret-fetch
        // + credentialed-use telemetry paths below (still seed-based).
        signingKey,
        signingSeed,
        vcCompact: loaded.vcCompact,
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
        // Per vault-use: mint the ephemeral handle keypair the secret is wrapped
        // to (its private key never leaves this listener's memory).
        genHandleKeypair: () => genVaultHandleKeypair(),
        // JIT credential release (two-layer envelope): POST the handle public
        // key → the IdP wraps the sealed secret to it → open with the handle
        // private key → unseal with the slot_seed → inject → zeroize. The secret
        // is never cached: the permissioned window is the call, not "forever".
        resolveSecret: (itemId, handle) =>
          resolveVaultSecret(itemId, {
            scope,
            slotSeed: loaded.slotSeed,
            handle,
            fetchWrappedSecret: (id, handlePubB64, handleId) =>
              fetchWrappedVaultSecret({
                idpUrl,
                agentDid: loaded.agentDid,
                vcCompact: loaded.vcCompact,
                signingKey,
                id,
                handlePubB64,
                handleId,
              }),
            openWithHandle,
            onReject: (id, why) =>
              process.stderr.write(`[lastid-agent] vault secret ${id} refused: ${why}\n`),
          }),
        fetchImpl: globalThis.fetch,
        now: () => Date.now(),
        // The `exec` op (CLI credential proxy) spawns the child HERE in the
        // listener with the injected env, so the secret stays in this process +
        // the child, never the agent's tool process.
        spawnImpl: childSpawn,
        recordUse: (kind, h, m) => {
          process.stderr.write(
            `[lastid-agent] vault ${kind}: item=${h.itemId} approved=${h.wasApproved}` +
              (m
                ? ` permissioned=${m.permissioned_ms}ms credentialed=${m.credentialed_ms}ms status=${m.status ?? '-'} outcome=${m.outcome}`
                : '') +
              '\n',
          );
          // Ship the timing to the operator's guardrail metrics (best-effort).
          void publishCredentialedUse({
            idpUrl,
            agentDid: loaded.agentDid,
            vcCompact: loaded.vcCompact,
            signingKey,
            kind,
            handle: h,
            metrics: m,
          });
        },
        // Audit chain: a credential injection event (gated by the
        // 'credential_use' class). enqueue → the listener drains its own spool.
        audit: (eventType, metadata) => enqueueAuditEvent({ scope, eventType, metadata }),
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
      // Same listener ctx so a self-heal ensureConversation reuses the ONE
      // cached orchestrator (no forked instance). B1 convergence.
      ctx: listenerCtx,
      agentDid: loaded.agentDid,
      send: (frame) => {
        const ok = ws.send(frame);
        if (!ok) {
          wsOpen = false;
          throw new Error('ws not open');
        }
        // Presence: a reply just went to the operator → clear that group's
        // typing indicator (the message itself is the signal). Continued tool
        // activity re-shows it; if the agent's done, idle fades it. Best-effort.
        if (frame?.type === 'group_chat.message' && frame?.payload?.group_id) {
          try {
            presence?.onAgentReply(frame.payload.group_id);
          } catch {
            /* best-effort */
          }
        }
      },
      // Self-heal auth: lets the drain create a conversation (invite the
      // operator's devices) when none exists, instead of queuing forever.
      idpUrl,
      vcCompact: loaded.vcCompact,
      signingKey,
      // Reaction drain: react to the operator's last message in the group via
      // presence (it holds the target message id from the read-receipt path).
      reactToLastMessage: (groupId, emoji, action) =>
        presence?.reactToLastOperatorMessage(groupId, emoji, action) ?? {
          sent: false,
          reason: 'no_presence',
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

  // Device-consistency reconcile: periodically pick up NEW operator devices
  // and add them to the conversation, so a device the operator added after
  // the group was created can still read the agent's messages. Throttled (a
  // per-device key-package fetch is involved) and best-effort; self-skips when
  // there's no group yet (ensureConversation owns creation). The DECISION runs
  // the shared planner — the same logic native uses.
  const RECONCILE_INTERVAL_MS = 5 * 60_000;
  // `reconciling` + `reconcileBrokerGroups` are declared earlier (before the WS
  // block) so the on-connect pass can reuse the same mutex.
  const reconcileTimer = setInterval(() => {
    // Multi-device reconcile for a BROKER-NATIVE agent (unit B2): the node-side
    // reconcile drives a NODE wasm orchestrator the broker branch never builds,
    // so for broker agents we reconcile EACH operator group THROUGH THE BROKER
    // instead of skipping the tick. Ed25519/legacy agents keep the node path.
    if (useBrokerMls) {
      void reconcileBrokerGroups('timer');
      return;
    }
    if (!wsOpen || reconciling || !operatorDid) return;
    reconciling = true;
    void reconcileConversationDevices({
      scope,
      mls,
      // Same listener ctx → the cached orchestrator, not a forked one.
      ctx: listenerCtx,
      agentDid: loaded.agentDid,
      operatorDid,
      idpUrl,
      vcCompact: loaded.vcCompact,
      signingKey,
      log: (l) => process.stderr.write(`${l}\n`),
    })
      .catch((err) =>
        process.stderr.write(`[lastid-agent] reconcile failed: ${err?.message ?? err}\n`),
      )
      .finally(() => {
        reconciling = false;
      });
  }, RECONCILE_INTERVAL_MS);
  if (typeof reconcileTimer.unref === 'function') reconcileTimer.unref();

  const shutdown = () => {
    process.stderr.write('[lastid-agent] shutting down\n');
    clearInterval(drainTimer);
    clearInterval(reconcileTimer);
    clearInterval(loopMonitor);
    ws.stop();
    if (embedServer) { try { embedServer.close(); } catch { /* ignore */ } }
    if (vaultServer) { try { vaultServer.close(); } catch { /* ignore */ } }
    // Free the ONE shared orchestrator handle explicitly. mls is a
    // fromOrchestrator wrapper (ownsHandle:false) so mls.free() is a no-op;
    // disposeOrchestrator is what releases the wasm handle. Explicit free here
    // also avoids the GC-finalize-flush rust panic at exit
    // (mem_01KSRJR43ZARPS9CPCYPB0DND3). MLS-into-broker (B3): the broker branch
    // never built a node orchestrator (orchestrator stays null, mls is the
    // broker client whose free() is a no-op), so there is nothing node-side to
    // dispose — the broker owns its handle lifecycle and is stopped below.
    if (!useBrokerMls) {
      try { disposeOrchestrator(listenerCtx); } catch { /* ignore */ }
    }
    // Stop the supervised signed broker (null when on the legacy node path).
    if (broker) { try { broker.stop(); } catch { /* ignore */ } }
    // Release the single-instance lock if it's still ours (a listener that
    // took over from us already claimed it — don't delete a live owner's pid).
    void releaseListenerLock({ scope }).catch(() => {});
    exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Stay-alive guards. Node v15+ defaults to terminating on an
  // unhandledRejection — wasm-bindgen's borrow-tracking panic
  // ("recursive use of an object detected ...") is thrown from inside a
  // wasm future and was killing the listener mid-session (witnessed
  // 2026-05-28 right after a welcome→queue_batch→message burst, before
  // the dispatcher's serialization fix landed). Belt-and-suspenders: log
  // the reason but DO NOT exit, so an isolated wasm or async error in
  // one inbound never strands the operator with a dead listener. The
  // SIGINT/SIGTERM paths above remain the only intentional shutdown.
  process.on('unhandledRejection', (reason) => {
    try {
      process.stderr.write(
        `[lastid-agent] unhandledRejection (kept alive): ${
          reason instanceof Error
            ? `${reason.message}\n${reason.stack ?? ''}`
            : String(reason)
        }\n`,
      );
    } catch { /* never throw from the guard */ }
  });
  process.on('uncaughtException', (err) => {
    try {
      process.stderr.write(
        `[lastid-agent] uncaughtException (kept alive): ${
          err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err)
        }\n`,
      );
    } catch { /* never throw from the guard */ }
  });

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

/**
 * `lastid-agent run --handle <token> -- <command> [args]` — the CLI
 * credential proxy. Mirrors the http_fetch shape exactly: caller already
 * minted the handle via `vault_use` (which is where the operator
 * approval gate lives), CLI just SPENDS the handle. The handle's
 * `handles.lookup` inside handleVaultExec is the validation — same
 * function http_fetch uses, same error shape on a bad/expired/wrong-
 * agent handle.
 *
 * No `--item` and no internal `vault_use` call: that path would
 * bifurcate the gate (the rules check + approval loop would fire here
 * AS WELL as in vault_use), making the CLI a second policy decision
 * site. Single-shape contract: mint via vault_use, spend via run or
 * http_fetch. The secret never enters this process or the agent's
 * context — only the listener + the child see it.
 */
async function cmdRun(flags, cmdArgv) {
  const scope = resolveScope(flags);
  const handle = typeof flags.handle === 'string' && flags.handle.length > 0
    ? flags.handle
    : null;
  if (!handle) {
    process.stderr.write(
      'run: --handle <token> required (mint via `vault_use` first).\n' +
      '     The CLI does NOT call vault_use itself — that\'s the operator\n' +
      '     approval / rules gate, owned by the MCP / wallet caller.\n',
    );
    exit(2);
  }
  if (Object.prototype.hasOwnProperty.call(flags, 'item')) {
    // --item used to mint internally; that was the bifurcation site that
    // produced duplicate approvals when a caller minted via vault_use AND
    // the CLI minted again. Hard-fail so the new shape is obvious.
    process.stderr.write(
      'run: --item is no longer accepted. The CLI now takes --handle <token>\n' +
      '     (mirroring http_fetch). Call vault_use first to get a handle,\n' +
      '     then pass it via --handle.\n',
    );
    exit(2);
  }
  if (!Array.isArray(cmdArgv) || cmdArgv.length === 0) {
    process.stderr.write('run: command required after `--`  (e.g. lastid-agent run --handle <token> -- aws s3 ls)\n');
    exit(2);
  }
  const { loadAgentVc } = await import('./keychain.js');
  const loaded = await loadAgentVc(scope);
  if (!loaded) {
    process.stderr.write('run: not provisioned — run `lastid-agent provision` first\n');
    exit(2);
  }
  const { vaultExecStream } = await import('./vault-ipc.js');
  // `used` shape is just { vault_handle } from here — exec validates the
  // handle via handles.lookup (same path http_fetch uses) and errors
  // with handle_invalid on missing/expired/wrong-agent.
  const used = { vault_handle: handle };

  // Stream the child's output live; the secret is injected + scrubbed entirely
  // in the listener, so only already-clean bytes reach us.
  let terminal;
  try {
    terminal = await vaultExecStream(
      scope,
      { vault_handle: used.vault_handle, argv: cmdArgv, cwd: process.cwd() },
      { onStdout: (b) => process.stdout.write(b), onStderr: (b) => process.stderr.write(b) },
    );
  } catch (e) {
    process.stderr.write(`run: exec failed (${e?.message ?? e})\n`);
    exit(1);
  }
  if (terminal?.error) {
    process.stderr.write(`run: ${terminal.error}${terminal.detail ? ': ' + terminal.detail : ''}\n`);
    exit(1);
  }
  if (terminal?.timed_out) process.stderr.write('run: command timed out and was killed\n');
  if (terminal?.truncated) process.stderr.write('run: output truncated (output cap reached)\n');
  exit(typeof terminal?.exit_code === 'number' ? terminal.exit_code : 0);
}

async function main() {
  const [, , cmd, ...rest] = argv;
  // `run` passes the child command after a `--` terminator; keep those tokens
  // out of parseFlags so the child's OWN flags (e.g. `aws s3 ls --recursive`)
  // aren't swallowed as ours.
  const ddIdx = rest.indexOf('--');
  const flagArgs = ddIdx === -1 ? rest : rest.slice(0, ddIdx);
  const cmdArgv = ddIdx === -1 ? [] : rest.slice(ddIdx + 1);
  const flags = parseFlags(flagArgs);
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
    case 'vault-list':
      await cmdVaultList(flags);
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
    case 'self-protection-status':
      await cmdSelfProtectionStatus(flags);
      break;
    case 'run':
      await cmdRun(flags, cmdArgv);
      break;
    case 'install-stub-sub':
      await cmdInstallStubSub(flags);
      break;
    case 'install-from-bundle':
      await cmdInstallFromBundle(flags);
      break;
    case 'list-subagents':
      await cmdListSubagents(flags);
      break;
    case 'uninstall-sub':
      await cmdUninstallSub(flags);
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
      console.log('  run        Run a CLI with a vault credential injected as env vars,');
      console.log('             without ever exposing the secret to the agent:');
      console.log('             lastid-agent run --item <id> -- <command> [args]');
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
