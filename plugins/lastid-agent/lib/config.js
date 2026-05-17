/**
 * Plugin-local config.
 *
 * Stored at `~/.lastid-agent/config.json`. Holds the one-time
 * `clientId` registered at https://human.lastid.co (free tier issues
 * one), the IdP endpoint URL, and any per-host preferences. Never
 * stores private key material — those live in the OS keychain (see
 * `keychain.js`).
 *
 * Mirrors the shape used by `lastid-claude-guard` so credentials
 * registered against one plugin can be reused by the other.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CONFIG_DIR = join(homedir(), '.lastid-agent');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

const DEFAULTS = Object.freeze({
  idpEndpoint: 'https://human.dev.lastid.co',
  clientId: '',
  callbackUrl: 'lastid-agent://callback',
  registeredAt: null,
});

export function loadConfig() {
  if (!existsSync(CONFIG_PATH)) {
    return { ...DEFAULTS };
  }
  try {
    const raw = readFileSync(CONFIG_PATH, 'utf-8');
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveConfig(updates) {
  const merged = { ...loadConfig(), ...updates };
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2), { mode: 0o600 });
  try {
    chmodSync(CONFIG_PATH, 0o600);
  } catch {
    // best-effort on non-POSIX hosts
  }
  return merged;
}

export function isConfigured() {
  const cfg = loadConfig();
  return typeof cfg.clientId === 'string' && cfg.clientId.length > 0;
}
