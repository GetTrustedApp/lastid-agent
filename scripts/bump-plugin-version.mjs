#!/usr/bin/env node
/**
 * Bumps the LastID Agent plugin version across every file that must
 * stay in sync. Claude Code caches plugins by manifest version — without
 * a bump, `/plugin update lastid-agent@lastid-agent` reports "already at
 * latest" and users never see new code.
 *
 * Files updated:
 *   - .claude-plugin/marketplace.json              (plugins[0].version)
 *   - plugins/lastid-agent/.claude-plugin/plugin.json
 *   - package.json
 *
 * Usage:
 *   node scripts/bump-plugin-version.mjs patch   # 0.1.0 → 0.1.1
 *   node scripts/bump-plugin-version.mjs minor   # 0.1.0 → 0.2.0
 *   node scripts/bump-plugin-version.mjs major   # 0.1.0 → 1.0.0
 *   node scripts/bump-plugin-version.mjs 0.1.5   # set explicit version
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

const FILES = [
  resolve(repoRoot, '.claude-plugin/marketplace.json'),
  resolve(repoRoot, 'plugins/lastid-agent/.claude-plugin/plugin.json'),
  resolve(repoRoot, 'package.json'),
];

function readVersion(path) {
  const obj = JSON.parse(readFileSync(path, 'utf-8'));
  if (path.endsWith('marketplace.json')) {
    return obj.plugins?.[0]?.version ?? null;
  }
  return obj.version ?? null;
}

function writeVersion(path, version) {
  const obj = JSON.parse(readFileSync(path, 'utf-8'));
  if (path.endsWith('marketplace.json')) {
    if (!obj.plugins?.[0]) {
      throw new Error(`${path}: no plugins[0] to update`);
    }
    obj.plugins[0].version = version;
  } else {
    obj.version = version;
  }
  writeFileSync(path, JSON.stringify(obj, null, 2) + '\n');
}

function bump(current, kind) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(current);
  if (!m) throw new Error(`unparseable version: ${current}`);
  let [maj, min, pat] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (kind === 'major') { maj++; min = 0; pat = 0; }
  else if (kind === 'minor') { min++; pat = 0; }
  else if (kind === 'patch') { pat++; }
  else throw new Error(`unknown bump kind: ${kind}`);
  return `${maj}.${min}.${pat}`;
}

const arg = process.argv[2];
if (!arg) {
  console.error('usage: bump-plugin-version.mjs (patch|minor|major|x.y.z)');
  process.exit(1);
}

const current = readVersion(FILES[1]);
if (!current) {
  console.error('could not read current version from plugins/lastid-agent/.claude-plugin/plugin.json');
  process.exit(1);
}

const next = /^\d+\.\d+\.\d+$/.test(arg) ? arg : bump(current, arg);

console.log(`bump: ${current} → ${next}`);
for (const f of FILES) {
  const before = readVersion(f);
  if (before === null) {
    console.error(`  ${f}: no version field — skipping`);
    continue;
  }
  writeVersion(f, next);
  console.log(`  ${f.replace(repoRoot + '/', '')}: ${before} → ${next}`);
}

// Marketplace.json doesn't set a version on the top-level object;
// confirm the manifest + package.json end up in sync.
const after = FILES.map(readVersion).filter((v) => v !== null);
if (new Set(after).size !== 1) {
  console.error(`drift! ${JSON.stringify(after)}`);
  process.exit(1);
}
console.log(`ok. all ${after.length} files at ${next}.`);
console.log('next: git add -A && git commit -m "bump: vX.Y.Z" && git push.');
console.log('Claude Code users get the new version on /plugin update lastid-agent@lastid-agent.');
