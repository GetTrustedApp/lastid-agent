/**
 * Audit policy — the operator's SIGNED control over which classes of agent
 * action land in the audit chain. Authored in the console, signed with the
 * operator's delegation_authority, shipped + verified on the SAME rails as
 * rules (kind 'audit_policy'), and HONORED here AT THE SOURCE: a disabled class
 * is never spooled, so it never chains or ships (not merely hidden in the UI).
 *
 * AUDIT_CLASSES is the SINGLE SOURCE OF TRUTH for the auditable-surface
 * taxonomy. It enumerates EVERY auditable surface — INCLUDING ones the agent
 * doesn't emit yet (emitted:false) — so the console shows a toggle for each and
 * a surface is governed the moment its emit is wired. RULE: never add an
 * auditable emit without adding (or reusing) a class here, and keep the console
 * mirror (lastid.co src/lib/audit-classes.ts) in lockstep — same keys, same
 * event_type mapping. (A parity guard lives in both test suites.)
 *
 * Fail-OPEN: an event_type with no known class, or a class absent from the
 * policy, is AUDITED. We only ever drop an event the operator EXPLICITLY
 * disabled — a taxonomy gap must never silently lose audit coverage. Integrity
 * records (ChainCheckpoint) are intentionally unmapped, so they are always
 * audited regardless of policy.
 */
import { readFileSync, statSync } from 'node:fs';
import { operatorStatePath } from './operator-store.js';

/** Agent-state record kind + the singleton record id the console publishes. */
export const AUDIT_POLICY_KIND = 'audit_policy';
export const AUDIT_POLICY_ID = 'audit-policy';

/**
 * The auditable-surface taxonomy. `default`: audited when there's no policy yet.
 * `emitted`: whether the agent emits this class TODAY (false = wired later, but
 * the toggle exists now). `events`: the event_type strings this class governs.
 */
export const AUDIT_CLASSES = [
  {
    key: 'tool_calls',
    label: 'Tool calls',
    description: 'Every tool the agent invokes and its result (success/failure).',
    default: true,
    emitted: true,
    events: ['AgentToolInvoked', 'AgentToolSucceeded', 'AgentToolFailed'],
  },
  {
    key: 'memory_writes',
    label: 'Memory changes',
    description: 'The agent creating, updating, or forgetting a memory.',
    default: true,
    emitted: true,
    events: ['AgentMemoryWritten', 'AgentMemoryUpdated', 'AgentMemoryForgotten'],
  },
  {
    key: 'memory_reads',
    label: 'Memory reads',
    description: 'The agent searching or reading its memory (high-volume).',
    default: false, // opt-in: high-volume, low-signal
    emitted: true,
    events: ['AgentMemoryRead'],
  },
  {
    key: 'credential_use',
    label: 'Credential use',
    description: 'Minting a vault handle and injecting a credential at the network boundary.',
    default: true,
    emitted: true,
    events: ['AgentCredentialInjected'],
  },
  {
    key: 'rule_fires',
    label: 'Rule enforcement',
    description: 'When a rule denies, warns, or rewrites a call.',
    default: true,
    emitted: true, // recorded via the rule-metrics stream (gated by this class)
    events: ['AgentRuleFired'],
  },
  {
    key: 'file_access',
    label: 'File access',
    description: 'Files the agent reads or writes (path + change size; opt-in, high-volume).',
    default: false, // opt-in: tool_calls already records file ops; this is the richer file view
    emitted: true,
    events: ['AgentFileRead', 'AgentFileWritten'],
  },
  {
    key: 'messages',
    label: 'Messages',
    description: 'Messages the agent sends to or receives from the operator.',
    default: true,
    emitted: true,
    events: ['MessageSent', 'MessageReceived'],
  },
  {
    key: 'sub_agents',
    label: 'Sub-agents',
    description: 'When the agent spawns a delegated sub-agent.',
    default: true,
    emitted: true,
    events: ['AgentSpawned'],
  },
];

/** event_type → class key (reverse index, built once). */
const EVENT_TO_CLASS = new Map();
for (const c of AUDIT_CLASSES) for (const ev of c.events) EVENT_TO_CLASS.set(ev, c.key);

/** The class key governing an event_type, or null if unmapped (→ fail-open). */
export function classForEvent(eventType) {
  return EVENT_TO_CLASS.get(eventType) ?? null;
}

/** The default policy (class key → enabled) from the taxonomy defaults. */
export function defaultPolicyClasses() {
  const out = {};
  for (const c of AUDIT_CLASSES) out[c.key] = c.default;
  return out;
}

/**
 * Is this event_type audited under `policy`? Fail-OPEN: unmapped events (e.g.
 * ChainCheckpoint) and classes the policy doesn't mention fall back to the
 * class default (or true) — only an EXPLICIT `false` disables a class.
 * @param {{classes?: Record<string, boolean>}|null} policy
 */
export function isAuditEnabled(policy, eventType) {
  const key = classForEvent(eventType);
  if (!key) return true; // unmapped (integrity/unknown) → always audit
  const classes = policy && typeof policy === 'object' ? policy.classes : null;
  if (classes && Object.prototype.hasOwnProperty.call(classes, key)) {
    return classes[key] !== false;
  }
  // No policy entry for this class → its taxonomy default.
  const def = AUDIT_CLASSES.find((c) => c.key === key);
  return def ? def.default !== false : true;
}

// Read the synced audit policy from operator-state.json (the audit_policy
// record's decrypted content), memoized by file mtime so the per-tool-call
// hooks + the long-lived MCP server don't re-parse on every enqueue.
let _cache = { path: null, mtimeMs: -1, policy: null };

/** The operator's synced audit policy for a scope, or null if none deployed. */
export function loadAuditPolicy(scope = 'main') {
  const path = operatorStatePath(scope);
  let mtimeMs;
  try {
    mtimeMs = statSync(path).mtimeMs;
  } catch {
    return null; // no operator-state yet
  }
  if (_cache.path === path && _cache.mtimeMs === mtimeMs) return _cache.policy;
  let policy = null;
  try {
    const state = JSON.parse(readFileSync(path, 'utf8'));
    const records = state?.records && typeof state.records === 'object' ? state.records : {};
    for (const r of Object.values(records)) {
      if (r?.kind === AUDIT_POLICY_KIND && r.content && typeof r.content === 'object') {
        policy = r.content;
        break;
      }
    }
  } catch {
    policy = null;
  }
  _cache = { path, mtimeMs, policy };
  return policy;
}

/** Test seam — drop the mtime memo. */
export function __resetAuditPolicyCache() {
  _cache = { path: null, mtimeMs: -1, policy: null };
}
