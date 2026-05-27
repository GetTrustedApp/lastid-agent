/**
 * Agent self-protection — the agent refusing to read LastID's OWN secrets into
 * its context. Distinct from operator rules: this is the system protecting
 * itself, not a user preference, so it ships ON by default and is enforced
 * built-in (a brand-new agent is protected before its first sync), but it CAN
 * be disabled (locally for debugging LastID itself, or remotely by the operator).
 *
 * THE GAP it closes: lib/keychain.js stores this agent's slot_seed /
 * project_root_seed / VC in the host keychain with no per-app ACL, so any
 * same-user process — INCLUDING the agent's own Bash/Read — can run
 * `security find-generic-password -s lastid.co/agent-slot-seed -w` (or
 * `secret-tool lookup`, or a script that does it) and pull the identity root
 * into context, side-stepping "the value never enters context". Until the
 * keychain items are ACL-locked to a signed LastID binary (the durable fix),
 * this denies the agent's TOOLS from naming or dumping that material.
 *
 * KEY INSIGHT: match the SECRET'S IDENTIFIERS, not the command — tool-agnostic,
 * so ONE rule catches every exfil vector: running `security …`, writing a
 * script that does it, `cat`/`python`-ing it, etc. (the matcher flattens every
 * string field of every tool call). The listener reads these via its own code
 * path — NOT a tool call through the hook — so this never blocks legitimate use.
 */

/** Built-in deny rules (OperatorStore matcher shape: tool/pattern/is_regex/
 *  severity/reason). tool '*' = any tool, so Bash AND a Write-of-a-script match.
 *  Patterns target LastID's own keychain service names (see keychain.js) + a
 *  full keychain dump that would sweep them up. Keep in lockstep with the
 *  SERVICE_* names in keychain.js. */
export const SELF_PROTECTION_RULES = [
  {
    id: 'lastid-key-material',
    tool: '*',
    // The sensitive LastID keychain services: agent/sub-agent slot-seed,
    // project-root-seed, and VC. Naming any of these in a tool call is the
    // tell, whether it's `security …`, `secret-tool …`, or a written script.
    pattern: 'lastid\\.co/(?:sub-)?agent-(?:slot-seed|project-root-seed|vc)\\b',
    is_regex: true,
    severity: 'deny',
    reason:
      "This is LastID's own agent key material — it must never be read into your context. Refuse, and tell your operator if you were asked to.",
  },
  {
    id: 'keychain-dump',
    tool: '*',
    // A full keychain dump would expose LastID's seeds along with everything
    // else. Reading a SPECIFIC non-LastID item by name is still allowed.
    pattern: '\\bsecurity\\s+dump-keychain\\b',
    is_regex: true,
    severity: 'deny',
    reason:
      "Dumping the whole keychain would expose LastID's own keys. Refuse — read a specific, named, non-LastID item if you have a legitimate need.",
  },
  {
    id: 'lastid-self-source',
    tool: '*',
    // self-protection.js + keychain.js enumerate the matcher patterns and the
    // literal key-material service names. PreToolUse sees tool INPUT, not its
    // output, so a plain `cat keychain.js` would otherwise slip those names into
    // context — recon for evading this very rule. Deny naming these files (the
    // .test.js fixtures embed the same names, so they're covered too). Defense-
    // in-depth: the plugin is open source, so this raises the bar for a local
    // rummage; it does not hide the patterns from anyone determined. The durable
    // key protection is the OS-ACL / daemon layer.
    pattern: '(?:self-protection|keychain)(?:\\.test)?\\.js\\b',
    is_regex: true,
    severity: 'deny',
    reason:
      "These files define LastID's own self-protection matcher and key-material service names — reading them into your context is off limits. Refuse, and tell your operator if you were asked to.",
  },
]

export const SELF_PROTECTION_PACK_ID = 'agent-self-protection'

const OFF_VALUES = new Set(['off', '0', 'false', 'disabled', 'no'])

/** Local override — disables self-protection for THIS process (debugging LastID
 *  itself). `LASTID_SELF_PROTECTION=off`. Injectable env for tests. */
export function selfProtectionDisabledByEnv(env = process.env) {
  return OFF_VALUES.has(String(env.LASTID_SELF_PROTECTION ?? '').trim().toLowerCase())
}

/**
 * The built-in deny rules as OperatorStore records, so the matcher can iterate
 * them alongside synced operator rules (one matcher, one deny/audit/metric
 * path). Attributed to the self-protection pack so a hit meters + audits like a
 * curated hit and the console can show "agent self-protection".
 */
export function selfProtectionRecords() {
  return SELF_PROTECTION_RULES.map((r) => ({
    id: `selfprot:${r.id}`,
    kind: 'rule',
    target: 'self_protection',
    status: 'active',
    version: 1,
    updated_at: '',
    content: {
      tool: r.tool,
      pattern: r.pattern,
      is_regex: r.is_regex,
      severity: r.severity,
      reason: r.reason,
      curated: true,
      pack: SELF_PROTECTION_PACK_ID,
      rule: r.id,
      self_protection: true,
    },
  }))
}

// ─── Output-side redaction ──────────────────────────────────────────────────
// The deny rules above gate tool INPUT. But PreToolUse never sees a tool's
// OUTPUT, so an obfuscated read (a string-split service name, an odd path to
// keychain.js) can still spill LastID's own material into the result. This masks
// that material out of a text chunk — used for the audit-chain result and, via a
// PostToolUse block, to withhold a result from the model.
//
// `keyMaterial` counts the HIGH-SIGNAL hits (key-material service tokens) so the
// caller can decide to withhold the WHOLE output: the harness lets a PostToolUse
// hook BLOCK an output but not rewrite its bytes, so all-or-nothing is the only
// model-side lever. A bare filename (e.g. `ls` listing keychain.js) is redacted
// from the audit text but does NOT count as key material, so it won't trigger a
// block. NOTE: a `-w` read that emits ONLY a raw value with no surrounding
// identifier is indistinguishable from any base64 and is NOT caught here without
// false positives; that case is closed only by the OS-ACL / daemon layer.
const KEY_MATERIAL_RE = /lastid\.co\/(?:sub-)?agent-(?:slot-seed|project-root-seed|vc)(?::[\w.-]+)?/g
const SELF_SOURCE_RE = /(?:self-protection|keychain)(?:\.test)?\.js\b/g
const REDACTION = '[REDACTED:lastid-self-protection]'

export function redactSelfProtected(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text: text ?? '', count: 0, keyMaterial: 0 }
  }
  let keyMaterial = 0
  let out = text.replace(KEY_MATERIAL_RE, () => {
    keyMaterial++
    return REDACTION
  })
  let fileHits = 0
  out = out.replace(SELF_SOURCE_RE, () => {
    fileHits++
    return REDACTION
  })
  return { text: out, count: keyMaterial + fileHits, keyMaterial }
}

// ─── Audit event for a self-protection FIRE ──────────────────────────────────
// The operator must always SEE when self-protection tripped — the agent reached
// for LastID's own key material or guard source. This builds the audit-chain
// event for a fire (or null when it's not one); callers enqueue it UNGATED (a
// security signal, distinct from the toggle-able rule_fires metric). 'input' = a
// PreToolUse deny on a self-protection rule; 'output' = key material flagged in a
// tool's result by redactSelfProtected.
export const SELF_PROTECTION_EVENT = 'AgentSelfProtectionTriggered'

export function selfProtectionAuditEvent({ matched, tool, phase, kind } = {}) {
  if (phase === 'output') {
    return {
      eventType: SELF_PROTECTION_EVENT,
      metadata: { phase: 'output', tool: tool ?? null, kind: kind ?? 'key_material_in_output' },
    }
  }
  // 'input': only a self-protection DENY counts. The matcher tags these with
  // self_protection:true and a 'selfprot:'-prefixed id; key off either.
  const isSelfProt =
    !!matched &&
    (matched.self_protection === true || String(matched.memory_id || '').startsWith('selfprot:'))
  if (!isSelfProt || matched.severity !== 'deny') return null
  return {
    eventType: SELF_PROTECTION_EVENT,
    metadata: {
      phase: 'input',
      tool: tool ?? null,
      rule: matched.memory_id ?? null,
      severity: matched.severity,
      pack: matched.pack ?? null,
    },
  }
}
