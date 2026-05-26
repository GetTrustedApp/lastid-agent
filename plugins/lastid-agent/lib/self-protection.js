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
