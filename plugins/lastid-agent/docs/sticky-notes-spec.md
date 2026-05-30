# Sticky Notes — file-anchored working memory (v1 spec)

Ref: `mem_01KSX20E` (design direction). Status: v1, build-as-we-go + tune.

## Summary
A **third context layer**: just-in-time, **location-anchored** working notes that
surface **only when the agent reads a file**, **persist across sessions**
(continuity if a session dies mid-task), and must be **resolved** (fixed /
not-relevant), **never ignored**. Built as a **new memory `kind`** on the
**existing rails** — no new storage or sync.

## The gap it fills
- **Always-on** (bedrock + per-turn injection) → loads every turn → context bloat.
- **Semantic recall** (durable memory) → topic-triggered.
- **MISSING → sticky notes**: JIT, location-anchored. v0.22.4 evicted transient
  TASK STATE from durable memory but gave it no home. Sticky notes are that home
  **and** the cross-session continuity layer, costing **zero context until the
  file is touched**.

Layer model: durable memory = *curate & keep*; harness task list = *this-session
todos*; sticky note = *scribble → surface-on-touch → resolve-and-remove*.

## Data model (rides the existing memory record)
- `kind: 'sticky'` — new; add to `KIND_ENUM` (memory-tools.js) + `MEMORY_KINDS`
  (memory-store.js) + the IdP agent-state kind enum.
- `claim` = the note **body**, which carries **STATE not just a reminder**
  (e.g. "left off at the KP purge in this file; root cause line 509; next: live reconcile").
- `anchor` = **NEW content field**: `{ repo_key, rel_path }` — **repo-relative**
  (reuse `projectKeyForPath`) so it is portable to **console** (NOT the agent's
  absolute, machine-specific path).
- `subject` = optional topic tags.
- `status`: `active` (open) → `forgotten` (resolved / ripped). Reuse the existing
  status lifecycle + write-through supersede.
- **stickiness**: *derived* (recency + surface_count), not stored as truth — it
  decays; low stickiness still surfaces, de-emphasized + "still relevant?".
- **EXCLUDED from semantic recall + ambient injection** — surfaces ONLY via the
  path trigger.

## Storage + sync (REUSE — the whole point)
Same rail as durable memory: local `MemoryStore` cache + **LIVE write-through to
`/v1/agent-state`** + **sync-down** (`agent-state-sync.js`). The write-through is
what reaches **console** and survives session loss. **Scope: agent + console.**
**Mobile: deferred** to a later one-shot (info + messaging matter more there first).
IdP must (a) accept `kind:'sticky'` and (b) round-trip the `anchor` field in the
record content through write + sync.

## Surfacing (JIT) — the Read hook
`pre-tool-use.js`, on **Read** (v1): resolve the tool's path → `{repo_key, rel_path}`
→ `store.stickyNotesForAnchor()` → inject **open** notes as `additionalContext`,
ordered by stickiness, with the **resolve-reflex** instruction ("fix it or confirm
not-relevant; never ignore"). Cap N per path; highest stickiness first.

## Tools — all existing MCP (no new tool surface)
- **ADD**: `lastid_memory_write({ kind:'sticky', path:<abs>, claim:<body> })` — the
  write tool gains an optional `path` arg (meaningful only for `kind:'sticky'`,
  resolved to `anchor`).
- **LIST**: `lastid_memory_list({ kinds:['sticky'], path? })`.
- **RESOLVE (rip up)**: `lastid_memory_forget({ id, reason:'fixed'|'not_relevant' })`.
- **PROMOTE**: resolve + `lastid_memory_write` a durable memory (manual).

## Lifecycle
Persist across sessions (synced); **never auto-deleted**. Prominence (stickiness)
**decays** with age/surface_count. **REFLEX** (a guidance line, sibling of the
v0.22.4 curation reflex): a surfaced note must be **resolved** — fixed or
confirmed-not-relevant — **never silently ignored**. Promote-or-rip at resolution.

## v1 scope
IN: new kind; repo-relative `anchor`; write-through + sync (agent+console);
Read-hook surfacing; add-via-write+path / list / resolve-via-forget; decay
prominence; resolve-reflex guidance line.
OUT (later): line/symbol anchoring (drift), Edit/Grep/Glob triggers, console
management UI (basic view is enough), mobile, auto-promote heuristics.

## Build phases
1. **Plugin store**: `sticky` kind, `anchor` field, `stickyNotesForAnchor` lookup,
   exclude from search + ambient. + tests.
2. **Plugin tools + hook**: `path` arg on write; Read-hook surfacing; resolve via
   forget. + tests.
3. **IdP**: accept `kind:'sticky'` + ensure `anchor` round-trips in agent-state
   content + sync. + tests.
4. **Console** (later): render + resolve sticky notes.
5. **Guidance**: add a sticky-note reflex line to `memory-guidance.js`.

## Test plan
store: write/list/resolve a sticky; excluded from search + ambient;
`stickyNotesForAnchor` matches by repo-relative anchor; decay ordering.
hook: Read surfaces path notes; nothing for an unanchored path.
IdP: `kind:'sticky'` accepted; `anchor` round-trips through write-through + sync.

## Open gut-checks (non-blocking — proceeding with these unless redirected)
- `anchor` as a dedicated content field vs a subject tag → **chose: dedicated field, repo-relative** (portable to console; clean).
- reuse `memory_write/list/forget` vs thin `sticky_*` tools → **chose: reuse + a `path` arg** (matches "all through MCP, just a new type").
