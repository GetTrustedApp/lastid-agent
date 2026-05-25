/**
 * Canonical tool taxonomy + cross-runtime normalization.
 *
 * Operators author rules against CANONICAL tool categories (a dropdown
 * in the browser), not a specific runtime's literal tool name. So one
 * rule — "deny shell `git stash`" — matches Claude Code's `Bash`, a
 * Codex `shell`, `sh`, etc., instead of breaking on a name mismatch
 * (`Bash` vs `bash` vs `sh`). At enforcement time the agent normalizes
 * the runtime's reported tool name to a canonical category and matches
 * the rule against that.
 *
 * The canonical values here are the contract shared with the browser
 * authoring UI (lastid.co) and any future runtime integration (Codex).
 */

// Stable canonical categories. '' means "any tool" (a tool-agnostic rule).
export const CANONICAL_TOOLS = [
  'shell', // run a command / terminal
  'file_read', // read a file
  'file_write', // create / overwrite a file
  'file_edit', // modify an existing file
  'search', // grep / glob / find
  'web_fetch', // fetch a URL
  'web_search', // search the web
  'subagent', // spawn a sub-agent / task
  'notebook', // edit a notebook
  'plan', // todo / plan updates
  'mcp', // any MCP server tool
];

// Claude Code (this plugin's runtime) literal tool name -> canonical.
// Keys are lowercased; lookups lowercase the incoming name.
const CLAUDE_TOOL_MAP = {
  bash: 'shell',
  powershell: 'shell',
  read: 'file_read', // also handles images / PDF / notebooks
  write: 'file_write',
  edit: 'file_edit',
  multiedit: 'file_edit', // removed in current Claude Code; harmless alias
  notebookedit: 'notebook',
  grep: 'search',
  glob: 'search',
  webfetch: 'web_fetch',
  websearch: 'web_search',
  agent: 'subagent', // the subagent-spawning tool is `Agent` (NOT `Task`)
  task: 'subagent', // legacy alias for older builds
  todowrite: 'plan',
  taskcreate: 'plan',
  taskupdate: 'plan',
  tasklist: 'plan',
  taskget: 'plan',
  taskstop: 'plan',
  enterplanmode: 'plan',
  exitplanmode: 'plan',
};

// Codex (OpenAI) literal tool name -> canonical, verified against the
// openai/codex source (codex-rs tool specs). Kept here as the single
// cross-runtime source of truth even though THIS plugin runs under Claude
// Code; the future Codex integration's pre-tool hook reuses this map.
//
// Caveats baked into the mapping:
//  - Codex exposes several exec tool names across model families
//    (shell / shell_command / exec_command / write_stdin / unified_exec);
//    all are the `shell` category.
//  - `apply_patch` is a 3-in-1 (Add/Update/Delete via a freeform patch);
//    mapped to file_edit as the dominant case. Codex also frequently runs
//    file ops (cat/grep/even apply_patch) THROUGH the shell, so a `shell`
//    rule catches a lot that a file_* rule would miss on Codex.
//  - view_image / request_permissions / tool_search have no canonical
//    category and fall through unmapped.
const CODEX_TOOL_MAP = {
  shell: 'shell',
  shell_command: 'shell',
  exec_command: 'shell',
  write_stdin: 'shell',
  unified_exec: 'shell',
  local_shell: 'shell',
  read_file: 'file_read',
  apply_patch: 'file_edit',
  update_plan: 'plan',
  get_goal: 'plan',
  create_goal: 'plan',
  update_goal: 'plan',
  web_search: 'web_search',
  spawn_agent: 'subagent',
  spawn_agents_on_csv: 'subagent',
};

/**
 * Normalize a runtime tool name to a canonical category. MCP tools
 * (`mcp__server__tool`) collapse to `mcp`. Unknown names fall through
 * lowercased so an operator could still target a literal name if needed.
 */
export function canonicalTool(runtimeToolName) {
  if (!runtimeToolName || typeof runtimeToolName !== 'string') return '';
  const t = runtimeToolName.trim();
  if (!t) return '';
  if (t.startsWith('mcp__')) return 'mcp';
  const lower = t.toLowerCase();
  return CLAUDE_TOOL_MAP[lower] ?? CODEX_TOOL_MAP[lower] ?? lower;
}
