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
  read: 'file_read',
  write: 'file_write',
  edit: 'file_edit',
  multiedit: 'file_edit',
  notebookedit: 'notebook',
  notebookread: 'notebook',
  grep: 'search',
  glob: 'search',
  ls: 'search',
  webfetch: 'web_fetch',
  websearch: 'web_search',
  task: 'subagent',
  todowrite: 'plan',
};

// Codex (OpenAI) literal tool name -> canonical. Filled from research
// (search-specialist) — kept here as the single cross-runtime source of
// truth even though THIS plugin runs under Claude Code; the Codex
// integration's pre-tool hook reuses this map. Refined per the research
// findings.
const CODEX_TOOL_MAP = {
  shell: 'shell',
  local_shell: 'shell',
  exec: 'shell',
  apply_patch: 'file_edit',
  update_plan: 'plan',
  web_search: 'web_search',
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
