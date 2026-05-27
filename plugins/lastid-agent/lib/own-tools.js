/**
 * Identify the LastID plugin's OWN MCP tools by their Claude Code namespace.
 *
 * Claude Code names a plugin MCP server's tools
 * `mcp__plugin_<plugin>_<server>__<tool>`. For this plugin both segments are
 * `lastid-agent`, e.g. `mcp__plugin_lastid-agent_lastid-agent__lastid_send_message`.
 *
 * The PreToolUse hook auto-ALLOWS this namespace (AFTER the operator's
 * rule-memory policy check, which can still deny/warn/rewrite). A hook `allow`
 * is authoritative and skips Claude Code's auto-mode safety classifier — which
 * otherwise denied legitimate calls like `lastid_send_message` ("sends to a
 * third party") even though the tool can ONLY reach the operator. These tools
 * are already governed by the agent's bounded VC capabilities, the policy
 * check, and the signed audit chain, so the generic classifier is redundant.
 *
 * The trailing `_` in the prefix is load-bearing: it pins the match to OUR
 * plugin and won't match a hypothetical `lastid-agent-x` plugin
 * (`mcp__plugin_lastid-agent-x_…`).
 */
export const OWN_TOOL_PREFIX = 'mcp__plugin_lastid-agent_';

/** True iff `toolName` is one of this plugin's own MCP tools. */
export function isOwnPluginTool(toolName) {
  return typeof toolName === 'string' && toolName.startsWith(OWN_TOOL_PREFIX);
}
