/**
 * `isOwnPluginTool` decides which tool names the PreToolUse hook auto-ALLOWS
 * (a hook allow skips Claude Code's auto-mode safety classifier). It must match
 * EVERY tool this plugin's MCP server exposes and NOTHING else — the classifier
 * must keep gating built-ins and other plugins. The trailing `_` in the prefix
 * pins it to our plugin name so a `lastid-agent-x` plugin can't slip through.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isOwnPluginTool, OWN_TOOL_PREFIX } from '../lib/own-tools.js';

test('allows every one of our own plugin MCP tools', () => {
  for (const t of [
    'mcp__plugin_lastid-agent_lastid-agent__lastid_send_message',
    'mcp__plugin_lastid-agent_lastid-agent__vault_use',
    'mcp__plugin_lastid-agent_lastid-agent__vault_list',
    'mcp__plugin_lastid-agent_lastid-agent__http_fetch',
    'mcp__plugin_lastid-agent_lastid-agent__lastid_memory_write',
    'mcp__plugin_lastid-agent_lastid-agent__lastid_whoami',
  ]) {
    assert.equal(isOwnPluginTool(t), true, t);
  }
});

test('does NOT match Claude Code built-in tools', () => {
  for (const t of ['Bash', 'Read', 'Write', 'Edit', 'Task', 'NotebookEdit', '']) {
    assert.equal(isOwnPluginTool(t), false, t);
  }
});

test('does NOT match other plugins or look-alike names', () => {
  // A different plugin entirely.
  assert.equal(isOwnPluginTool('mcp__plugin_other_other__do_thing'), false);
  // Boundary: a plugin whose name STARTS with "lastid-agent" must not match —
  // the trailing underscore in the prefix is what guards this.
  assert.equal(isOwnPluginTool('mcp__plugin_lastid-agent-x_srv__tool'), false);
  // A bare (non-plugin) MCP server tool.
  assert.equal(isOwnPluginTool('mcp__somesrv__tool'), false);
});

test('tolerates non-string input', () => {
  assert.equal(isOwnPluginTool(undefined), false);
  assert.equal(isOwnPluginTool(null), false);
  assert.equal(isOwnPluginTool(123), false);
  assert.equal(isOwnPluginTool({}), false);
});

test('prefix is the documented namespace', () => {
  assert.equal(OWN_TOOL_PREFIX, 'mcp__plugin_lastid-agent_');
});
