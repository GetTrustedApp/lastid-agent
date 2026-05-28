/**
 * Reaction emoji ↔ wire-name table (lib/reactions.js). The wire name is the
 * snake_case ReactionType from the Rust SDK; clients render it back to the
 * emoji. These tests pin the core 6 (the app quick-bar), the both-hearts case,
 * and that unknown input is rejected (never sent as a bad reaction).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  reactionWireName,
  isSupportedReaction,
  CORE_REACTIONS,
  CORE_REACTION_EMOJIS,
  REACTION_WIRE,
} from '../lib/reactions.js';

test('core 6 map to their SDK wire names', () => {
  assert.equal(reactionWireName('👍'), 'thumbs_up');
  assert.equal(reactionWireName('❤️'), 'heart');
  assert.equal(reactionWireName('😂'), 'laugh');
  assert.equal(reactionWireName('😮'), 'wow');
  assert.equal(reactionWireName('😢'), 'sad');
  assert.equal(reactionWireName('🙏'), 'pray');
});

test('both ❤️ (with VS16) and ❤ (bare) resolve to heart', () => {
  assert.equal(reactionWireName('❤️'), 'heart');
  assert.equal(reactionWireName('❤'), 'heart');
});

test('an extended emoji still maps (faithful to the full ReactionType set)', () => {
  assert.equal(reactionWireName('🎉'), 'party');
  assert.equal(reactionWireName('🔥'), 'fire');
  assert.equal(reactionWireName('✅'), 'check');
});

test('NEGATIVE: unsupported / empty / non-string → null, not a guessed reaction', () => {
  assert.equal(reactionWireName('🍕'), null);
  assert.equal(reactionWireName(''), null);
  assert.equal(reactionWireName('thumbs_up'), null); // the NAME is not an emoji input
  assert.equal(reactionWireName(null), null);
  assert.equal(reactionWireName(42), null);
  assert.equal(isSupportedReaction('🍕'), false);
  assert.equal(isSupportedReaction('👍'), true);
});

test('CORE_REACTION_EMOJIS is the 6-emoji tool enum, each with a wire mapping', () => {
  assert.equal(CORE_REACTION_EMOJIS.length, 6);
  for (const emoji of CORE_REACTION_EMOJIS) {
    assert.ok(reactionWireName(emoji), `${emoji} maps to a wire name`);
  }
  // CORE_REACTIONS carries an intent for each, and its wire matches the table.
  for (const r of CORE_REACTIONS) {
    assert.equal(reactionWireName(r.emoji), r.wire);
    assert.ok(typeof r.intent === 'string' && r.intent.length > 0);
  }
});

test('every wire name is unique-per-emoji and snake_case', () => {
  for (const [emoji, wire] of REACTION_WIRE) {
    assert.match(wire, /^[a-z_]+$/, `${emoji} → ${wire} is snake_case`);
  }
});
