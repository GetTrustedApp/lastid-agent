/**
 * Reaction emoji ↔ wire-name table — the single source of truth for the agent
 * reaction path, mirroring the Rust SDK's `ReactionType`
 * (lastid-sdk/lastid-core/src/types/messaging.rs). The IdP relays a
 * `group_chat.reaction` whose `reaction` field is the snake_case NAME
 * (`thumbs_up`, `heart`, …), NOT the raw emoji — clients render it back to the
 * emoji via the same enum. So the agent picks an emoji; we map it to the wire
 * name here, exactly as the native apps do (manager.rs `send_group_reaction`
 * uses `ReactionType::from_emoji(emoji).as_str()`).
 *
 * The full 24-variant map keeps us faithful to the SDK (any emoji the apps
 * accept also works from the agent), while CORE_REACTION_EMOJIS is the curated
 * 6 the app surfaces in its quick-reaction bar (allowedReactionEmojis in
 * packages/lastid_models) — what the agent tool advertises.
 */

/**
 * emoji → wire name. Mirrors ReactionType's `#[serde(rename_all="snake_case")]`
 * + `from_emoji`. Both ❤️ (with VS16) and ❤ (bare) map to `heart`, matching the
 * Rust `from_emoji` which accepts either.
 */
export const REACTION_WIRE = new Map([
  // Core (the app quick-reaction bar)
  ['\u{1F44D}', 'thumbs_up'], // 👍
  ['❤️', 'heart'], // ❤️ (with variation selector)
  ['❤', 'heart'], // ❤ (bare)
  ['\u{1F602}', 'laugh'], // 😂
  ['\u{1F62E}', 'wow'], // 😮
  ['\u{1F622}', 'sad'], // 😢
  ['\u{1F64F}', 'pray'], // 🙏
  // Extended
  ['\u{1F44F}', 'clap'], // 👏
  ['\u{1F389}', 'party'], // 🎉
  ['\u{1F525}', 'fire'], // 🔥
  ['\u{1F4AF}', 'hundred'], // 💯
  ['✨', 'sparkles'], // ✨
  ['\u{1F4AA}', 'muscle'], // 💪
  ['\u{1F60A}', 'smile'], // 😊
  ['\u{1F970}', 'love'], // 🥰
  ['\u{1F60E}', 'cool'], // 😎
  ['\u{1F914}', 'think'], // 🤔
  ['\u{1F605}', 'sweat'], // 😅
  ['\u{1F644}', 'roll_eyes'], // 🙄
  ['\u{1F440}', 'eyes'], // 👀
  ['\u{1F91D}', 'handshake'], // 🤝
  ['✅', 'check'], // ✅
  ['❌', 'cross'], // ❌
  ['\u{1F4A1}', 'bulb'], // 💡
  ['⭐', 'star'], // ⭐
]);

/**
 * The 6 core reactions, in the app's quick-bar order — the set the agent tool
 * advertises. Each paired with the intent it reads as, so the tool description
 * (and the agent) map a situation to an emoji.
 */
export const CORE_REACTIONS = [
  { emoji: '\u{1F44D}', wire: 'thumbs_up', intent: 'acknowledge / agree / done' },
  { emoji: '❤️', wire: 'heart', intent: 'love it / strong agreement / thanks' },
  { emoji: '\u{1F602}', wire: 'laugh', intent: 'that was funny' },
  { emoji: '\u{1F62E}', wire: 'wow', intent: 'surprised / unexpected' },
  { emoji: '\u{1F622}', wire: 'sad', intent: "found a bug / that's broken / oh no" },
  { emoji: '\u{1F64F}', wire: 'pray', intent: 'thank you / please / fingers crossed' },
];

/** The bare core emoji list (for the tool input enum). */
export const CORE_REACTION_EMOJIS = CORE_REACTIONS.map((r) => r.emoji);

/**
 * Map an emoji to its wire name, or null if it isn't a supported reaction.
 * Normalizes a trailing VS16 (U+FE0F) so a heart with or without it resolves.
 */
export function reactionWireName(emoji) {
  if (typeof emoji !== 'string' || emoji.length === 0) return null;
  if (REACTION_WIRE.has(emoji)) return REACTION_WIRE.get(emoji);
  // Tolerate a stray variation selector the caller's keyboard may add/drop.
  const stripped = emoji.replace(/️/g, '');
  return REACTION_WIRE.get(stripped) ?? null;
}

/** Is this emoji a reaction the SDK/clients can render? */
export function isSupportedReaction(emoji) {
  return reactionWireName(emoji) !== null;
}
