/**
 * Decode the payload of an SD-JWT VC compact string.
 *
 * Input format: `<header>.<payload>.<signature>~<disclosure>~<disclosure>...`
 * We only need the payload's claims, so we ignore everything past the
 * first `~` and the signature segment.
 *
 * Returns the parsed claims object, or null when the input isn't a
 * recognisable JWT (no agent VC present, malformed string, etc.).
 */
export function decodeVcClaims(vcCompact) {
  if (!vcCompact || typeof vcCompact !== 'string') return null;
  const parts = vcCompact.split('~')[0]?.split('.');
  if (!parts || parts.length < 2) return null;
  try {
    return JSON.parse(
      Buffer.from(
        parts[1].replace(/-/g, '+').replace(/_/g, '/'),
        'base64',
      ).toString('utf-8'),
    );
  } catch {
    return null;
  }
}

/**
 * True iff the VC claims grant `action` on `resource`.
 *
 * Capability shape (matches `lastid_whoami` output and the IdP's
 * issued VC):
 *   { resource: "message:send", actions: ["Send"], constraints: [] }
 *
 * Matching is exact on both resource and action — no wildcards, no
 * substring matches. An agent that wasn't issued the capability is
 * refused, full stop. This is the authoritative gate; the LLM does
 * not get to decide whether it "has" a capability.
 */
export function hasCapability(claims, resource, action) {
  const caps = Array.isArray(claims?.capabilities) ? claims.capabilities : [];
  return caps.some(
    (c) =>
      c &&
      c.resource === resource &&
      Array.isArray(c.actions) &&
      c.actions.includes(action),
  );
}
