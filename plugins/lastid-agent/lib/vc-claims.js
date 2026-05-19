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
