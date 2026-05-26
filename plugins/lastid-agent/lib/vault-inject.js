/**
 * Credential injection — the 4 kinds, ported from the desktop's
 * http_fetch_tool.dart `_applyInjection`. PURE: given an injection spec, the
 * secret, and the outbound request shape, return the request with the
 * credential attached. No I/O, no decryption — the caller (the listener) has
 * already unfurled the secret and calls this at the last moment before the
 * fetch. Keeping it pure means the one place plaintext meets the request is
 * unit-tested in isolation.
 *
 *   header        headers[name] = format.replace('{value}', secret)
 *   oauth_bearer  same template path (token refresh handled by the caller)
 *   query_param   url ?name = format.replace('{value}', secret)
 *   basic_auth    Authorization: Basic base64(username:secret)
 *                 username from item[username_field]
 */

const VALUE = "{value}";

function fillTemplate(format, secret) {
  const f = typeof format === "string" && format.length > 0 ? format : VALUE;
  return f.split(VALUE).join(secret);
}

/**
 * Apply `injection` to a request. Returns a NEW { url, headers } — never
 * mutates the inputs. `item` supplies the basic_auth username via
 * `injection.username_field`. Throws on a spec that can't attach (missing
 * name / username) so a misconfigured share fails loud, not silently
 * un-credentialed.
 *
 * @param {object}   a
 * @param {object}   a.injection  { type, name?, format?, username_field? }
 * @param {string}   a.secret     the unfurled credential value
 * @param {string}   a.url        outbound URL
 * @param {object}   [a.headers]  outbound headers (case-insensitive intent)
 * @param {object}   [a.item]     the decoded share bundle (for username_field)
 * @returns {{ url: string, headers: Record<string,string> }}
 */
export function applyInjection({ injection, secret, url, headers = {}, item = {} }) {
  if (!injection || typeof injection.type !== "string") {
    throw new Error("injection spec missing type");
  }
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("injection has no secret to attach");
  }
  const out = { url: String(url ?? ""), headers: { ...headers } };

  switch (injection.type) {
    case "header":
    case "oauth_bearer": {
      const name = injection.name?.trim();
      if (!name) throw new Error(`${injection.type} injection needs a header name`);
      out.headers[name] = fillTemplate(injection.format, secret);
      return out;
    }
    case "query_param": {
      const name = injection.name?.trim();
      if (!name) throw new Error("query_param injection needs a param name");
      const u = new URL(out.url);
      u.searchParams.set(name, fillTemplate(injection.format, secret));
      out.url = u.toString();
      return out;
    }
    case "basic_auth": {
      const field = injection.username_field?.trim();
      if (!field) throw new Error("basic_auth injection needs a username_field");
      const username = typeof item?.[field] === "string" ? item[field] : "";
      if (!username) throw new Error(`basic_auth username_field '${field}' is empty on the item`);
      const token = Buffer.from(`${username}:${secret}`, "utf-8").toString("base64");
      out.headers["Authorization"] = `Basic ${token}`;
      return out;
    }
    default:
      throw new Error(`unknown injection type: ${injection.type}`);
  }
}

/**
 * The injection SUMMARY returned to the agent (no secret) — so the model knows
 * HOW the credential will attach (to avoid setting a conflicting header) but
 * never sees the value. Mirrors the desktop's `summariseInjection`.
 */
export function injectionSummary(injection) {
  if (!injection || typeof injection.type !== "string") return null;
  const s = { type: injection.type };
  if (injection.name) s.name = injection.name;
  if (injection.format) s.format = injection.format;
  if (injection.username_field) s.username_field = injection.username_field;
  return s;
}
