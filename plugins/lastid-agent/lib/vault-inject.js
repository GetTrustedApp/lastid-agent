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
 * Build the ENV-VAR injection for a CLI run (vault injection kind 'env'). Returns
 * { env: { NAME: value } } — a process-env map, NOT the { url, headers } shape
 * applyInjection returns, because this attaches at a different boundary: a child
 * process, not an outbound request. Reads `injection.env_map`, an array of
 * { name, field: 'secret' | 'secret_secondary', format? }. PURE: the listener
 * has already unfurled secret/secret_secondary; this only maps fields → var
 * names. Throws on an unusable spec so a misconfigured share fails loud, not
 * silently un-credentialed. (Array, not a map object, so it round-trips through
 * the operator-signed canonical ACL byte-for-byte — key order isn't stable.)
 *
 * @param {object} a
 * @param {object} a.injection         { type:'env', env_map: [{name, field, format?}] }
 * @param {string} a.secret            primary unfurled credential
 * @param {string} [a.secret_secondary] companion (e.g. AWS secret access key)
 * @returns {{ env: Record<string,string> }}
 */
export function buildEnvInjection({ injection, secret, secret_secondary }) {
  if (!injection || injection.type !== "env") {
    throw new Error("not an env injection");
  }
  const map = Array.isArray(injection.env_map) ? injection.env_map : [];
  if (map.length === 0) throw new Error("env injection has no env_map");
  const env = {};
  for (const entry of map) {
    const name = typeof entry?.name === "string" ? entry.name.trim() : "";
    if (!name) throw new Error("env injection entry needs a name");
    const field = entry.field === "secret_secondary" ? "secret_secondary" : "secret";
    const value = field === "secret_secondary" ? secret_secondary : secret;
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`env injection field '${field}' is empty on the item`);
    }
    env[name] = fillTemplate(entry.format, value);
  }
  return { env };
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
  // For env (the CLI proxy): tell the agent WHICH env vars get set, names only —
  // never the field mapping or the values.
  if (injection.type === "env" && Array.isArray(injection.env_map)) {
    s.env_vars = injection.env_map.map((e) => e?.name).filter(Boolean);
  }
  return s;
}
