/**
 * Credential injection (lib/vault-inject.js) — the one place the unfurled
 * secret meets the outbound request. Locks each of the 4 kinds, that inputs
 * aren't mutated, and that a spec which can't attach throws (rather than
 * silently sending an un-credentialed request).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { applyInjection, injectionSummary } from "../lib/vault-inject.js";

test("header: fills {value} into the named header, leaves url + other headers alone", () => {
  const headers = { Accept: "application/json" };
  const out = applyInjection({
    injection: { type: "header", name: "Authorization", format: "Bearer {value}" },
    secret: "sk-123",
    url: "https://api.openai.com/v1/models",
    headers,
  });
  assert.equal(out.headers.Authorization, "Bearer sk-123");
  assert.equal(out.headers.Accept, "application/json");
  assert.equal(out.url, "https://api.openai.com/v1/models");
  assert.equal(headers.Authorization, undefined, "input headers not mutated");
});

test("header with no format defaults to the bare value", () => {
  const out = applyInjection({
    injection: { type: "header", name: "X-Api-Key" },
    secret: "raw-key",
    url: "https://x",
  });
  assert.equal(out.headers["X-Api-Key"], "raw-key");
});

test("oauth_bearer uses the same template path", () => {
  const out = applyInjection({
    injection: { type: "oauth_bearer", name: "Authorization", format: "Bearer {value}" },
    secret: "tok",
    url: "https://x",
  });
  assert.equal(out.headers.Authorization, "Bearer tok");
});

test("query_param sets the param on the url", () => {
  const out = applyInjection({
    injection: { type: "query_param", name: "api_key" },
    secret: "qsecret",
    url: "https://api.example.com/data?page=2",
  });
  const u = new URL(out.url);
  assert.equal(u.searchParams.get("api_key"), "qsecret");
  assert.equal(u.searchParams.get("page"), "2");
});

test("basic_auth base64s username:secret from the item's username_field", () => {
  const out = applyInjection({
    injection: { type: "basic_auth", username_field: "account" },
    secret: "pw",
    url: "https://x",
    item: { account: "alice" },
  });
  assert.equal(out.headers.Authorization, `Basic ${Buffer.from("alice:pw").toString("base64")}`);
});

test("throws when a spec can't attach (no name / no username / no secret)", () => {
  assert.throws(() => applyInjection({ injection: { type: "header" }, secret: "s", url: "https://x" }), /header name/);
  assert.throws(() => applyInjection({ injection: { type: "query_param" }, secret: "s", url: "https://x" }), /param name/);
  assert.throws(
    () => applyInjection({ injection: { type: "basic_auth" }, secret: "s", url: "https://x" }),
    /username_field/,
  );
  assert.throws(
    () => applyInjection({ injection: { type: "basic_auth", username_field: "account" }, secret: "s", url: "https://x", item: {} }),
    /empty/,
  );
  assert.throws(() => applyInjection({ injection: { type: "header", name: "A" }, secret: "", url: "https://x" }), /no secret/);
  assert.throws(() => applyInjection({ injection: { type: "nope", name: "A" }, secret: "s", url: "https://x" }), /unknown injection/);
});

test("injectionSummary carries shape, never a secret slot", () => {
  assert.deepEqual(injectionSummary({ type: "header", name: "Authorization", format: "Bearer {value}" }), {
    type: "header",
    name: "Authorization",
    format: "Bearer {value}",
  });
  assert.equal(injectionSummary(null), null);
});
