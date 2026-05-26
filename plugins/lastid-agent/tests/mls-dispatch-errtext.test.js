/**
 * errText (lib/mls-dispatch.js) — the MLS wasm rejects with a JsValue/string,
 * not a JS Error, so the old `${err.message}` logged `undefined` and hid every
 * processWelcome/processInbound failure. These lock that a thrown value of any
 * shape yields informative text (never "undefined").
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { errText } from '../lib/mls-dispatch.js';

test('errText: a thrown string (the wasm shape) is returned verbatim', () => {
  assert.equal(errText('WrongEpoch'), 'WrongEpoch');
  assert.equal(errText('CannotDecryptOwnMessage'), 'CannotDecryptOwnMessage');
});

test('errText: a real Error returns message (+stack when present)', () => {
  const e = new Error('boom');
  assert.match(errText(e), /boom/);
});

test('errText: an object without .message serializes to JSON, not "undefined"', () => {
  assert.equal(errText({ code: 'NoMatchingKeyPackage', epoch: 7 }), '{"code":"NoMatchingKeyPackage","epoch":7}');
});

test('errText: an object WITH a string .message uses it', () => {
  assert.equal(errText({ message: 'welcome rejected' }), 'welcome rejected');
});

test('errText: never returns the literal "undefined" for a non-Error throw', () => {
  for (const v of ['x', { a: 1 }, 0, false, { message: 'm' }]) {
    assert.notEqual(errText(v), 'undefined', `errText(${JSON.stringify(v)}) must be informative`);
  }
  // A genuinely null/undefined throw is the one honest "undefined".
  assert.equal(errText(undefined), 'undefined');
  assert.equal(errText(null), 'null');
});
