import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { base64UrlDecodeCanonical, base64UrlEncode } from "./encoding.js";

// Node's Buffer is the reference: the portable codec must encode identically
// and accept exactly the strings that survive a Buffer decode/encode round trip.
const nodeCanonical = (value: string): Uint8Array | undefined => {
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? new Uint8Array(bytes) : undefined;
};

test("base64url encoding matches Buffer for every length and byte value", () => {
  for (let length = 0; length <= 96; length++) {
    for (let round = 0; round < 8; round++) {
      const bytes = new Uint8Array(randomBytes(length));
      const encoded = base64UrlEncode(bytes);
      assert.equal(encoded, Buffer.from(bytes).toString("base64url"));
      assert.deepEqual(base64UrlDecodeCanonical(encoded), bytes);
    }
  }
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.equal(base64UrlEncode(all), Buffer.from(all).toString("base64url"));
});

test("canonical base64url decoding accepts exactly Buffer's round-trip set", () => {
  const chars = [
    ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    ..."+/= .\né",
  ];
  const check = (value: string) =>
    assert.deepEqual(base64UrlDecodeCanonical(value), nodeCanonical(value), value);
  check("");
  for (const a of chars) {
    check(a);
    for (const b of chars) {
      check(a + b);
      for (const c of chars) check(a + b + c);
    }
  }
  for (const value of ["AAAA", "AAA=", "AA==", "AB", "AAB", "-_-_", "+/+/", "QUJD\n"])
    check(value);
});
