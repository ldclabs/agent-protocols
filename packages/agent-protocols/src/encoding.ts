/**
 * Portable base64url (RFC 4648 Section 5, no padding). The SDK avoids Node's
 * `Buffer` and `node:crypto` so the same build runs in Node, browsers and
 * Cloudflare Workers.
 */
const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DECODE = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) DECODE[ALPHABET.charCodeAt(i)] = i;

export function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    // 1, 2 or 3 remaining bytes encode to 2, 3 or 4 characters.
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 4) / 3));
    for (let j = 0; j < chars; j++) out += ALPHABET[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}

/**
 * Decodes canonical base64url: URL-safe alphabet, no padding and zero trailing
 * bits. Any other string returns undefined, so each byte string has exactly one
 * accepted text form.
 */
export function base64UrlDecodeCanonical(value: string): Uint8Array | undefined {
  if (value.length % 4 === 1) return undefined;
  const bytes = new Uint8Array(Math.floor((value.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const digit = code < 128 ? DECODE[code] : -1;
    if (digit < 0) return undefined;
    buffer = ((buffer << 6) | digit) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = (buffer >> bits) & 0xff;
    }
  }
  return (buffer & ((1 << bits) - 1)) === 0 ? bytes : undefined;
}
