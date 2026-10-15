/**
 * Base64 and base64url over bytes, without `atob`/`btoa`: Hermes has had those
 * only since React Native 0.74, and they work on Latin-1 strings, not bytes.
 *
 * Decoding is strict. JWS segments are produced by encoders that never emit
 * padding, foreign characters, or non-zero trailing bits; accepting them is
 * what let alternative encodings of one signature verify in jsrsasign
 * (GHSA-3fvg-4v2m-98jf). See memory_bank/domain/token-model.md#base64url.
 */

const STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_SAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function lookupTable(alphabet: string): Int16Array {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) {
    table[alphabet.charCodeAt(i)] = i;
  }
  return table;
}

const STANDARD_LOOKUP = lookupTable(STANDARD);
const URL_SAFE_LOOKUP = lookupTable(URL_SAFE);

function encodeUrlSafe(bytes: Uint8Array): string {
  const a = URL_SAFE;
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += a[(n >> 18) & 63]! + a[(n >> 12) & 63]! + a[(n >> 6) & 63]! + a[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += a[(n >> 18) & 63]! + a[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += a[(n >> 18) & 63]! + a[(n >> 12) & 63]! + a[(n >> 6) & 63]!;
  }
  return out;
}

/** Returns null for any input that is not the canonical encoding of some bytes. */
function decode(text: string, lookup: Int16Array): Uint8Array | null {
  if (text.length % 4 === 1) {
    return null;
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? (lookup[code] as number) : -1;
    if (value < 0) {
      return null;
    }
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >> bits) & 0xff;
    }
  }
  // Leftover bits must be zero, or two different strings would decode to the
  // same bytes.
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    return null;
  }
  return out.subarray(0, o);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return encodeUrlSafe(bytes);
}

/** Strict: no padding, no `+` or `/`, no whitespace, zero trailing bits. */
export function base64UrlDecode(text: string): Uint8Array | null {
  return decode(text, URL_SAFE_LOOKUP);
}

/** Standard alphabet with `=` padding, as in PEM bodies once line breaks are removed. */
export function base64Decode(text: string): Uint8Array | null {
  if (text.length % 4 !== 0) {
    return null;
  }
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  return decode(text.slice(0, text.length - padding), STANDARD_LOOKUP);
}
