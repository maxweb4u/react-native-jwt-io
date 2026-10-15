/**
 * UTF-8 without `TextEncoder`/`TextDecoder`: Hermes has no `TextDecoder`, and
 * older versions have no `TextEncoder` either.
 */

export function utf8Encode(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i++;
      }
    }
    // A lone surrogate becomes U+FFFD, as TextEncoder does.
    if (code >= 0xd800 && code <= 0xdfff) {
      code = 0xfffd;
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    } else {
      out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    }
  }
  return Uint8Array.from(out);
}

/** Returns null for invalid UTF-8: overlong forms, surrogates, truncated sequences, code points above U+10FFFF. */
export function utf8Decode(bytes: Uint8Array): string | null {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i] as number;
    let code: number;
    let extra: number;
    let min: number;
    if (b0 < 0x80) {
      code = b0;
      extra = 0;
      min = 0;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      code = b0 & 0x1f;
      extra = 1;
      min = 0x80;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      code = b0 & 0x0f;
      extra = 2;
      min = 0x800;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      code = b0 & 0x07;
      extra = 3;
      min = 0x10000;
    } else {
      return null;
    }
    for (let k = 1; k <= extra; k++) {
      const b = bytes[i + k];
      if (b === undefined || (b & 0xc0) !== 0x80) {
        return null;
      }
      code = (code << 6) | (b & 0x3f);
    }
    if (code < min || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
      return null;
    }
    out += code >= 0x10000
      ? String.fromCharCode(0xd800 + ((code - 0x10000) >> 10), 0xdc00 + ((code - 0x10000) & 0x3ff))
      : String.fromCharCode(code);
    i += extra + 1;
  }
  return out;
}
