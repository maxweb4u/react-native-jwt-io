export function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Compares in time that depends only on the lengths, so an HMAC check leaks nothing about the expected tag. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/**
 * Hex to bytes. Exported for callers migrating from 1.x, where a secret that
 * looked like hex was used as hex: `verify(token, hexToBytes('deadbeef'))`
 * reproduces those signatures.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new TypeError('hexToBytes expects an even-length string of hexadecimal digits.');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = BigInt(0);
  for (const byte of bytes) {
    value = (value << BigInt(8)) | BigInt(byte);
  }
  return value;
}

export function bitLength(value: bigint): number {
  return value === BigInt(0) ? 0 : value.toString(2).length;
}
