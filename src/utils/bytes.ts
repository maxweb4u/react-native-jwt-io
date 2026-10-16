import { JwtKeyError } from '../errors/errors';

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
    throw new JwtKeyError('hexToBytes expects an even-length string of hexadecimal digits.');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * Big-endian bytes to a BigInt, through one hex string: linear, where
 * shifting in a byte at a time is quadratic — half a second for a 48 KB field
 * in a hostile JWK, before any size check could run.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '';
  for (const byte of bytes) {
    hex += (byte < 16 ? '0' : '') + byte.toString(16);
  }
  return hex === '' ? BigInt(0) : BigInt(`0x${hex}`);
}

/** The length of `bytes` without its leading zero bytes. */
export function significantLength(bytes: Uint8Array): number {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  return bytes.length - start;
}

export function bitLength(value: bigint): number {
  return value === BigInt(0) ? 0 : value.toString(2).length;
}
