import { JwtHostRequirementError } from '../errors/errors';
import { bitLength, bytesToBigInt, equalBytes, isBytes } from '../utils/bytes';

type RandomValues = (array: Uint8Array) => unknown;

/** A throwing `crypto` or `getRandomValues` getter counts as none. */
function randomValues(): RandomValues | undefined {
  try {
    const crypto = (globalThis as { crypto?: { getRandomValues?: unknown } }).crypto;
    const fill = crypto?.getRandomValues;
    return typeof fill === 'function' ? (array) => (fill as RandomValues).call(crypto, array) : undefined;
  } catch {
    return undefined;
  }
}

// Draws a real source fails all of with a chance under 2^-32 when the
// modulus is given: each falls in (1, n) with a chance of at least a half.
const MAX_DRAWS = 32;

/**
 * Whether the host's `crypto.getRandomValues` works: it exists, does not
 * throw, and returns (noble uses what it returns, not the array it passed)
 * a Uint8Array of the length asked for, with bytes that differ between
 * draws and are not all zero. Given an RSA modulus, it must also yield a
 * number in (1, n) the way micro-rsa-dsa-dh draws its blinding factor —
 * that draw is a loop with no bound. Asked before each use: a broken
 * polyfill or test mock — one that returns nothing, the same bytes or a
 * counter — would otherwise make blinding loop forever, or fail with an
 * error that blames the key. A source that changes its behaviour after the
 * probe is beyond it.
 */
export function randomSourceWorks(modulus?: bigint): boolean {
  const fill = randomValues();
  if (fill === undefined) {
    return false;
  }
  const bits = modulus === undefined ? 256 : bitLength(modulus);
  const length = Math.ceil(bits / 8);
  const mask = (BigInt(1) << BigInt(bits)) - BigInt(1);
  try {
    let previous: Uint8Array | undefined;
    for (let draw = 0; draw < MAX_DRAWS; draw++) {
      const bytes = fill(new Uint8Array(length));
      if (!isBytes(bytes) || bytes.length !== length || !bytes.some((byte) => byte !== 0)) {
        return false;
      }
      if (previous !== undefined && equalBytes(previous, bytes)) {
        return false;
      }
      previous = bytes;
      const r = bytesToBigInt(bytes) & mask;
      // Never on the first draw: a source that fills one array and no more would pass.
      if (draw > 0 && (modulus === undefined || (r > BigInt(1) && r < modulus))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * RSA-PSS signing draws a random salt through `crypto.getRandomValues`, which
 * Hermes does not provide. Every other operation works without it.
 */
export function assertRandomSource(operation: string): void {
  if (randomValues() === undefined) {
    throw new JwtHostRequirementError(
      'crypto.getRandomValues',
      `${operation} needs crypto.getRandomValues, which this JavaScript engine does not provide. ` +
        'In React Native, install react-native-get-random-values and import it once, before this library.',
    );
  }
  if (!randomSourceWorks()) {
    throw new JwtHostRequirementError(
      'crypto.getRandomValues',
      `${operation} needs crypto.getRandomValues, but the one installed throws or does not produce random bytes. ` +
        'Check the polyfill (react-native-get-random-values needs its native module, or Expo) or the test mock.',
    );
  }
}
