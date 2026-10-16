import { JwtHostRequirementError } from '../errors/errors';

type CryptoLike = { getRandomValues?: unknown };

/**
 * RSA-PSS signing draws a random salt through `crypto.getRandomValues`, which
 * Hermes does not provide. Every other operation is deterministic.
 */
export function assertRandomSource(operation: string): void {
  const host = (globalThis as { crypto?: CryptoLike }).crypto;
  if (!host || typeof host.getRandomValues !== 'function') {
    throw new JwtHostRequirementError(
      'crypto.getRandomValues',
      `${operation} needs crypto.getRandomValues, which this JavaScript engine does not provide. ` +
        "In React Native, install react-native-get-random-values and import it once, before this library.",
    );
  }
}
