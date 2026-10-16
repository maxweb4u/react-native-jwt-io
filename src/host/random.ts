import { JwtHostRequirementError } from '../errors/errors';

type CryptoLike = { getRandomValues?: unknown };

/** Whether the host has `crypto.getRandomValues` (in React Native, from react-native-get-random-values). */
export function hasRandomSource(): boolean {
  const host = (globalThis as { crypto?: CryptoLike }).crypto;
  return !!host && typeof host.getRandomValues === 'function';
}

/**
 * RSA-PSS signing draws a random salt through `crypto.getRandomValues`, which
 * Hermes does not provide. Every other operation is deterministic.
 */
export function assertRandomSource(operation: string): void {
  if (!hasRandomSource()) {
    throw new JwtHostRequirementError(
      'crypto.getRandomValues',
      `${operation} needs crypto.getRandomValues, which this JavaScript engine does not provide. ` +
        "In React Native, install react-native-get-random-values and import it once, before this library.",
    );
  }
}
