import { JwtHostRequirementError } from '../errors/errors';

/**
 * The engine features the crypto dependencies need at import time.
 *
 * `@noble/hashes`, `@noble/curves` and `micro-rsa-dsa-dh` call `Object.hasOwn`
 * while their modules load, and use `BigInt` throughout. A missing one would
 * otherwise surface as `Object.hasOwn is not a function` from inside noble.
 *
 * See memory_bank/adr/ADR-005-host-requirements.md.
 */
export function missingHostFeature(): string | null {
  if (typeof BigInt !== 'function') {
    return 'BigInt';
  }
  if (typeof (Object as { hasOwn?: unknown }).hasOwn !== 'function') {
    return 'Object.hasOwn';
  }
  return null;
}

export function assertHost(): void {
  const missing = missingHostFeature();
  if (missing !== null) {
    throw new JwtHostRequirementError(
      missing,
      `react-native-jwt-io needs ${missing}, which this JavaScript engine does not provide. ` +
        'Use a React Native version whose Hermes has it (see the README for the supported range), ' +
        `or install a polyfill for ${missing} before importing this library.`,
    );
  }
}

// Runs when the module is evaluated. `src/index.ts` imports this module first,
// so the check happens before any crypto dependency is loaded.
assertHost();
