import { JwtHostRequirementError } from '../errors/errors';

/**
 * What the crypto dependencies need from the host at import time.
 *
 * `@noble/hashes`, `@noble/curves` and `micro-rsa-dsa-dh` call `Object.hasOwn`
 * while their modules load, and use `BigInt` throughout. A missing one would
 * otherwise surface as `Object.hasOwn is not a function` from inside noble.
 *
 * The third check is about the build, not the engine: `@noble/curves` raises a
 * BigInt to a power with `**` on the Ed25519 path. A Babel setup that rewrites
 * `**` into `Math.pow` — React Native 0.70's preset did, as does
 * `@babel/preset-env` aimed at old targets — turns that into a TypeError, and
 * Ed25519 verification into a silent "invalid signature". This line goes
 * through the same Babel setup as noble does, so it fails exactly when noble
 * would.
 *
 * See memory_bank/adr/ADR-005-host-requirements.md.
 */
export const HostFeature = {
  BigInt: 'BigInt',
  ObjectHasOwn: 'Object.hasOwn',
  BigIntExponentiation: 'BigInt exponentiation (**)',
} as const;
export type HostFeature = (typeof HostFeature)[keyof typeof HostFeature];

export function missingHostFeature(): HostFeature | null {
  if (typeof BigInt !== 'function') {
    return HostFeature.BigInt;
  }
  if (typeof (Object as { hasOwn?: unknown }).hasOwn !== 'function') {
    return HostFeature.ObjectHasOwn;
  }
  try {
    if (BigInt(2) ** BigInt(3) !== BigInt(8)) {
      return HostFeature.BigIntExponentiation;
    }
  } catch {
    return HostFeature.BigIntExponentiation;
  }
  return null;
}

const ADVICE: Record<HostFeature, string> = {
  [HostFeature.BigInt]:
    'This JavaScript engine has no BigInt. Use Hermes from React Native 0.71 or later (see the README).',
  [HostFeature.ObjectHasOwn]:
    'This JavaScript engine has no Object.hasOwn. Use Hermes from React Native 0.71 or later, ' +
    'or install a polyfill for Object.hasOwn before importing this library.',
  [HostFeature.BigIntExponentiation]:
    'Your Babel configuration rewrites the ** operator into Math.pow, which cannot handle BigInt. ' +
    "React Native 0.70's preset does this; React Native 0.71 and later do not. Upgrade, or remove " +
    '@babel/plugin-transform-exponentiation-operator (or an old @babel/preset-env target) from your Babel config.',
};

export function assertHost(): void {
  const missing = missingHostFeature();
  if (missing !== null) {
    throw new JwtHostRequirementError(missing, `react-native-jwt-io cannot run here: ${ADVICE[missing]}`);
  }
}

// Runs when the module is evaluated. `src/index.ts` imports this module first,
// so the check happens before any crypto dependency is loaded.
assertHost();
