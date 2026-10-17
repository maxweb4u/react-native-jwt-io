import { JwtAlgorithmError, JwtKeyError, JwtKeyNotFoundError } from '../errors/errors';
import { type Algorithm } from '../types/algorithm';
import { type JwkSet } from '../types/jwt';
import { describeValue } from '../utils/describe';
import { isPlainObject } from '../utils/json';
import { assertAlgorithmOption, assertKnownOptions } from '../utils/options';
import { importJWK, unsupportedReason } from './jwk';
import { type JwtKey } from './JwtKey';

/** Keys selected by the token's `kid`, then by `alg`. Create one with `createJWKS`. */
export interface JwtKeySet {
  readonly keys: readonly JwtKey[];
  /**
   * Keys of a supported type that could not be imported (too short, malformed,
   * an `alg` that contradicts the key). They are left out so the rest of the
   * set still works; a token whose `kid` names one fails with the reason.
   */
  readonly skipped: readonly SkippedJwk[];
}

export interface SkippedJwk {
  /** Position in the JWKS `keys` array. */
  readonly index: number;
  readonly kid?: string;
  readonly reason: string;
}

export interface CreateJwksOptions {
  /** The algorithm for RSA and `oct` keys that carry no `alg`, as some issuers publish them. */
  readonly algorithm?: Algorithm;
}

const keySets = new WeakSet<object>();

/**
 * A key set from a JWKS object (`{ keys: [...] }`), loaded however the caller
 * likes. Keys that are not for signatures (`use: "enc"`) or of a type this
 * library does not support are left out silently; a supported key that cannot
 * be imported is left out and listed in `skipped` — one bad key in an
 * issuer's set must not stop the others from working. Remote fetching is
 * planned for 2.1 (memory_bank/product/roadmap.md).
 */
export function createJWKS(jwks: JwkSet, options: CreateJwksOptions = {}): JwtKeySet {
  // Options first, as everywhere (ADR-008).
  const opts: CreateJwksOptions = options ?? {};
  assertKnownOptions(opts, ['algorithm']);
  // Checked here: inside the loop an unknown name would only skip every key it applies to.
  const setAlgorithm = opts.algorithm;
  assertAlgorithmOption(setAlgorithm);
  if (!isPlainObject(jwks) || !Array.isArray(jwks.keys)) {
    throw new JwtKeyError('createJWKS expects a JWKS object: { keys: [...] }.');
  }
  const keys: JwtKey[] = [];
  const skipped: SkippedJwk[] = [];
  jwks.keys.forEach((jwk, index) => {
    if (!isPlainObject(jwk)) {
      throw new JwtKeyError(`JWKS key #${index} is not an object.`);
    }
    if (unsupportedReason(jwk) !== null) {
      return;
    }
    const algorithm = jwk.alg === undefined && (jwk.kty === 'RSA' || jwk.kty === 'oct') ? setAlgorithm : undefined;
    try {
      keys.push(importJWK(jwk, algorithm));
    } catch (error) {
      if (!(error instanceof JwtKeyError)) {
        throw error;
      }
      skipped.push(Object.freeze({ index, ...(typeof jwk.kid === 'string' ? { kid: jwk.kid } : {}), reason: error.message }));
    }
  });
  const set: JwtKeySet = Object.freeze({ keys: Object.freeze(keys), skipped: Object.freeze(skipped) });
  keySets.add(set);
  return set;
}

export function isJwtKeySet(value: unknown): value is JwtKeySet {
  return value !== null && typeof value === 'object' && keySets.has(value);
}

/**
 * Picks the key for a token. With a `kid`, only keys with that `kid` are
 * candidates; without one, the set must hold exactly one key for the token's
 * `alg`. Never falls back to trying every key.
 */
export function selectKey(set: JwtKeySet, kid: string | undefined, alg: Algorithm): JwtKey {
  if (kid !== undefined) {
    const sameKid = set.keys.filter((key) => key.kid === kid);
    if (sameKid.length === 0) {
      const unusable = set.skipped.find((entry) => entry.kid === kid);
      if (unusable) {
        throw new JwtKeyError(`The key with kid ${describeValue(kid)} is in the set but could not be imported: ${unusable.reason}`);
      }
      throw new JwtKeyNotFoundError(`No key in the set has kid ${describeValue(kid)}.`, kid);
    }
    const matches = sameKid.filter((key) => key.algorithm === alg);
    if (matches.length === 0) {
      throw new JwtAlgorithmError(`The key with kid ${describeValue(kid)} is for ${sameKid.map((k) => k.algorithm).join(', ')}, but the token says ${alg}.`);
    }
    if (matches.length > 1) {
      throw new JwtKeyNotFoundError(`${matches.length} keys in the set have kid ${describeValue(kid)} and are for ${alg}; the choice would be a guess.`, kid);
    }
    return matches[0] as JwtKey;
  }
  const forAlg = set.keys.filter((key) => key.algorithm === alg);
  if (forAlg.length !== 1) {
    throw new JwtKeyNotFoundError(
      forAlg.length === 0
        ? `The token has no kid, and no key in the set is for ${alg}${
            set.skipped.length > 0 ? ` (${set.skipped.length} could not be imported; see the set's skipped list)` : ''
          }.`
        : `The token has no kid, and ${forAlg.length} keys in the set are for ${alg}; the choice would be a guess.`,
      undefined,
    );
  }
  return forAlg[0] as JwtKey;
}
