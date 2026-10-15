import { JwtAlgorithmError, JwtKeyError, JwtKeyNotFoundError } from '../errors/errors';
import { type Algorithm } from '../types/algorithm';
import { type JwkSet } from '../types/jwt';
import { isPlainObject } from '../utils/json';
import { importJWK, unsupportedReason } from './jwk';
import { type JwtKey } from './JwtKey';

/** Keys selected by the token's `kid`, then by `alg`. Create one with `createJWKS`. */
export interface JwtKeySet {
  readonly keys: readonly JwtKey[];
}

export interface CreateJwksOptions {
  /** The algorithm for RSA and `oct` keys that carry no `alg`, as some issuers publish them. */
  readonly algorithm?: Algorithm;
}

const keySets = new WeakSet<object>();

/**
 * A key set from a JWKS object (`{ keys: [...] }`), loaded however the caller
 * likes. Keys that are not for signatures (`use: "enc"`) or of a type this
 * library does not support are skipped; a supported key that is malformed is
 * an error. Remote fetching is planned for 2.1 (memory_bank/product/roadmap.md).
 */
export function createJWKS(jwks: JwkSet, options: CreateJwksOptions = {}): JwtKeySet {
  if (!isPlainObject(jwks) || !Array.isArray(jwks.keys)) {
    throw new JwtKeyError('createJWKS expects a JWKS object: { keys: [...] }.');
  }
  const keys: JwtKey[] = [];
  jwks.keys.forEach((jwk, index) => {
    if (!isPlainObject(jwk)) {
      throw new JwtKeyError(`JWKS key #${index} is not an object.`);
    }
    if (unsupportedReason(jwk) !== null) {
      return;
    }
    const algorithm = jwk.alg === undefined && (jwk.kty === 'RSA' || jwk.kty === 'oct') ? options.algorithm : undefined;
    try {
      keys.push(importJWK(jwk, algorithm));
    } catch (error) {
      if (error instanceof JwtKeyError) {
        const name = typeof jwk.kid === 'string' ? `"${jwk.kid}"` : `#${index}`;
        throw new JwtKeyError(`JWKS key ${name}: ${error.message}`);
      }
      throw error;
    }
  });
  const set: JwtKeySet = Object.freeze({ keys: Object.freeze(keys) });
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
      throw new JwtKeyNotFoundError(`No key in the set has kid "${kid}".`, kid);
    }
    const match = sameKid.find((key) => key.algorithm === alg);
    if (!match) {
      throw new JwtAlgorithmError(`The key with kid "${kid}" is for ${sameKid.map((k) => k.algorithm).join(', ')}, but the token says ${alg}.`);
    }
    return match;
  }
  const forAlg = set.keys.filter((key) => key.algorithm === alg);
  if (forAlg.length !== 1) {
    throw new JwtKeyNotFoundError(
      forAlg.length === 0
        ? `The token has no kid, and no key in the set is for ${alg}.`
        : `The token has no kid, and ${forAlg.length} keys in the set are for ${alg}; the choice would be a guess.`,
      undefined,
    );
  }
  return forAlg[0] as JwtKey;
}
