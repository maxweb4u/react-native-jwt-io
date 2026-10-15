import { JwtAlgorithmError, JwtKeyError } from '../errors/errors';
import { type Algorithm, type HmacAlgorithm, isHmacAlgorithm } from '../types/algorithm';
import { isBytes } from '../utils/bytes';
import { utf8Encode } from '../utils/utf8';
import { type JwtKey, keyMaterialOf, type KeyMaterial } from './JwtKey';

/** A bare HMAC secret, or a key from `importPEM` / `importJWK`. */
export type KeyInput = string | Uint8Array | JwtKey;

export interface ResolvedKey {
  readonly algorithm: Algorithm;
  readonly material: KeyMaterial;
  readonly kid: string | undefined;
}

const HMAC_MIN_BYTES: Record<HmacAlgorithm, number> = { HS256: 32, HS384: 48, HS512: 64 };

/**
 * One key, one algorithm: a bare secret is HS256 unless `algorithm` names
 * another HMAC; an imported key is whatever it was imported for, and a
 * contradicting `algorithm` is an error, not an override.
 * See memory_bank/adr/ADR-003-one-key-one-algorithm.md.
 */
export function resolveKey(key: KeyInput, algorithm: unknown): ResolvedKey {
  if (typeof key === 'string' || isBytes(key)) {
    const text = typeof key === 'string' ? key : String.fromCharCode(...key.subarray(0, 64));
    if (/-----BEGIN [A-Z ]+-----/.test(text)) {
      // A PEM passed as a string would otherwise be used as an HMAC secret —
      // the precondition of RS256-to-HS256 confusion.
      throw new JwtKeyError("A PEM key was passed as a string. Import it with importPEM(pem, 'RS256') — strings are HMAC secrets.");
    }
    const chosen = algorithm ?? 'HS256';
    if (!isHmacAlgorithm(chosen)) {
      throw new JwtAlgorithmError(`A bare secret is an HMAC key; "algorithm" must be HS256, HS384 or HS512, not ${String(chosen)}.`);
    }
    const secret = typeof key === 'string' ? utf8Encode(key) : key.slice();
    return { algorithm: chosen, material: { kind: 'secret', secret }, kid: undefined };
  }
  const material = keyMaterialOf(key);
  if (!material) {
    throw new JwtKeyError('Keys must be a secret string, a Uint8Array, or a key from importPEM, importJWK or createJWKS.');
  }
  if (algorithm !== undefined && algorithm !== key.algorithm) {
    throw new JwtAlgorithmError(`This key is bound to ${key.algorithm}; it cannot be used as ${String(algorithm)}.`);
  }
  return { algorithm: key.algorithm, material, kid: key.kid };
}

/**
 * RFC 7518 §3.2: an HMAC key at least as long as the hash output. Checked
 * after the algorithm is settled, so a wrong algorithm is reported as such.
 */
export function assertSecretStrength(resolved: ResolvedKey, allowShortSecret: boolean | undefined): void {
  if (resolved.material.kind !== 'secret') {
    return;
  }
  const { secret } = resolved.material;
  const algorithm = resolved.algorithm as HmacAlgorithm;
  if (secret.length === 0) {
    throw new JwtKeyError('The HMAC secret is empty.');
  }
  const minimum = HMAC_MIN_BYTES[algorithm];
  if (secret.length < minimum && allowShortSecret !== true) {
    throw new JwtKeyError(
      `${algorithm} needs a secret of at least ${minimum} bytes (RFC 7518 §3.2); this one is ${secret.length}. ` +
        'Use a longer secret, or pass { allowShortSecret: true } only to work with a legacy issuer.',
    );
  }
}
