/**
 * Supported JWS algorithms. `none` is not one of them, and never will be.
 * See memory_bank/domain/algorithms.md.
 */
export const Algorithm = Object.freeze({
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
  RS256: 'RS256',
  RS384: 'RS384',
  RS512: 'RS512',
  PS256: 'PS256',
  PS384: 'PS384',
  PS512: 'PS512',
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  ES256K: 'ES256K',
  EdDSA: 'EdDSA',
} as const);
export type Algorithm = (typeof Algorithm)[keyof typeof Algorithm];

export type HmacAlgorithm = 'HS256' | 'HS384' | 'HS512';

const ALGORITHMS: ReadonlySet<string> = new Set(Object.keys(Algorithm));

export function isAlgorithm(value: unknown): value is Algorithm {
  return typeof value === 'string' && ALGORITHMS.has(value);
}

export function isHmacAlgorithm(value: unknown): value is HmacAlgorithm {
  return value === 'HS256' || value === 'HS384' || value === 'HS512';
}
