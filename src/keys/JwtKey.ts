import { JwtKeyError } from '../errors/errors';
import { type Algorithm } from '../types/algorithm';
import { bitLength } from '../utils/bytes';

export type EcCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';

/**
 * What a key is made of. Public parts are always present, so any key that can
 * sign can also verify.
 */
export type KeyMaterial =
  | { readonly kind: 'secret'; readonly secret: Uint8Array }
  | { readonly kind: 'rsa'; readonly n: bigint; readonly e: bigint; readonly d?: bigint }
  | { readonly kind: 'ec'; readonly curve: EcCurve; readonly publicKey: Uint8Array; readonly privateKey?: Uint8Array }
  | { readonly kind: 'okp'; readonly curve: 'Ed25519'; readonly publicKey: Uint8Array; readonly privateKey?: Uint8Array };

export type KeyType = 'secret' | 'public' | 'private';

/**
 * An imported key, bound to exactly one algorithm (RFC 8725 §3.1).
 * Create one with `importPEM`, `importJWK`, or through `createJWKS`.
 * See memory_bank/adr/ADR-003-one-key-one-algorithm.md.
 */
export interface JwtKey {
  readonly algorithm: Algorithm;
  readonly type: KeyType;
  readonly kid?: string;
}

// The material lives outside the object, so a key cannot be forged from a
// plain object literal and its secret parts do not show up when it is logged.
const materials = new WeakMap<object, KeyMaterial>();

const EC_CURVE_FOR: Partial<Record<Algorithm, EcCurve>> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
  ES256K: 'secp256k1',
};

export const MIN_RSA_BITS = 2048;

/** Throws unless `material` is usable with `algorithm`. */
export function assertKeyFitsAlgorithm(material: KeyMaterial, algorithm: Algorithm): void {
  const family = algorithm.slice(0, 2);
  if (family === 'HS') {
    if (material.kind !== 'secret') {
      throw new JwtKeyError(`${algorithm} needs an HMAC secret, but the key is ${describe(material)}.`);
    }
    return;
  }
  if (family === 'RS' || family === 'PS') {
    if (material.kind !== 'rsa') {
      throw new JwtKeyError(`${algorithm} needs an RSA key, but the key is ${describe(material)}.`);
    }
    // RFC 7518 §3.3. micro-rsa-dsa-dh checks this only for keys it generates.
    if (bitLength(material.n) < MIN_RSA_BITS) {
      throw new JwtKeyError(`RSA keys must be at least ${MIN_RSA_BITS} bits; this one is ${bitLength(material.n)}.`);
    }
    if (material.e < BigInt(3) || material.e % BigInt(2) === BigInt(0)) {
      throw new JwtKeyError('The RSA public exponent must be odd and at least 3.');
    }
    return;
  }
  if (algorithm === 'EdDSA') {
    if (material.kind !== 'okp') {
      throw new JwtKeyError(`EdDSA needs an Ed25519 key, but the key is ${describe(material)}.`);
    }
    return;
  }
  const curve = EC_CURVE_FOR[algorithm];
  if (material.kind !== 'ec' || material.curve !== curve) {
    throw new JwtKeyError(`${algorithm} needs a ${curve} key, but the key is ${describe(material)}.`);
  }
}

function describe(material: KeyMaterial): string {
  switch (material.kind) {
    case 'secret':
      return 'an HMAC secret';
    case 'rsa':
      return 'an RSA key';
    case 'ec':
      return `an EC ${material.curve} key`;
    case 'okp':
      return `an ${material.curve} key`;
  }
}

export function createKey(material: KeyMaterial, algorithm: Algorithm, kid?: string): JwtKey {
  assertKeyFitsAlgorithm(material, algorithm);
  const hasPrivate =
    material.kind === 'rsa' ? material.d !== undefined : material.kind === 'secret' ? false : material.privateKey !== undefined;
  const key: JwtKey = Object.freeze({
    algorithm,
    type: material.kind === 'secret' ? 'secret' : hasPrivate ? 'private' : 'public',
    ...(kid !== undefined ? { kid } : {}),
  });
  materials.set(key, material);
  return key;
}

export function keyMaterialOf(key: unknown): KeyMaterial | undefined {
  return key !== null && typeof key === 'object' ? materials.get(key) : undefined;
}

export function canSign(material: KeyMaterial): boolean {
  switch (material.kind) {
    case 'secret':
      return true;
    case 'rsa':
      return material.d !== undefined;
    default:
      return material.privateKey !== undefined;
  }
}
