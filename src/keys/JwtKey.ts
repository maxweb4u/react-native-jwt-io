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

/** The JWS operations a JWK's `key_ops` allows (RFC 7517 §4.3). */
export type KeyOperation = 'sign' | 'verify';

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
// Only for a JWK with key_ops; any other key may do what its material allows.
const operations = new WeakMap<object, readonly KeyOperation[]>();

const EC_CURVE_FOR: Partial<Record<Algorithm, EcCurve>> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
  ES256K: 'secp256k1',
};

export const MIN_RSA_BITS = 2048;
/** micro-rsa-dsa-dh refuses larger moduli at every operation; refusing them at import says why. */
export const MAX_RSA_BITS = 16384;
/**
 * As BoringSSL allows. Real keys use 65537; a huge exponent from a hostile
 * JWKS would only make every verification slow (2^256 - 1 is 45 times slower).
 */
export const MAX_RSA_EXPONENT_BITS = 33;

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
    if (bitLength(material.n) > MAX_RSA_BITS) {
      throw new JwtKeyError(`RSA keys larger than ${MAX_RSA_BITS} bits are not supported; this one is ${bitLength(material.n)}.`);
    }
    if (bitLength(material.e) > MAX_RSA_EXPONENT_BITS) {
      throw new JwtKeyError(`RSA public exponents above ${MAX_RSA_EXPONENT_BITS} bits are not supported.`);
    }
    if (material.n % BigInt(2) === BigInt(0)) {
      throw new JwtKeyError('The RSA modulus must be odd.');
    }
    // Below the modulus too, since the modulus has at least 2048 bits.
    if (material.e < BigInt(3) || material.e % BigInt(2) === BigInt(0)) {
      throw new JwtKeyError('The RSA public exponent must be odd and at least 3.');
    }
    if (material.d !== undefined && (material.d <= BigInt(1) || material.d >= material.n)) {
      throw new JwtKeyError('The RSA private exponent is out of range for its modulus.');
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

/**
 * When the primes are known (PKCS#1, PKCS#8, and JWKs that carry them), a
 * private key whose parts do not belong together is refused at import —
 * otherwise it would sign tokens nobody can verify.
 */
export function rsaPrivatePartsMatch(n: bigint, e: bigint, d: bigint, p: bigint, q: bigint): boolean {
  const one = BigInt(1);
  if (p <= one || q <= one || p * q !== n) {
    return false;
  }
  const gcd = (a: bigint, b: bigint): bigint => {
    let x = a;
    let y = b;
    while (y !== BigInt(0)) {
      [x, y] = [y, x % y];
    }
    return x;
  };
  const lambda = ((p - one) * (q - one)) / gcd(p - one, q - one);
  return (e * d) % lambda === one;
}

export function createKey(material: KeyMaterial, algorithm: Algorithm, kid?: string, allowed?: readonly KeyOperation[]): JwtKey {
  assertKeyFitsAlgorithm(material, algorithm);
  const hasPrivate =
    material.kind === 'rsa' ? material.d !== undefined : material.kind === 'secret' ? false : material.privateKey !== undefined;
  const key: JwtKey = Object.freeze({
    algorithm,
    type: material.kind === 'secret' ? 'secret' : hasPrivate ? 'private' : 'public',
    ...(kid !== undefined ? { kid } : {}),
  });
  materials.set(key, material);
  if (allowed !== undefined) {
    operations.set(key, Object.freeze([...allowed]));
  }
  return key;
}

export function keyOperationsOf(key: object): readonly KeyOperation[] | undefined {
  return operations.get(key);
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
