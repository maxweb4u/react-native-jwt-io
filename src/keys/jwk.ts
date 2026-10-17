import {
  EC_FIELD_BYTES,
  ecPublicKeyFromPrivate,
  ed25519PublicKeyFromPrivate,
  isValidEd25519PublicKey,
  normalizeEcPublicKey,
} from '../crypto/curves';
import { JwtKeyError, JwtOptionError } from '../errors/errors';
import { type Algorithm, isAlgorithm } from '../types/algorithm';
import { type Jwk } from '../types/jwt';
import { base64UrlDecode } from '../utils/base64';
import { bytesToBigInt, concatBytes, equalBytes, significantLength } from '../utils/bytes';
import { describeValue } from '../utils/describe';
import { isPlainObject } from '../utils/json';
import {
  createKey,
  type EcCurve,
  type JwtKey,
  type KeyMaterial,
  MAX_RSA_BITS,
  MAX_RSA_EXPONENT_BITS,
  rsaPrivatePartsMatch,
} from './JwtKey';

const EC_ALGORITHM: Record<EcCurve, Algorithm> = {
  'P-256': 'ES256',
  'P-384': 'ES384',
  'P-521': 'ES512',
  secp256k1: 'ES256K',
};

const SUPPORTED_CURVES: readonly string[] = Object.keys(EC_ALGORITHM);

/** Why a JWK cannot be used for signatures at all, or null if it can. */
export function unsupportedReason(jwk: Jwk): string | null {
  const type = unsupportedType(jwk);
  if (type !== null) {
    return type;
  }
  if (jwk.alg !== undefined && !isAlgorithm(jwk.alg)) {
    // RFC 9864 names Ed25519 signatures "Ed25519"; this library still calls them EdDSA.
    return jwk.alg === 'Ed25519' ? 'alg "Ed25519" (RFC 9864) is not supported yet; EdDSA is' : `alg ${describeValue(jwk.alg)}`;
  }
  return null;
}

// JWE key-management algorithms (RFC 7518 §4): an encryption key, even without "use".
const ENCRYPTION_ALG = /^(?:RSA1_5|RSA-OAEP(?:-\d{3})?|ECDH-ES(?:\+A\d{3}KW)?|A\d{3}(?:GCM)?KW|dir|PBES2-HS\d{3}\+A\d{3}KW)$/;

/** Why a JWK is not a signature key of a supported type, or null. `createJWKS` leaves such keys out silently. */
export function unsupportedType(jwk: Jwk): string | null {
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    return `use ${describeValue(jwk.use)}`;
  }
  if (typeof jwk.alg === 'string' && ENCRYPTION_ALG.test(jwk.alg)) {
    return `alg ${describeValue(jwk.alg)}, for encryption`;
  }
  const ops = jwk.key_ops;
  if (ops !== undefined && !(Array.isArray(ops) && ops.some((op) => op === 'sign' || op === 'verify'))) {
    return `key_ops ${describeValue(ops)}`;
  }
  switch (jwk.kty) {
    case 'RSA':
    case 'oct':
      return null;
    case 'EC':
      return typeof jwk.crv === 'string' && SUPPORTED_CURVES.includes(jwk.crv) ? null : `curve ${describeValue(jwk.crv)}`;
    case 'OKP':
      return jwk.crv === 'Ed25519' ? null : `curve ${describeValue(jwk.crv)}`;
    default:
      return `kty ${describeValue(jwk.kty)}`;
  }
}

/**
 * Imports a JWK for exactly one algorithm: the JWK's own `alg`, else the
 * `algorithm` argument, else the one its curve implies. RSA and `oct` keys
 * need one of the first two. See memory_bank/domain/keys.md#binding.
 */
export function importJWK(jwk: Jwk, algorithm?: Algorithm): JwtKey {
  // The algorithm argument first: naming no algorithm is a mistake in the call, whatever the JWK.
  if (algorithm !== undefined && !isAlgorithm(algorithm)) {
    throw new JwtOptionError('algorithm', `Unsupported algorithm ${describeValue(algorithm)}.`);
  }
  if (!isPlainObject(jwk)) {
    throw new JwtKeyError('importJWK expects a JWK object.');
  }
  const reason = unsupportedReason(jwk);
  if (reason !== null) {
    throw new JwtKeyError(`This JWK cannot be used for JWS signatures (${reason}).`);
  }
  if (jwk.alg !== undefined && algorithm !== undefined && jwk.alg !== algorithm) {
    throw new JwtKeyError(`The JWK is for ${jwk.alg}, not ${algorithm}. A key is bound to exactly one algorithm.`);
  }
  if (jwk.kid !== undefined && typeof jwk.kid !== 'string') {
    throw new JwtKeyError('The JWK "kid" must be a string.');
  }
  const material = materialOf(jwk);
  const bound = (jwk.alg as Algorithm | undefined) ?? algorithm ?? impliedAlgorithm(material);
  if (bound === undefined) {
    throw new JwtKeyError(
      `This ${jwk.kty} JWK has no "alg", and its type allows several algorithms. Pass one: importJWK(jwk, '${
        jwk.kty === 'oct' ? 'HS256' : 'RS256'
      }').`,
    );
  }
  return createKey(material, bound, jwk.kid);
}

function impliedAlgorithm(material: KeyMaterial): Algorithm | undefined {
  if (material.kind === 'ec') {
    return EC_ALGORITHM[material.curve];
  }
  if (material.kind === 'okp') {
    return 'EdDSA';
  }
  return undefined;
}

function materialOf(jwk: Jwk): KeyMaterial {
  switch (jwk.kty) {
    case 'oct': {
      const secret = member(jwk, 'k');
      if (secret.length === 0) {
        throw new JwtKeyError('The JWK "k" is empty.');
      }
      return { kind: 'secret', secret };
    }
    case 'RSA': {
      const n = rsaInteger(jwk, 'n', MAX_RSA_BITS);
      const e = rsaInteger(jwk, 'e', MAX_RSA_EXPONENT_BITS);
      if (jwk.d === undefined) {
        return { kind: 'rsa', n, e };
      }
      const d = rsaInteger(jwk, 'd', MAX_RSA_BITS);
      // RFC 7518 §6.3.2: the primes come with d or not at all. When present,
      // they must produce this n, e and d.
      if (jwk.p !== undefined || jwk.q !== undefined) {
        const p = rsaInteger(jwk, 'p', MAX_RSA_BITS);
        const q = rsaInteger(jwk, 'q', MAX_RSA_BITS);
        if (!rsaPrivatePartsMatch(n, e, d, p, q)) {
          throw new JwtKeyError('The RSA JWK parts do not belong together.');
        }
      }
      return { kind: 'rsa', n, e, d };
    }
    case 'EC': {
      const curve = jwk.crv as EcCurve;
      const size = EC_FIELD_BYTES[curve];
      const x = member(jwk, 'x', size);
      const y = member(jwk, 'y', size);
      const publicKey = normalizeEcPublicKey(curve, concatBytes(Uint8Array.of(4), x, y));
      if (!publicKey) {
        throw new JwtKeyError(`The JWK x and y are not a point on ${curve}.`);
      }
      if (jwk.d === undefined) {
        return { kind: 'ec', curve, publicKey };
      }
      const privateKey = member(jwk, 'd', size);
      const derived = ecPublicKeyFromPrivate(curve, privateKey);
      if (!derived || !equalBytes(derived, publicKey)) {
        throw new JwtKeyError('The JWK "d" does not match its "x" and "y".');
      }
      return { kind: 'ec', curve, publicKey, privateKey };
    }
    default: {
      const publicKey = member(jwk, 'x', 32);
      if (!isValidEd25519PublicKey(publicKey)) {
        throw new JwtKeyError('The JWK "x" is not a valid Ed25519 public key.');
      }
      if (jwk.d === undefined) {
        return { kind: 'okp', curve: 'Ed25519', publicKey };
      }
      const privateKey = member(jwk, 'd', 32);
      const derived = ed25519PublicKeyFromPrivate(privateKey);
      if (!derived || !equalBytes(derived, publicKey)) {
        throw new JwtKeyError('The JWK "d" does not match its "x".');
      }
      return { kind: 'okp', curve: 'Ed25519', publicKey, privateKey };
    }
  }
}

/** An RSA JWK integer, its size checked before the conversion, which costs time in proportion to its length. */
function rsaInteger(jwk: Jwk, name: string, maxBits: number): bigint {
  const bytes = member(jwk, name);
  if (significantLength(bytes) > Math.ceil(maxBits / 8)) {
    throw new JwtKeyError(
      name === 'e'
        ? `RSA public exponents above ${maxBits} bits are not supported.`
        : `RSA keys larger than ${maxBits} bits are not supported; the JWK "${name}" is longer.`,
    );
  }
  return bytesToBigInt(bytes);
}

function member(jwk: Jwk, name: string, length?: number): Uint8Array {
  const value = (jwk as Readonly<Record<string, unknown>>)[name];
  if (typeof value !== 'string') {
    throw new JwtKeyError(`The ${String(jwk.kty)} JWK is missing "${name}".`);
  }
  const bytes = base64UrlDecode(value);
  if (bytes === null) {
    throw new JwtKeyError(`The JWK "${name}" is not valid base64url.`);
  }
  if (length !== undefined && bytes.length !== length) {
    throw new JwtKeyError(`The JWK "${name}" must be ${length} bytes; it is ${bytes.length}.`);
  }
  return bytes;
}
