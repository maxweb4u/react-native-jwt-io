import {
  EC_FIELD_BYTES,
  ecPublicKeyFromPrivate,
  ed25519PublicKeyFromPrivate,
  isValidEd25519PublicKey,
  normalizeEcPublicKey,
} from '../crypto/curves';
import { JwtKeyError } from '../errors/errors';
import { type Algorithm, isAlgorithm } from '../types/algorithm';
import { type Jwk } from '../types/jwt';
import { base64UrlDecode } from '../utils/base64';
import { bytesToBigInt, concatBytes, equalBytes } from '../utils/bytes';
import { isPlainObject } from '../utils/json';
import { createKey, type EcCurve, type JwtKey, type KeyMaterial, rsaPrivatePartsMatch } from './JwtKey';

const EC_ALGORITHM: Record<EcCurve, Algorithm> = {
  'P-256': 'ES256',
  'P-384': 'ES384',
  'P-521': 'ES512',
  secp256k1: 'ES256K',
};

const SUPPORTED_CURVES: readonly string[] = Object.keys(EC_ALGORITHM);

/** Why a JWK cannot be used for signatures at all, or null if it can. Used by `createJWKS` to skip such keys. */
export function unsupportedReason(jwk: Jwk): string | null {
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    return `use "${String(jwk.use)}"`;
  }
  const ops = jwk.key_ops;
  if (ops !== undefined && !(Array.isArray(ops) && ops.some((op) => op === 'sign' || op === 'verify'))) {
    return `key_ops ${JSON.stringify(ops)}`;
  }
  if (jwk.alg !== undefined && !isAlgorithm(jwk.alg)) {
    return `alg "${String(jwk.alg)}"`;
  }
  switch (jwk.kty) {
    case 'RSA':
    case 'oct':
      return null;
    case 'EC':
      return SUPPORTED_CURVES.includes(String(jwk.crv)) ? null : `curve "${String(jwk.crv)}"`;
    case 'OKP':
      return jwk.crv === 'Ed25519' ? null : `curve "${String(jwk.crv)}"`;
    default:
      return `kty "${String(jwk.kty)}"`;
  }
}

/**
 * Imports a JWK for exactly one algorithm: the JWK's own `alg`, else the
 * `algorithm` argument, else the one its curve implies. RSA and `oct` keys
 * need one of the first two. See memory_bank/domain/keys.md#binding.
 */
export function importJWK(jwk: Jwk, algorithm?: Algorithm): JwtKey {
  if (!isPlainObject(jwk)) {
    throw new JwtKeyError('importJWK expects a JWK object.');
  }
  const reason = unsupportedReason(jwk);
  if (reason !== null) {
    throw new JwtKeyError(`This JWK cannot be used for JWS signatures (${reason}).`);
  }
  if (algorithm !== undefined && !isAlgorithm(algorithm)) {
    throw new JwtKeyError(`Unsupported algorithm ${String(algorithm)}.`);
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
      const n = bytesToBigInt(member(jwk, 'n'));
      const e = bytesToBigInt(member(jwk, 'e'));
      if (jwk.d === undefined) {
        return { kind: 'rsa', n, e };
      }
      const d = bytesToBigInt(member(jwk, 'd'));
      // RFC 7518 §6.3.2: the primes come with d or not at all. When present,
      // they must produce this n, e and d.
      if (jwk.p !== undefined || jwk.q !== undefined) {
        const p = bytesToBigInt(member(jwk, 'p'));
        const q = bytesToBigInt(member(jwk, 'q'));
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

function member(jwk: Jwk, name: string, length?: number): Uint8Array {
  const value = jwk[name];
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
