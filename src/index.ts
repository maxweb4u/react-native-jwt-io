// Must stay the first import: it checks the engine before the crypto
// dependencies load. See memory_bank/adr/ADR-005-host-requirements.md.
import './host/hostCheck';
import { legacyDefaultExport } from './jwt/legacy';

// 1.x tombstones by name, for require() and Node ESM default imports.
export { decode, encode } from './jwt/legacy';

export { sign } from './jwt/sign';
export { verify } from './jwt/verify';
export { decodeUnverified } from './jwt/decodeUnverified';
export { getExpiration, isExpired } from './jwt/expiry';

export { importPEM, type ImportOptions } from './keys/pem';
export { importJWK } from './keys/jwk';
export { createJWKS, type CreateJwksOptions, type JwtKeySet } from './keys/jwks';
export { type JwtKey, type KeyType } from './keys/JwtKey';
export { type KeyInput } from './keys/resolveKey';
export { hexToBytes } from './utils/bytes';

export { Algorithm, type HmacAlgorithm } from './types/algorithm';
export { type DecodedJwt, type Jwk, type JwkSet, type JwtHeader, type JwtPayload } from './types/jwt';
export { type ClockOptions, type Duration, type SignOptions, type VerifyOptions } from './types/options';

export {
  JwtAlgorithmError,
  JwtClaimError,
  JwtError,
  JwtErrorCode,
  JwtExpiredError,
  JwtHostRequirementError,
  JwtKeyError,
  JwtKeyNotFoundError,
  JwtMalformedError,
  JwtMigrationError,
  JwtNotBeforeError,
  JwtSignatureError,
} from './errors/errors';

/** @deprecated The 1.x API. Every member throws `JwtMigrationError`. Removed in 3.0, with the named `encode` and `decode`. */
export default legacyDefaultExport;
