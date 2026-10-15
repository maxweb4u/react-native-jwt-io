/**
 * Every deliberate failure in the library is one of these classes.
 *
 * Callers can branch on `code`, which survives duplicate copies of the package
 * in one bundle, where `instanceof` does not.
 *
 * See memory_bank/engineering/typescript.md#errors.
 */

export const JwtErrorCode = {
  Malformed: 'ERR_JWT_MALFORMED',
  Algorithm: 'ERR_JWT_ALGORITHM',
  SignatureInvalid: 'ERR_JWT_SIGNATURE_INVALID',
  Expired: 'ERR_JWT_EXPIRED',
  NotBefore: 'ERR_JWT_NOT_BEFORE',
  ClaimInvalid: 'ERR_JWT_CLAIM_INVALID',
  KeyInvalid: 'ERR_JWT_KEY_INVALID',
  KeyNotFound: 'ERR_JWT_KEY_NOT_FOUND',
  HostRequirement: 'ERR_JWT_HOST_REQUIREMENT',
  Migration: 'ERR_JWT_MIGRATION',
} as const;
export type JwtErrorCode = (typeof JwtErrorCode)[keyof typeof JwtErrorCode];

export class JwtError extends Error {
  readonly code: JwtErrorCode;

  constructor(code: JwtErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    // Babel's class transform, which some React Native presets still apply,
    // breaks `instanceof` for subclasses of built-ins without this.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** The token is not three base64url segments of a JSON object header and payload. */
export class JwtMalformedError extends JwtError {
  constructor(message: string) {
    super(JwtErrorCode.Malformed, message);
  }
}

/** `alg` is missing, `none`, unsupported, or differs from the key's single algorithm. */
export class JwtAlgorithmError extends JwtError {
  constructor(message: string) {
    super(JwtErrorCode.Algorithm, message);
  }
}

/** The signature does not verify with the given key. */
export class JwtSignatureError extends JwtError {
  constructor(message = 'Signature verification failed.') {
    super(JwtErrorCode.SignatureInvalid, message);
  }
}

/** `exp` has passed, or the token is older than `maxTokenAge`. */
export class JwtExpiredError extends JwtError {
  readonly expiredAt: Date;

  constructor(message: string, expiredAt: Date) {
    super(JwtErrorCode.Expired, message);
    this.expiredAt = expiredAt;
  }
}

/** `nbf` is still in the future. */
export class JwtNotBeforeError extends JwtError {
  readonly notBefore: Date;

  constructor(message: string, notBefore: Date) {
    super(JwtErrorCode.NotBefore, message);
    this.notBefore = notBefore;
  }
}

/** A claim has the wrong type or value, or a required claim is missing. */
export class JwtClaimError extends JwtError {
  readonly claim: string;

  constructor(claim: string, message: string) {
    super(JwtErrorCode.ClaimInvalid, message);
    this.claim = claim;
  }
}

/** A key cannot be imported, or cannot be used for the requested operation. */
export class JwtKeyError extends JwtError {
  constructor(message: string) {
    super(JwtErrorCode.KeyInvalid, message);
  }
}

/** No key in the key set matches the token's `kid` and `alg`. */
export class JwtKeyNotFoundError extends JwtError {
  readonly kid: string | undefined;

  constructor(message: string, kid: string | undefined) {
    super(JwtErrorCode.KeyNotFound, message);
    this.kid = kid;
  }
}

/** The JavaScript engine lacks a feature the library needs. */
export class JwtHostRequirementError extends JwtError {
  readonly feature: string;

  constructor(feature: string, message: string) {
    super(JwtErrorCode.HostRequirement, message);
    this.feature = feature;
  }
}

/** A 1.x API was called. See the migration guide in the README. */
export class JwtMigrationError extends JwtError {
  constructor(message: string) {
    super(JwtErrorCode.Migration, message);
  }
}
