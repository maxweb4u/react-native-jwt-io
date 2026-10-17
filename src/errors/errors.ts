/**
 * Every deliberate failure in the library is one of these classes.
 *
 * Callers can branch on `code`, which survives duplicate copies of the package
 * in one bundle, where `instanceof` does not.
 *
 * See memory_bank/engineering/typescript.md#errors.
 */

export const JwtErrorCode = Object.freeze({
  Malformed: 'ERR_JWT_MALFORMED',
  Algorithm: 'ERR_JWT_ALGORITHM',
  SignatureInvalid: 'ERR_JWT_SIGNATURE_INVALID',
  Expired: 'ERR_JWT_EXPIRED',
  NotBefore: 'ERR_JWT_NOT_BEFORE',
  ClaimInvalid: 'ERR_JWT_CLAIM_INVALID',
  OptionInvalid: 'ERR_JWT_OPTION_INVALID',
  KeyInvalid: 'ERR_JWT_KEY_INVALID',
  KeyNotFound: 'ERR_JWT_KEY_NOT_FOUND',
  HostRequirement: 'ERR_JWT_HOST_REQUIREMENT',
  Migration: 'ERR_JWT_MIGRATION',
} as const);
export type JwtErrorCode = (typeof JwtErrorCode)[keyof typeof JwtErrorCode];

export class JwtError extends Error {
  readonly code: JwtErrorCode;

  constructor(code: JwtErrorCode, message: string) {
    super(message);
    // `name` comes from the prototype (see `named` below), not from
    // `new.target.name`: a minifier renames classes, and in a release build
    // every error would be called "u".
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

/** `alg` is `none`, unsupported, or differs from the key's single algorithm or `options.algorithm`. A missing `alg` is a `JwtMalformedError`. */
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

/**
 * An option is unknown, of the wrong type, or out of range — a mistake in the
 * calling code, not in the token. Its own class so that an app which treats
 * every `JwtError` from `verify` as "sign the user out" can still tell a bug
 * from a bad token. See memory_bank/adr/ADR-008-option-errors.md.
 */
export class JwtOptionError extends JwtError {
  /** The option's name, such as `clockTolerance` or `header.kid`; `options` for the object as a whole. */
  readonly option: string;

  constructor(option: string, message: string) {
    super(JwtErrorCode.OptionInvalid, message);
    this.option = option;
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

/**
 * Sets each class's `name` as a string literal, which survives minification.
 * Metro's release build mangles class names, so `new.target.name` would read
 * "u". Not enumerable, like `Error.prototype.name`.
 */
function named(classes: Record<string, { prototype: object }>): void {
  for (const [name, errorClass] of Object.entries(classes)) {
    Object.defineProperty(errorClass.prototype, 'name', { value: name, writable: true, configurable: true });
  }
}

named({
  JwtError,
  JwtMalformedError,
  JwtAlgorithmError,
  JwtSignatureError,
  JwtExpiredError,
  JwtNotBeforeError,
  JwtClaimError,
  JwtOptionError,
  JwtKeyError,
  JwtKeyNotFoundError,
  JwtHostRequirementError,
  JwtMigrationError,
});
