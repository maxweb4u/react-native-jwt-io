import { type Algorithm } from './algorithm';

/** Seconds, or a string such as `'90s'`, `'15m'`, `'2h'`, `'7d'`. */
export type Duration = number | string;

interface SecretOptions {
  /**
   * For a bare string or `Uint8Array` secret: which HMAC, HS256 by default.
   * An imported key carries its own algorithm; passing a different one is an
   * error. In `verify` the token's `alg` must equal it too, for a key set as
   * for a single key. See memory_bank/adr/ADR-003-one-key-one-algorithm.md.
   */
  readonly algorithm?: Algorithm | undefined;
  /**
   * Accept an HMAC secret shorter than the hash output (RFC 7518 §3.2). For
   * legacy issuers whose secret you do not control; never for new secrets.
   */
  readonly allowShortSecret?: boolean | undefined;
}

export interface SignOptions extends SecretOptions {
  /** Sets `exp` this long after `iat`. */
  readonly expiresIn?: Duration | undefined;
  /** Sets `nbf` this long after `iat`. */
  readonly notBefore?: Duration | undefined;
  readonly issuer?: string | undefined;
  readonly audience?: string | readonly string[] | undefined;
  readonly subject?: string | undefined;
  readonly jwtId?: string | undefined;
  /** Header `kid`. Defaults to the key's `kid`, if it has one. */
  readonly keyId?: string | undefined;
  /** Extra header parameters. `alg`, `crit` and `b64` cannot be set here. */
  readonly header?: Readonly<Record<string, unknown>> | undefined;
  /** Do not add `iat`. By default `iat` is the signing time; an `iat` already in the payload is kept either way. */
  readonly noTimestamp?: boolean | undefined;
  /** The signing time. Defaults to now. */
  readonly now?: Date | undefined;
}

export interface ClockOptions {
  /** Allowed clock skew when comparing time claims. Default 0. */
  readonly clockTolerance?: Duration | undefined;
  /** The current time. Defaults to now. */
  readonly now?: Date | undefined;
}

export interface VerifyOptions extends SecretOptions, ClockOptions {
  /** `iss` must equal one of these. */
  readonly issuer?: string | readonly string[] | undefined;
  /** `aud` must contain at least one of these. */
  readonly audience?: string | readonly string[] | undefined;
  /** `sub` must equal this. */
  readonly subject?: string | undefined;
  /** Header `typ` must match, ignoring case; `JWT` and `application/JWT` are the same (RFC 7515 §4.1.9). */
  readonly typ?: string | undefined;
  /** These claims must be present. */
  readonly requiredClaims?: readonly string[] | undefined;
  /** The token must be younger than this, measured from `iat`, which then becomes required. */
  readonly maxTokenAge?: Duration | undefined;
  /** Skip the `exp` check. The signature is still verified. */
  readonly ignoreExpiration?: boolean | undefined;
  /** Skip the `nbf` check. The signature is still verified. */
  readonly ignoreNotBefore?: boolean | undefined;
}
