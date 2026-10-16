import { type Algorithm } from './algorithm';

/** The JOSE header. Only `alg` is guaranteed; anything else the token carried is kept. */
export interface JwtHeader {
  readonly alg: Algorithm | string;
  readonly typ?: string;
  readonly kid?: string;
  readonly cty?: string;
  readonly crit?: readonly string[];
  readonly [parameter: string]: unknown;
}

/** Registered claims (RFC 7519 §4.1), typed; everything else is `unknown` until the caller narrows it. */
export interface JwtPayload {
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  /** Seconds since the epoch. */
  readonly exp?: number;
  /** Seconds since the epoch. */
  readonly nbf?: number;
  /** Seconds since the epoch. */
  readonly iat?: number;
  readonly jti?: string;
  readonly [claim: string]: unknown;
}

export interface DecodedJwt<TPayload = JwtPayload> {
  readonly header: JwtHeader;
  readonly payload: TPayload;
}

/** A JSON Web Key as it appears in JSON (RFC 7517). Only the members this library reads are typed. */
export interface Jwk {
  readonly kty?: string;
  readonly alg?: string;
  readonly kid?: string;
  readonly use?: string;
  readonly crv?: string;
  readonly n?: string;
  readonly e?: string;
  readonly d?: string;
  readonly x?: string;
  readonly y?: string;
  readonly k?: string;
  readonly [member: string]: unknown;
}

export interface JwkSet {
  readonly keys: readonly Jwk[];
}
