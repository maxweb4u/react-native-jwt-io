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

/** The registered claims' types, as `verify` checks them at run time. */
interface RegisteredClaims {
  iss: string;
  sub: string;
  aud: string | readonly string[];
  exp: number;
  nbf: number;
  iat: number;
  jti: string;
}

/**
 * What a payload type may say: anything about the caller's own claims, but a
 * registered claim only as its checked type or narrower (`sub: string`,
 * `aud: string`) — never `exp: Date`, which would compile and fail at run time.
 * Use it to pass a payload type through a generic of your own:
 * `function read<T extends PayloadShape<T>>(token: string) { return verify<T>(token, key); }`.
 */
export type PayloadShape<T> = { [K in keyof T]: K extends keyof RegisteredClaims ? RegisteredClaims[K] : unknown };

/**
 * `TPayload` describes the claims the caller expects and adds them to the
 * registered ones, so `exp`, `sub` and the rest stay typed: with
 * `verify<{ roles: string[] }>`, `payload.roles` and `payload.exp` both work.
 * Everything is read-only, as the object is frozen. Only the registered claims
 * are checked at run time; the rest is the caller's assertion.
 */
export interface DecodedJwt<TPayload = JwtPayload> {
  readonly header: JwtHeader;
  readonly payload: JwtPayload & Readonly<TPayload>;
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
