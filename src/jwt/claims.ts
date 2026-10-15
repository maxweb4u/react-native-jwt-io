import { JwtClaimError, JwtExpiredError, JwtNotBeforeError } from '../errors/errors';
import { type JwtHeader, type JwtPayload } from '../types/jwt';
import { type Duration, type VerifyOptions } from '../types/options';
import { fromNumericDate, parseDuration } from '../utils/time';

/**
 * Claim rules, applied only after the signature holds.
 * See memory_bank/domain/validation.md#time-claims and #other-claims.
 */
export function validateClaims(header: JwtHeader, payload: JwtPayload, options: VerifyOptions): void {
  const now = currentSeconds(options.now);
  const tolerance = durationOption(options.clockTolerance, 'clockTolerance') ?? 0;

  // Compared against the exact time, not the second it falls in: a
  // fractional exp must not live up to a second longer than it says.
  const exp = numericClaim(payload, 'exp');
  if (exp !== undefined && options.ignoreExpiration !== true && now - tolerance >= exp) {
    throw new JwtExpiredError(`The token expired at ${fromNumericDate(exp).toISOString()}.`, fromNumericDate(exp));
  }
  const nbf = numericClaim(payload, 'nbf');
  if (nbf !== undefined && options.ignoreNotBefore !== true && now + tolerance < nbf) {
    throw new JwtNotBeforeError(`The token is not valid before ${fromNumericDate(nbf).toISOString()}.`, fromNumericDate(nbf));
  }
  const iat = numericClaim(payload, 'iat');
  if (iat !== undefined && iat > now + tolerance) {
    throw new JwtClaimError('iat', 'The token was issued in the future ("iat" is later than now).');
  }
  const maxAge = durationOption(options.maxTokenAge, 'maxTokenAge');
  if (maxAge !== undefined) {
    if (iat === undefined) {
      throw new JwtClaimError('iat', '"maxTokenAge" was given, but the token has no "iat".');
    }
    if (now - tolerance > iat + maxAge) {
      throw new JwtExpiredError(`The token is older than maxTokenAge (${options.maxTokenAge}).`, fromNumericDate(iat + maxAge));
    }
  }

  if (options.issuer !== undefined && !stringList(options.issuer, 'issuer').includes(payload.iss as string)) {
    throw new JwtClaimError('iss', `Unexpected issuer ${JSON.stringify(payload.iss)}.`);
  }
  if (options.audience !== undefined) {
    const expected = stringList(options.audience, 'audience');
    const actual = typeof payload.aud === 'string' ? [payload.aud] : (payload.aud ?? []);
    if (!actual.some((aud) => expected.includes(aud))) {
      throw new JwtClaimError('aud', `Unexpected audience ${JSON.stringify(payload.aud)}.`);
    }
  }
  if (options.subject !== undefined && payload.sub !== options.subject) {
    throw new JwtClaimError('sub', `Unexpected subject ${JSON.stringify(payload.sub)}.`);
  }
  if (options.typ !== undefined) {
    if (typeof options.typ !== 'string') {
      throw new JwtClaimError('typ', 'The "typ" option must be a string.');
    }
    if (typeof header.typ !== 'string' || normalizeTyp(header.typ) !== normalizeTyp(options.typ)) {
      throw new JwtClaimError('typ', `Unexpected header "typ" ${JSON.stringify(header.typ)}.`);
    }
  }
  for (const claim of stringList(options.requiredClaims ?? [], 'requiredClaims')) {
    if (!Object.prototype.hasOwnProperty.call(payload, claim)) {
      throw new JwtClaimError(claim, `The token has no "${claim}" claim.`);
    }
  }
}

/**
 * The current time in seconds, exact (not rounded). An invalid `now` is an
 * error: an Invalid Date makes every comparison false, which would switch
 * off every time check.
 */
export function currentSeconds(now: unknown): number {
  if (now === undefined) {
    return Date.now() / 1000;
  }
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new JwtClaimError('now', 'The "now" option must be a valid Date.');
  }
  return now.getTime() / 1000;
}

/**
 * RFC 7519 §4.1: the registered claims have fixed types. Checked wherever a
 * payload is read or written, so the `JwtPayload` type tells the truth.
 */
export function validateRegisteredClaims(payload: Record<string, unknown>): void {
  for (const name of ['iss', 'sub', 'jti'] as const) {
    if (payload[name] !== undefined && typeof payload[name] !== 'string') {
      throw new JwtClaimError(name, `"${name}" must be a string.`);
    }
  }
  const aud = payload.aud;
  if (aud !== undefined && typeof aud !== 'string' && !(Array.isArray(aud) && aud.every((a) => typeof a === 'string'))) {
    throw new JwtClaimError('aud', '"aud" must be a string or an array of strings.');
  }
  for (const name of ['exp', 'nbf', 'iat'] as const) {
    numericClaim(payload, name);
  }
}

/** A time claim must be a finite number when present; a string `exp` is not "no expiry". */
export function numericClaim(payload: JwtPayload, name: 'exp' | 'nbf' | 'iat'): number | undefined {
  const value = payload[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new JwtClaimError(name, `"${name}" must be a NumericDate (a number of seconds).`);
  }
  return value;
}

export function durationOption(value: Duration | undefined, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const seconds = parseDuration(value);
  if (seconds === null) {
    throw new JwtClaimError(name, `"${name}" must be a number of seconds or a duration such as '30s', '15m', '2h', '7d'.`);
  }
  return seconds;
}

/** A string or an array of strings, as an array; anything else is a caller error. */
export function stringList(value: unknown, name: string): readonly string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value as string[];
  }
  throw new JwtClaimError(name, `"${name}" must be a string or an array of strings.`);
}

/** RFC 7515 §4.1.9: compare case-insensitively, with the `application/` prefix optional. */
function normalizeTyp(typ: string): string {
  const lower = typ.toLowerCase();
  return lower.startsWith('application/') ? lower.slice('application/'.length) : lower;
}
