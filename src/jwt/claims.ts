import { JwtClaimError, JwtExpiredError, JwtNotBeforeError } from '../errors/errors';
import { type JwtHeader, type JwtPayload } from '../types/jwt';
import { type Duration, type VerifyOptions } from '../types/options';
import { fromNumericDate, parseDuration, toNumericDate } from '../utils/time';

/**
 * Claim rules, applied only after the signature holds.
 * See memory_bank/domain/validation.md#time-claims and #other-claims.
 */
export function validateClaims(header: JwtHeader, payload: JwtPayload, options: VerifyOptions): void {
  const now = toNumericDate(options.now ?? new Date());
  const tolerance = durationOption(options.clockTolerance, 'clockTolerance') ?? 0;

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

  if (options.issuer !== undefined && !list(options.issuer).includes(payload.iss as string)) {
    throw new JwtClaimError('iss', `Unexpected issuer ${JSON.stringify(payload.iss)}.`);
  }
  if (options.audience !== undefined) {
    const expected = list(options.audience);
    const actual = typeof payload.aud === 'string' ? [payload.aud] : Array.isArray(payload.aud) ? payload.aud : [];
    if (!actual.some((aud) => typeof aud === 'string' && expected.includes(aud))) {
      throw new JwtClaimError('aud', `Unexpected audience ${JSON.stringify(payload.aud)}.`);
    }
  }
  if (options.subject !== undefined && payload.sub !== options.subject) {
    throw new JwtClaimError('sub', `Unexpected subject ${JSON.stringify(payload.sub)}.`);
  }
  if (options.typ !== undefined) {
    if (typeof header.typ !== 'string' || normalizeTyp(header.typ) !== normalizeTyp(options.typ)) {
      throw new JwtClaimError('typ', `Unexpected header "typ" ${JSON.stringify(header.typ)}.`);
    }
  }
  for (const claim of options.requiredClaims ?? []) {
    if (!Object.prototype.hasOwnProperty.call(payload, claim)) {
      throw new JwtClaimError(claim, `The token has no "${claim}" claim.`);
    }
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

function list(value: string | readonly string[]): readonly string[] {
  return typeof value === 'string' ? [value] : value;
}

/** RFC 7515 §4.1.9: compare case-insensitively, with the `application/` prefix optional. */
function normalizeTyp(typ: string): string {
  const lower = typ.toLowerCase();
  return lower.startsWith('application/') ? lower.slice('application/'.length) : lower;
}
