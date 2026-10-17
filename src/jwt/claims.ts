import { JwtClaimError, JwtExpiredError, JwtNotBeforeError, JwtOptionError } from '../errors/errors';
import { type JwtHeader, type JwtPayload } from '../types/jwt';
import { type Duration, type VerifyOptions } from '../types/options';
import { describeValue } from '../utils/describe';
import { fromNumericDate, MAX_CLOCK_TOLERANCE_SECONDS, MAX_DATE_SECONDS, parseDuration } from '../utils/time';

/** `verify`'s claim options, checked and normalized before the token is read. */
export interface ClaimRules {
  readonly now: number;
  readonly tolerance: number;
  readonly maxTokenAge: { readonly seconds: number; readonly label: Duration } | undefined;
  readonly issuers: readonly string[] | undefined;
  readonly audiences: readonly string[] | undefined;
  readonly subject: string | undefined;
  readonly typ: string | undefined;
  readonly requiredClaims: readonly string[];
  readonly ignoreExpiration: boolean;
  readonly ignoreNotBefore: boolean;
}

/**
 * Checks every claim option up front: a mistake in the call is a
 * `JwtOptionError` whatever the token is, not only once a valid token
 * reaches the claim checks — otherwise an expired or forged token would hide it.
 */
export function claimRules(options: VerifyOptions): ClaimRules {
  const maxAge = durationOption(options.maxTokenAge, 'maxTokenAge');
  if (options.subject !== undefined && typeof options.subject !== 'string') {
    throw new JwtOptionError('subject', 'The "subject" option must be a string.');
  }
  if (options.typ !== undefined && typeof options.typ !== 'string') {
    throw new JwtOptionError('typ', 'The "typ" option must be a string.');
  }
  return {
    now: currentSeconds(options.now),
    tolerance: clockToleranceOption(options.clockTolerance),
    maxTokenAge: maxAge === undefined ? undefined : { seconds: maxAge, label: options.maxTokenAge as Duration },
    issuers: options.issuer === undefined ? undefined : stringList(options.issuer, 'issuer'),
    audiences: options.audience === undefined ? undefined : stringList(options.audience, 'audience'),
    subject: options.subject,
    typ: options.typ,
    requiredClaims: stringList(options.requiredClaims ?? [], 'requiredClaims'),
    ignoreExpiration: booleanOption(options.ignoreExpiration, 'ignoreExpiration'),
    ignoreNotBefore: booleanOption(options.ignoreNotBefore, 'ignoreNotBefore'),
  };
}

/**
 * Claim rules, applied only after the signature holds.
 * See memory_bank/domain/validation.md#time-claims and #other-claims.
 */
export function validateClaims(header: JwtHeader, payload: JwtPayload, rules: ClaimRules): void {
  const { now, tolerance } = rules;

  // Compared against the exact time, not the second it falls in: a
  // fractional exp must not live up to a second longer than it says.
  const exp = numericClaim(payload, 'exp');
  if (exp !== undefined && !rules.ignoreExpiration && now - tolerance >= exp) {
    throw new JwtExpiredError(`The token expired at ${fromNumericDate(exp).toISOString()}.`, fromNumericDate(exp));
  }
  const nbf = numericClaim(payload, 'nbf');
  if (nbf !== undefined && !rules.ignoreNotBefore && now + tolerance < nbf) {
    throw new JwtNotBeforeError(`The token is not valid before ${fromNumericDate(nbf).toISOString()}.`, fromNumericDate(nbf));
  }
  const iat = numericClaim(payload, 'iat');
  // iat is only checked when the caller asks for an age limit, as in jose:
  // a device clock a few seconds behind the issuer's would otherwise refuse
  // every fresh token, and exp and nbf already bound the token's validity.
  if (rules.maxTokenAge !== undefined) {
    if (iat === undefined) {
      throw new JwtClaimError('iat', '"maxTokenAge" was given, but the token has no "iat".');
    }
    if (iat > now + tolerance) {
      throw new JwtClaimError('iat', 'The token was issued in the future ("iat" is later than now).');
    }
    // Like exp: at exactly iat + maxTokenAge the token is too old.
    const until = iat + rules.maxTokenAge.seconds;
    if (now - tolerance >= until) {
      throw new JwtExpiredError(`The token is older than maxTokenAge (${rules.maxTokenAge.label}).`, fromNumericDate(until));
    }
  }

  if (rules.issuers !== undefined && !rules.issuers.includes(payload.iss as string)) {
    throw new JwtClaimError('iss', `Unexpected issuer ${describeValue(payload.iss)}.`);
  }
  if (rules.audiences !== undefined) {
    const expected = rules.audiences;
    const actual = typeof payload.aud === 'string' ? [payload.aud] : (payload.aud ?? []);
    if (!actual.some((aud) => expected.includes(aud))) {
      throw new JwtClaimError('aud', `Unexpected audience ${describeValue(payload.aud)}.`);
    }
  }
  if (rules.subject !== undefined && payload.sub !== rules.subject) {
    throw new JwtClaimError('sub', `Unexpected subject ${describeValue(payload.sub)}.`);
  }
  if (rules.typ !== undefined && (typeof header.typ !== 'string' || normalizeTyp(header.typ) !== normalizeTyp(rules.typ))) {
    throw new JwtClaimError('typ', `Unexpected header "typ" ${describeValue(header.typ)}.`);
  }
  for (const claim of rules.requiredClaims) {
    if (!Object.prototype.hasOwnProperty.call(payload, claim)) {
      throw new JwtClaimError(claim, `The token has no "${claim}" claim.`);
    }
  }
}

/**
 * A switch must be a boolean: `ignoreExpiration: 'false'` read as truthy
 * would switch a check off, and read as false would hide the mistake.
 */
export function booleanOption(value: unknown, name: string): boolean {
  if (value !== undefined && typeof value !== 'boolean') {
    throw new JwtOptionError(name, `"${name}" must be true or false; got ${describeValue(value)}.`);
  }
  return value === true;
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
    throw new JwtOptionError('now', 'The "now" option must be a valid Date.');
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

/**
 * A time claim must be a finite number when present — a string `exp` is not
 * "no expiry" — and inside the range a Date can represent.
 */
export function numericClaim(payload: JwtPayload, name: 'exp' | 'nbf' | 'iat'): number | undefined {
  const value = payload[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new JwtClaimError(name, `"${name}" must be a NumericDate (a number of seconds).`);
  }
  if (Math.abs(value) > MAX_DATE_SECONDS) {
    throw new JwtClaimError(name, `"${name}" is ${value}, outside the range of dates (±${MAX_DATE_SECONDS} seconds).`);
  }
  return value;
}

/** `clockTolerance` in seconds, 0 when absent; at most a day ({@link MAX_CLOCK_TOLERANCE_SECONDS}). */
export function clockToleranceOption(value: Duration | undefined): number {
  const seconds = durationOption(value, 'clockTolerance') ?? 0;
  if (seconds > MAX_CLOCK_TOLERANCE_SECONDS) {
    throw new JwtOptionError(
      'clockTolerance',
      `"clockTolerance" is ${seconds} seconds; the most is ${MAX_CLOCK_TOLERANCE_SECONDS} (a day). Clock skew is seconds or minutes — to accept expired tokens, use ignoreExpiration.`,
    );
  }
  return seconds;
}

export function durationOption(value: Duration | undefined, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const seconds = parseDuration(value);
  if (seconds === null) {
    throw new JwtOptionError(name, `"${name}" must be a number of seconds or a duration such as '30s', '15m', '2h', '7d'.`);
  }
  return seconds;
}

/** An option that is a string or an array of strings, as an array; anything else is a caller error. */
export function stringList(value: unknown, name: string): readonly string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value as string[];
  }
  throw new JwtOptionError(name, `"${name}" must be a string or an array of strings.`);
}

/**
 * RFC 7515 §4.1.9: a `typ` without a `/` stands for `application/<typ>`.
 * Media types compare case-insensitively.
 */
function normalizeTyp(typ: string): string {
  const lower = typ.toLowerCase();
  return lower.includes('/') ? lower : `application/${lower}`;
}
