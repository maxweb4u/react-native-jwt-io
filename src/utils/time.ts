/**
 * NumericDate and duration helpers. A NumericDate is seconds since the epoch,
 * never milliseconds. See memory_bank/domain/validation.md#time-claims.
 */

/** Above this a NumericDate is almost certainly milliseconds: 1e11 seconds is the year 5138. */
export const MAX_PLAUSIBLE_NUMERIC_DATE = 1e11;

/** The JavaScript Date range, in seconds (ECMA-262 §21.4.1.1). Beyond it no Date exists to report the time. */
export const MAX_DATE_SECONDS = 8.64e12;

/** The longest duration accepted, for `expiresIn`, `notBefore` and `maxTokenAge`: as long as the longest plausible NumericDate. */
export const MAX_DURATION_SECONDS = MAX_PLAUSIBLE_NUMERIC_DATE;

/**
 * The largest `clockTolerance`: one day. Clock skew is seconds to minutes; a
 * tolerance of years is not skew, it is `exp` switched off.
 */
export const MAX_CLOCK_TOLERANCE_SECONDS = 86400;

export function fromNumericDate(seconds: number): Date {
  return new Date(seconds * 1000);
}

const UNIT_SECONDS: Record<string, number> = {
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  d: 86400,
  day: 86400,
  days: 86400,
  w: 604800,
  week: 604800,
  weeks: 604800,
};

const DURATION = /^(\d+(?:\.\d+)?)\s*([a-z]+)$/i;

/**
 * A duration in whole seconds, rounded down: a non-negative number of
 * seconds, or a string such as `'90s'`, `'15m'`, `'2.5h'`, `'7d'`, `'1 week'`.
 * Returns null when the input is neither, or longer than
 * `MAX_DURATION_SECONDS`.
 */
export function parseDuration(input: number | string): number | null {
  if (typeof input === 'number') {
    return Number.isFinite(input) && input >= 0 && input <= MAX_DURATION_SECONDS ? Math.floor(input) : null;
  }
  if (typeof input !== 'string' || input.length > 64) {
    return null;
  }
  const match = DURATION.exec(input.trim());
  if (!match) {
    return null;
  }
  const name = (match[2] as string).toLowerCase();
  // An own-property check, so `'5 constructor'` is not a duration.
  if (!Object.prototype.hasOwnProperty.call(UNIT_SECONDS, name)) {
    return null;
  }
  // In integers, not floats: 2.05 * 60 is 122.99999999999999 in floating point.
  const [whole, fraction = ''] = (match[1] as string).split('.') as [string, string?];
  const scaled = BigInt(whole + fraction) * BigInt(UNIT_SECONDS[name] as number);
  const seconds = scaled / BigInt(`1${'0'.repeat(fraction.length)}`);
  return seconds <= BigInt(MAX_DURATION_SECONDS) ? Number(seconds) : null;
}
