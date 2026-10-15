/**
 * NumericDate and duration helpers. A NumericDate is seconds since the epoch,
 * never milliseconds. See memory_bank/domain/validation.md#time-claims.
 */

/** Above this a NumericDate is almost certainly milliseconds: 1e11 seconds is the year 5138. */
export const MAX_PLAUSIBLE_NUMERIC_DATE = 1e11;

export function toNumericDate(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

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
 * A duration in whole seconds: a non-negative number of seconds, or a string
 * such as `'90s'`, `'15m'`, `'2h'`, `'7d'`, `'1 week'`. Returns null when the
 * input is neither.
 */
export function parseDuration(input: number | string): number | null {
  if (typeof input === 'number') {
    return Number.isFinite(input) && input >= 0 ? Math.floor(input) : null;
  }
  if (typeof input !== 'string') {
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
  return Math.floor(Number(match[1]) * (UNIT_SECONDS[name] as number));
}
