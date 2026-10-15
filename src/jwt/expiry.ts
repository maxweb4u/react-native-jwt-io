import { type ClockOptions } from '../types/options';
import { fromNumericDate } from '../utils/time';
import { currentSeconds, durationOption, numericClaim } from './claims';
import { parseToken } from './parse';

/**
 * Whether the token's `exp` has passed. A token without `exp` never expires.
 * The signature is **not** checked: this is for deciding when to refresh.
 */
export function isExpired(token: string, options: ClockOptions = {}): boolean {
  const exp = numericClaim(parseToken(token).payload, 'exp');
  if (exp === undefined) {
    return false;
  }
  const now = currentSeconds((options ?? {}).now);
  const tolerance = durationOption((options ?? {}).clockTolerance, 'clockTolerance') ?? 0;
  return now - tolerance >= exp;
}

/** The token's `exp` as a Date, or null when it has none. The signature is **not** checked. */
export function getExpiration(token: string): Date | null {
  const exp = numericClaim(parseToken(token).payload, 'exp');
  return exp === undefined ? null : fromNumericDate(exp);
}
