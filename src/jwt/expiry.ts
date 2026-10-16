import { type ClockOptions } from '../types/options';
import { assertKnownOptions } from '../utils/options';
import { fromNumericDate } from '../utils/time';
import { clockToleranceOption, currentSeconds, numericClaim } from './claims';
import { parseToken } from './parse';

/**
 * Whether the token's `exp` has passed. A token without `exp` never expires.
 * The signature is **not** checked: this is for deciding when to refresh.
 */
export function isExpired(token: string, options: ClockOptions = {}): boolean {
  const opts: ClockOptions = options ?? {};
  assertKnownOptions(opts, ['clockTolerance', 'now']);
  // Options first, so a mistake in them shows for a token without exp too.
  const now = currentSeconds(opts.now);
  const tolerance = clockToleranceOption(opts.clockTolerance);
  const exp = numericClaim(parseToken(token).payload, 'exp');
  return exp !== undefined && now - tolerance >= exp;
}

/** The token's `exp` as a Date, or null when it has none. The signature is **not** checked. */
export function getExpiration(token: string): Date | null {
  const exp = numericClaim(parseToken(token).payload, 'exp');
  return exp === undefined ? null : fromNumericDate(exp);
}
