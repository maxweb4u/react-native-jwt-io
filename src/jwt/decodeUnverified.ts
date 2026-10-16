import { type DecodedJwt, type JwtPayload } from '../types/jwt';
import { parseToken } from './parse';

/**
 * Reads the header and payload **without checking the signature or any claim**.
 * Safe for display and for scheduling a refresh; never for deciding who the
 * caller is. Use `verify` for that.
 */
export function decodeUnverified<TPayload = JwtPayload>(token: string): DecodedJwt<TPayload> {
  const { header, payload } = parseToken(token);
  return Object.freeze({ header, payload: payload as JwtPayload & TPayload });
}
