import { signBytes } from '../crypto/backend';
import { JwtClaimError } from '../errors/errors';
import { assertSecretStrength, type KeyInput, resolveKey } from '../keys/resolveKey';
import { type SignOptions } from '../types/options';
import { base64UrlEncode } from '../utils/base64';
import { isPlainObject } from '../utils/json';
import { MAX_PLAUSIBLE_NUMERIC_DATE, toNumericDate } from '../utils/time';
import { utf8Encode } from '../utils/utf8';
import { durationOption } from './claims';

const RESERVED_HEADER = ['alg', 'crit', 'b64'];

/**
 * Signs `payload` and returns a compact JWS.
 *
 * `iat` is set to the signing time unless `noTimestamp` is given. Time claims
 * are seconds; a value that looks like milliseconds is refused.
 */
export function sign(payload: Record<string, unknown>, key: KeyInput, options: SignOptions = {}): string {
  if (!isPlainObject(payload)) {
    throw new JwtClaimError('payload', 'The payload must be a plain object.');
  }
  const resolved = resolveKey(key, options.algorithm);
  assertSecretStrength(resolved, options.allowShortSecret);
  const claims: Record<string, unknown> = { ...payload };

  for (const name of ['exp', 'nbf', 'iat'] as const) {
    const value = claims[name];
    if (value === undefined) {
      continue;
    }
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new JwtClaimError(name, `"${name}" must be a NumericDate (a number of seconds).`);
    }
    if (value > MAX_PLAUSIBLE_NUMERIC_DATE) {
      throw new JwtClaimError(name, `"${name}" is ${value}, which looks like milliseconds. JWT times are seconds: use Math.floor(Date.now() / 1000).`);
    }
  }

  const now = toNumericDate(options.now ?? new Date());
  if (claims.iat === undefined && options.noTimestamp !== true) {
    claims.iat = now;
  }
  const base = typeof claims.iat === 'number' ? claims.iat : now;
  setRelative(claims, 'exp', base, durationOption(options.expiresIn, 'expiresIn'), 'expiresIn');
  setRelative(claims, 'nbf', base, durationOption(options.notBefore, 'notBefore'), 'notBefore');
  setOnce(claims, 'iss', options.issuer, 'issuer');
  setOnce(claims, 'sub', options.subject, 'subject');
  setOnce(claims, 'jti', options.jwtId, 'jwtId');
  setOnce(claims, 'aud', typeof options.audience === 'object' ? [...options.audience] : options.audience, 'audience');

  const header: Record<string, unknown> = { alg: resolved.algorithm, typ: 'JWT' };
  for (const [name, value] of Object.entries(options.header ?? {})) {
    if (RESERVED_HEADER.includes(name)) {
      throw new JwtClaimError(`header.${name}`, `The header "${name}" cannot be set through options.header.`);
    }
    if (name !== '__proto__') {
      header[name] = value;
    }
  }
  const kid = options.keyId ?? resolved.kid;
  if (kid !== undefined) {
    header.kid = kid;
  }

  const signingInput = `${encodeJson(header, 'header')}.${encodeJson(claims, 'payload')}`;
  const signature = signBytes(resolved.algorithm, resolved.material, utf8Encode(signingInput));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

function setRelative(
  claims: Record<string, unknown>,
  name: 'exp' | 'nbf',
  base: number,
  offset: number | undefined,
  option: string,
): void {
  if (offset === undefined) {
    return;
  }
  if (claims[name] !== undefined) {
    throw new JwtClaimError(name, `Both payload.${name} and options.${option} are set; use one.`);
  }
  claims[name] = base + offset;
}

function setOnce(claims: Record<string, unknown>, name: string, value: unknown, option: string): void {
  if (value === undefined) {
    return;
  }
  if (claims[name] !== undefined) {
    throw new JwtClaimError(name, `Both payload.${name} and options.${option} are set; use one.`);
  }
  claims[name] = value;
}

function encodeJson(value: Record<string, unknown>, name: string): string {
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch (error) {
    throw new JwtClaimError(name, `The ${name} cannot be serialized to JSON: ${(error as Error).message}`);
  }
  return base64UrlEncode(utf8Encode(text as string));
}
