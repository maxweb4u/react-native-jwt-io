import { signBytes } from '../crypto/backend';
import { JwtClaimError } from '../errors/errors';
import { assertSecretStrength, type KeyInput, resolveKey } from '../keys/resolveKey';
import { type SignOptions } from '../types/options';
import { base64UrlEncode } from '../utils/base64';
import { isPlainObject, parseJson } from '../utils/json';
import { assertKnownOptions } from '../utils/options';
import { MAX_PLAUSIBLE_NUMERIC_DATE } from '../utils/time';
import { utf8Encode } from '../utils/utf8';
import { currentSeconds, durationOption, stringList, validateRegisteredClaims } from './claims';

const RESERVED_HEADER = ['alg', 'crit', 'b64'];
const STRING_HEADER = ['typ', 'cty', 'kid'] as const;
const SIGN_OPTIONS = [
  'algorithm',
  'allowShortSecret',
  'expiresIn',
  'notBefore',
  'issuer',
  'audience',
  'subject',
  'jwtId',
  'keyId',
  'header',
  'noTimestamp',
  'now',
];

/**
 * Signs `payload` and returns a compact JWS.
 *
 * `iat` is set to the signing time unless `noTimestamp` is given. Time claims
 * are seconds; a value that looks like milliseconds is refused.
 */
export function sign(payload: object, key: KeyInput, options: SignOptions = {}): string {
  const opts: SignOptions = options ?? {};
  assertKnownOptions(opts, SIGN_OPTIONS, (name, message) => new JwtClaimError(name, message));
  if (!isPlainObject(payload)) {
    throw new JwtClaimError('payload', 'The payload must be a plain object.');
  }
  const resolved = resolveKey(key, opts.algorithm);
  assertSecretStrength(resolved, opts.allowShortSecret);
  const claims: Record<string, unknown> = { ...payload };

  const now = Math.floor(currentSeconds(opts.now));
  if (claims.iat === undefined && opts.noTimestamp !== true) {
    claims.iat = now;
  }
  const base = typeof claims.iat === 'number' ? claims.iat : now;
  setRelative(claims, 'exp', base, durationOption(opts.expiresIn, 'expiresIn'), 'expiresIn');
  setRelative(claims, 'nbf', base, durationOption(opts.notBefore, 'notBefore'), 'notBefore');
  setOnce(claims, 'iss', stringOption(opts.issuer, 'issuer'), 'issuer');
  setOnce(claims, 'sub', stringOption(opts.subject, 'subject'), 'subject');
  setOnce(claims, 'jti', stringOption(opts.jwtId, 'jwtId'), 'jwtId');
  setOnce(claims, 'aud', audienceOption(opts.audience), 'audience');

  if (opts.header !== undefined && !isPlainObject(opts.header)) {
    throw new JwtClaimError('header', 'options.header must be a plain object.');
  }
  const header: Record<string, unknown> = { alg: resolved.algorithm, typ: 'JWT' };
  for (const [name, value] of Object.entries(opts.header ?? {})) {
    if (RESERVED_HEADER.includes(name)) {
      throw new JwtClaimError(`header.${name}`, `The header "${name}" cannot be set through options.header.`);
    }
    if (name !== '__proto__') {
      header[name] = value;
    }
  }
  const kid = stringOption(opts.keyId, 'keyId') ?? resolved.kid;
  if (kid !== undefined) {
    header.kid = kid;
  }

  // Validated as serialized, not as passed: a `toJSON` method or a getter can
  // make JSON.stringify emit something other than what was checked above.
  const headerText = serialize(header, 'header');
  const headerEcho = parseJson(headerText) as Record<string, unknown>;
  if (
    !isPlainObject(headerEcho) ||
    headerEcho.alg !== resolved.algorithm ||
    RESERVED_HEADER.slice(1).some((name) => name in headerEcho)
  ) {
    throw new JwtClaimError('header', 'The header does not serialize to the header that was built (a toJSON method?).');
  }
  // verify refuses these when they are not strings; sign must not issue such a token.
  for (const name of STRING_HEADER) {
    if (headerEcho[name] !== undefined && typeof headerEcho[name] !== 'string') {
      throw new JwtClaimError(`header.${name}`, `The header "${name}" must be a string.`);
    }
  }
  const payloadText = serialize(claims, 'payload');
  const payloadEcho = parseJson(payloadText);
  if (!isPlainObject(payloadEcho)) {
    throw new JwtClaimError('payload', 'The payload does not serialize to a JSON object (a toJSON method?).');
  }
  validateRegisteredClaims(payloadEcho);
  for (const name of ['exp', 'nbf', 'iat'] as const) {
    const value = payloadEcho[name];
    if (typeof value === 'number' && value > MAX_PLAUSIBLE_NUMERIC_DATE) {
      throw new JwtClaimError(
        name,
        `"${name}" is ${value}, which looks like milliseconds or an overflow. JWT times are seconds: use Math.floor(Date.now() / 1000).`,
      );
    }
  }

  const signingInput = `${base64UrlEncode(utf8Encode(headerText))}.${base64UrlEncode(utf8Encode(payloadText))}`;
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

function stringOption(value: unknown, name: string): string | undefined {
  if (value !== undefined && typeof value !== 'string') {
    throw new JwtClaimError(name, `options.${name} must be a string.`);
  }
  return value;
}

function audienceOption(value: unknown): string | string[] | undefined {
  if (value === undefined || typeof value === 'string') {
    return value;
  }
  return [...stringList(value, 'audience')];
}

function serialize(value: Record<string, unknown>, name: string): string {
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch (error) {
    throw new JwtClaimError(name, `The ${name} cannot be serialized to JSON: ${(error as Error).message}`);
  }
  if (typeof text !== 'string') {
    throw new JwtClaimError(name, `The ${name} does not serialize to JSON.`);
  }
  return text;
}
