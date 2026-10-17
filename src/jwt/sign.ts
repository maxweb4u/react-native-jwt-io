import { signBytes } from '../crypto/backend';
import { JwtClaimError, JwtOptionError } from '../errors/errors';
import { assertSecretStrength, type KeyInput, resolveKey } from '../keys/resolveKey';
import { type SignOptions } from '../types/options';
import { base64UrlEncode } from '../utils/base64';
import { describeValue } from '../utils/describe';
import { isPlainObject, parseJson } from '../utils/json';
import { assertAlgorithmOption, assertKnownOptions } from '../utils/options';
import { MAX_PLAUSIBLE_NUMERIC_DATE } from '../utils/time';
import { utf8Encode } from '../utils/utf8';
import { booleanOption, currentSeconds, durationOption, stringList, validateRegisteredClaims } from './claims';

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
  assertKnownOptions(opts, SIGN_OPTIONS);
  assertAlgorithmOption(opts.algorithm);
  const allowShortSecret = booleanOption(opts.allowShortSecret, 'allowShortSecret');
  const noTimestamp = booleanOption(opts.noTimestamp, 'noTimestamp');
  if (!isPlainObject(payload)) {
    throw new JwtClaimError('payload', 'The payload must be a plain object.');
  }
  // Own keys one by one, not a spread: Babel's loose object spread (the React
  // Native preset) is Object.assign, which turns an own "__proto__" key into
  // the copy's prototype — iat and iss would be inherited, not serialized.
  const claims: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(payload)) {
    if (name !== '__proto__') {
      claims[name] = value;
    }
  }
  const resolved = resolveKey(key, opts.algorithm);
  assertSecretStrength(resolved, allowShortSecret);

  const now = Math.floor(currentSeconds(opts.now));
  if (claims.iat === undefined && !noTimestamp) {
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
    throw new JwtOptionError('header', 'options.header must be a plain object.');
  }
  const header: Record<string, unknown> = { alg: resolved.algorithm, typ: 'JWT' };
  for (const [name, value] of Object.entries(opts.header ?? {})) {
    if (RESERVED_HEADER.includes(name)) {
      throw new JwtOptionError(`header.${name}`, `The header "${name}" cannot be set through options.header.`);
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
  const headerEcho = reparse(headerText, 'header') as Record<string, unknown>;
  if (
    !isPlainObject(headerEcho) ||
    headerEcho.alg !== resolved.algorithm ||
    RESERVED_HEADER.slice(1).some((name) => name in headerEcho)
  ) {
    throw new JwtOptionError('header', 'The header does not serialize to the header that was built (a toJSON method?).');
  }
  // verify refuses these when they are not strings; sign must not issue such a token.
  for (const name of STRING_HEADER) {
    if (headerEcho[name] !== undefined && typeof headerEcho[name] !== 'string') {
      throw new JwtOptionError(`header.${name}`, `The header "${name}" must be a string.`);
    }
  }
  const payloadText = serialize(claims, 'payload');
  const payloadEcho = reparse(payloadText, 'payload');
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
    throw new JwtOptionError(option, `Both payload.${name} and options.${option} are set; use one.`);
  }
  claims[name] = base + offset;
}

function setOnce(claims: Record<string, unknown>, name: string, value: unknown, option: string): void {
  if (value === undefined) {
    return;
  }
  if (claims[name] !== undefined) {
    throw new JwtOptionError(option, `Both payload.${name} and options.${option} are set; use one.`);
  }
  claims[name] = value;
}

function stringOption(value: unknown, name: string): string | undefined {
  if (value !== undefined && typeof value !== 'string') {
    throw new JwtOptionError(name, `options.${name} must be a string.`);
  }
  return value;
}

function audienceOption(value: unknown): string | string[] | undefined {
  if (value === undefined || typeof value === 'string') {
    return value;
  }
  return [...stringList(value, 'audience')];
}

/** The header comes from options, the payload is claims: each failure is reported as what it is. */
function fail(name: 'header' | 'payload', message: string): Error {
  return name === 'header' ? new JwtOptionError(name, message) : new JwtClaimError(name, message);
}

function serialize(value: Record<string, unknown>, name: 'header' | 'payload'): string {
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch (error) {
    // A toJSON may throw anything, null included.
    const reason = error instanceof Error ? error.message : describeValue(error);
    throw fail(name, `The ${name} cannot be serialized to JSON: ${reason}`);
  }
  if (typeof text !== 'string') {
    throw fail(name, `The ${name} does not serialize to JSON.`);
  }
  return text;
}

/**
 * The serialized text read back. JSON.stringify accepts nesting that parsing
 * cannot take — Hermes parses 512 levels at most — so the echo can fail too.
 */
function reparse(text: string, name: 'header' | 'payload'): unknown {
  try {
    return parseJson(text);
  } catch {
    throw fail(name, `The ${name} is nested too deeply to be read back.`);
  }
}
