import { signBytes } from '../crypto/backend';
import { JwtClaimError, JwtOptionError } from '../errors/errors';
import { assertSecretStrength, type KeyInput, resolveKey } from '../keys/resolveKey';
import { type SignOptions } from '../types/options';
import { base64UrlEncode } from '../utils/base64';
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
  // Options first, whatever the payload and the key: a mistake in the call is
  // a JwtOptionError, not hidden behind a payload or key error.
  const opts: SignOptions = options ?? {};
  assertKnownOptions(opts, SIGN_OPTIONS);
  assertAlgorithmOption(opts.algorithm);
  const allowShortSecret = booleanOption(opts.allowShortSecret, 'allowShortSecret');
  const noTimestamp = booleanOption(opts.noTimestamp, 'noTimestamp');
  const now = Math.floor(currentSeconds(opts.now));
  if (now > MAX_PLAUSIBLE_NUMERIC_DATE) {
    throw new JwtOptionError('now', `The "now" option is ${now} seconds since 1970, which no signing time can be.`);
  }
  const expiresIn = durationOption(opts.expiresIn, 'expiresIn');
  const notBefore = durationOption(opts.notBefore, 'notBefore');
  const issuer = stringOption(opts.issuer, 'issuer');
  const subject = stringOption(opts.subject, 'subject');
  const jwtId = stringOption(opts.jwtId, 'jwtId');
  const audience = audienceOption(opts.audience);
  const keyId = stringOption(opts.keyId, 'keyId');
  const extraHeader = headerOption(opts.header);

  if (!isPlainObject(payload)) {
    throw new JwtClaimError('payload', 'The payload must be a plain object.');
  }
  const claims: Record<string, unknown> = { ...payload };
  // The payload as given, before options add to it: a bad aud or a
  // millisecond iat is the payload's fault, whatever the options say.
  validateRegisteredClaims(claims);
  assertPlausibleTimes(claims);

  const resolved = resolveKey(key, opts.algorithm);
  assertSecretStrength(resolved, allowShortSecret);

  if (claims.iat === undefined && !noTimestamp) {
    claims.iat = now;
  }
  const base = typeof claims.iat === 'number' ? claims.iat : now;
  setRelative(claims, 'exp', base, expiresIn, 'expiresIn');
  setRelative(claims, 'nbf', base, notBefore, 'notBefore');
  setOnce(claims, 'iss', issuer, 'issuer');
  setOnce(claims, 'sub', subject, 'subject');
  setOnce(claims, 'jti', jwtId, 'jwtId');
  setOnce(claims, 'aud', audience, 'audience');

  const header: Record<string, unknown> = { alg: resolved.algorithm, typ: 'JWT', ...extraHeader };
  const kid = keyId ?? resolved.kid;
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
    throw new JwtOptionError('header', 'The header does not serialize to the header that was built (a toJSON method?).');
  }
  // verify refuses these when they are not strings; sign must not issue such a token.
  for (const name of STRING_HEADER) {
    if (headerEcho[name] !== undefined && typeof headerEcho[name] !== 'string') {
      throw new JwtOptionError(`header.${name}`, `The header "${name}" must be a string.`);
    }
  }
  const payloadText = serialize(claims, 'payload');
  const payloadEcho = parseJson(payloadText);
  if (!isPlainObject(payloadEcho)) {
    throw new JwtClaimError('payload', 'The payload does not serialize to a JSON object (a toJSON method?).');
  }
  validateRegisteredClaims(payloadEcho);
  assertPlausibleTimes(payloadEcho);

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
  const value = base + offset;
  if (value > MAX_PLAUSIBLE_NUMERIC_DATE) {
    throw new JwtOptionError(option, `options.${option} puts "${name}" at ${value} seconds since 1970, past any plausible date.`);
  }
  claims[name] = value;
}

/** iat first: a millisecond iat also pushes the exp and nbf computed from it. */
function assertPlausibleTimes(claims: Record<string, unknown>): void {
  for (const name of ['iat', 'exp', 'nbf'] as const) {
    const value = claims[name];
    if (typeof value === 'number' && value > MAX_PLAUSIBLE_NUMERIC_DATE) {
      throw new JwtClaimError(
        name,
        `"${name}" is ${value}, which looks like milliseconds or an overflow. JWT times are seconds: use Math.floor(Date.now() / 1000).`,
      );
    }
  }
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
  // Not empty: verify refuses an empty audience list, so a token with aud [] could never be accepted.
  return [...stringList(value, 'audience', { nonEmpty: true })];
}

/** options.header: a plain object without the parameters only the library sets. */
function headerOption(value: unknown): Record<string, unknown> {
  if (value === undefined) {
    return {};
  }
  if (!isPlainObject(value)) {
    throw new JwtOptionError('header', 'options.header must be a plain object.');
  }
  const header: Record<string, unknown> = {};
  for (const [name, parameter] of Object.entries(value)) {
    if (RESERVED_HEADER.includes(name)) {
      throw new JwtOptionError(`header.${name}`, `The header "${name}" cannot be set through options.header.`);
    }
    if (name !== '__proto__') {
      header[name] = parameter;
    }
  }
  return header;
}

/** The header comes from options, the payload is claims: each failure is reported as what it is. */
function serialize(value: Record<string, unknown>, name: 'header' | 'payload'): string {
  const fail = (message: string): Error => (name === 'header' ? new JwtOptionError(name, message) : new JwtClaimError(name, message));
  let text: string | undefined;
  try {
    text = JSON.stringify(value);
  } catch (error) {
    throw fail(`The ${name} cannot be serialized to JSON: ${(error as Error).message}`);
  }
  if (typeof text !== 'string') {
    throw fail(`The ${name} does not serialize to JSON.`);
  }
  return text;
}
