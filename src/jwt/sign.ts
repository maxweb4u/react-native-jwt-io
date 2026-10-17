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
  // Options first, whatever the payload and the key: a mistake in the call is
  // a JwtOptionError, not hidden behind a payload or key error.
  const opts: SignOptions = options ?? {};
  assertKnownOptions(opts, SIGN_OPTIONS);
  // Read once: a getter must not answer one value to the check and another to the use.
  const algorithm = opts.algorithm;
  assertAlgorithmOption(algorithm);
  const allowShortSecret = booleanOption(opts.allowShortSecret, 'allowShortSecret');
  const noTimestamp = booleanOption(opts.noTimestamp, 'noTimestamp');
  const now = Math.floor(currentSeconds(opts.now));
  if (now > MAX_PLAUSIBLE_NUMERIC_DATE) {
    throw new JwtOptionError('now', `The "now" option is ${now} seconds since 1970, which no signing time can be.`);
  }
  const expiresIn = durationOption(opts.expiresIn, 'expiresIn');
  if (expiresIn === 0) {
    // exp = iat: verify refuses the token the moment it is issued.
    throw new JwtOptionError('expiresIn', `"expiresIn" is ${describeValue(opts.expiresIn)}, under a second: the token would expire as it is issued.`);
  }
  const notBefore = durationOption(opts.notBefore, 'notBefore');
  const issuer = stringOption(opts.issuer, 'issuer');
  const subject = stringOption(opts.subject, 'subject');
  const jwtId = stringOption(opts.jwtId, 'jwtId');
  const audience = audienceOption(opts.audience);
  const keyId = stringOption(opts.keyId, 'keyId');
  const extraHeader = headerOption(opts.header);
  if (keyId !== undefined && extraHeader.kid !== undefined && extraHeader.kid !== keyId) {
    throw new JwtOptionError('keyId', 'Both options.keyId and options.header.kid are set, to different values; use one.');
  }

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
  // The payload as given, before options add to it: a bad aud or a
  // millisecond iat is the payload's fault, whatever the options say.
  validateRegisteredClaims(claims);

  const resolved = resolveKey(key, algorithm);
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
  // What the caller says beats what the key carries.
  const kid = keyId ?? (extraHeader.kid as string | undefined) ?? resolved.kid;
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
  // As serialized, here with the other options rather than after the payload
  // and the key: a toJSON, a BigInt or a cycle, and the parameters verify
  // requires to be strings.
  const echo = reparse(serialize(header, 'header'), 'header');
  if (!isPlainObject(echo) || RESERVED_HEADER.some((name) => name in echo)) {
    throw new JwtOptionError('header', 'options.header does not serialize to a plain object without alg, crit and b64 (a toJSON method?).');
  }
  for (const name of STRING_HEADER) {
    if (echo[name] !== undefined && typeof echo[name] !== 'string') {
      throw new JwtOptionError(`header.${name}`, `The header "${name}" must be a string.`);
    }
  }
  return header;
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
