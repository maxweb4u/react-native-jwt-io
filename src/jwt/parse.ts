import { JwtMalformedError } from '../errors/errors';
import { type JwtHeader, type JwtPayload } from '../types/jwt';
import { base64UrlDecode } from '../utils/base64';
import { deepFreeze, isPlainObject, parseJson } from '../utils/json';
import { utf8Decode, utf8Encode } from '../utils/utf8';
import { validateRegisteredClaims } from './claims';

/** Larger tokens are refused before any decoding work. HTTP headers rarely allow more than 16 KiB. */
export const MAX_TOKEN_LENGTH = 65536;

export interface ParsedToken {
  readonly header: JwtHeader;
  readonly payload: JwtPayload;
  readonly signingInput: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * Splits and decodes a compact JWS without verifying it.
 * See memory_bank/domain/token-model.md.
 */
export function parseToken(token: unknown): ParsedToken {
  if (typeof token !== 'string') {
    throw new JwtMalformedError('The token must be a string.');
  }
  if (token.length > MAX_TOKEN_LENGTH) {
    throw new JwtMalformedError(`The token is longer than ${MAX_TOKEN_LENGTH} characters.`);
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwtMalformedError(
      parts.length === 5
        ? 'The token has five segments: it is an encrypted JWE, which is not supported.'
        : `A JWT has three segments separated by dots; this token has ${parts.length}.`,
    );
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = decodeJsonSegment(headerPart, 'header');
  if (typeof header.alg !== 'string' || header.alg.length === 0) {
    throw new JwtMalformedError('The header has no "alg".');
  }
  for (const name of ['typ', 'cty', 'kid'] as const) {
    if (header[name] !== undefined && typeof header[name] !== 'string') {
      throw new JwtMalformedError(`The header "${name}" must be a string.`);
    }
  }
  const payload = decodeJsonSegment(payloadPart, 'payload');
  validateRegisteredClaims(payload);
  const signature = base64UrlDecode(signaturePart);
  if (signature === null) {
    throw new JwtMalformedError('The signature segment is not valid base64url.');
  }
  return {
    // Deeply: a verified `aud` array must not be editable after the check.
    header: deepFreeze(header) as JwtHeader,
    payload: deepFreeze(payload) as JwtPayload,
    // The segments are base64url, so this is ASCII.
    signingInput: utf8Encode(`${headerPart}.${payloadPart}`),
    signature,
  };
}

function decodeJsonSegment(segment: string, name: 'header' | 'payload'): Record<string, unknown> {
  if (segment.length === 0) {
    throw new JwtMalformedError(`The ${name} segment is empty.`);
  }
  const bytes = base64UrlDecode(segment);
  if (bytes === null) {
    throw new JwtMalformedError(`The ${name} segment is not valid base64url.`);
  }
  const text = utf8Decode(bytes);
  if (text === null) {
    throw new JwtMalformedError(`The ${name} is not valid UTF-8.`);
  }
  let value: unknown;
  try {
    value = parseJson(text);
  } catch {
    throw new JwtMalformedError(`The ${name} is not valid JSON.`);
  }
  if (!isPlainObject(value)) {
    throw new JwtMalformedError(`The ${name} must be a JSON object.`);
  }
  return value;
}
