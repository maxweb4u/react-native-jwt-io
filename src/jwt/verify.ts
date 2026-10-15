import { verifyBytes } from '../crypto/backend';
import { JwtAlgorithmError, JwtMalformedError, JwtSignatureError } from '../errors/errors';
import { isJwtKeySet, type JwtKeySet, selectKey } from '../keys/jwks';
import { assertSecretStrength, type KeyInput, resolveKey } from '../keys/resolveKey';
import { isAlgorithm } from '../types/algorithm';
import { type DecodedJwt, type JwtPayload } from '../types/jwt';
import { type VerifyOptions } from '../types/options';
import { validateClaims } from './claims';
import { parseToken } from './parse';

/**
 * Verifies the signature, then the claims, and returns the decoded token.
 * Throws a `JwtError` subclass at the first failure; never returns a failed result.
 *
 * The algorithm comes from the key, never from the token's header:
 * a bare secret is HS256 unless `options.algorithm` says otherwise.
 * See memory_bank/domain/validation.md#order.
 */
export function verify<TPayload = JwtPayload>(
  token: string,
  key: KeyInput | JwtKeySet,
  options: VerifyOptions = {},
): DecodedJwt<TPayload> {
  const { header, payload, signingInput, signature } = parseToken(token);
  const opts: VerifyOptions = options ?? {};

  const alg = header.alg as string;
  if (alg.toLowerCase() === 'none') {
    throw new JwtAlgorithmError('Unsigned tokens (alg "none") are never accepted.');
  }
  if (!isAlgorithm(alg)) {
    throw new JwtAlgorithmError(`Unsupported algorithm "${alg}".`);
  }
  // RFC 7515 §4.1.11: an extension we do not understand must not be ignored.
  if (header.crit !== undefined) {
    throw new JwtMalformedError('The header lists critical extensions ("crit"), which this library does not support.');
  }
  if ('b64' in header) {
    throw new JwtMalformedError('Unencoded payloads ("b64", RFC 7797) are not supported.');
  }

  const chosen = isJwtKeySet(key) ? selectKey(key, header.kid, alg) : key;
  // `algorithm` constrains a key set too: a token whose key in the set is
  // for another algorithm fails, rather than the option being ignored.
  const resolved = resolveKey(chosen, opts.algorithm);
  if (resolved.algorithm !== alg) {
    throw new JwtAlgorithmError(`The token is signed with ${alg}, but the key is for ${resolved.algorithm}.`);
  }
  assertSecretStrength(resolved, opts.allowShortSecret);
  if (!verifyBytes(alg, resolved.material, signingInput, signature)) {
    throw new JwtSignatureError();
  }

  validateClaims(header, payload, opts);
  return Object.freeze({ header, payload: payload as TPayload });
}
