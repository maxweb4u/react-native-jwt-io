/**
 * SC-14 and the shape of the public API. Most of this file is checked by
 * `tsc` (npm run typecheck), not by Jest: a promise slipping into the core,
 * or a key import without an algorithm, is a type error here.
 */
import * as api from '../index';
import { decodeUnverified, getExpiration, importPEM, isExpired, sign, verify } from '../index';
import { nodeKeyPair, pem, SECRET_32 } from './helpers/node';

type NotPromise<T> = T extends PromiseLike<unknown> ? never : T;
const assertSync = <T>(value: NotPromise<T>): T => value;

it('nothing in the core returns a promise (SC-14)', () => {
  const token = assertSync(sign({ sub: 'x' }, SECRET_32));
  const verified = assertSync(verify<{ sub: string }>(token, SECRET_32));
  const sub: string = verified.payload.sub;
  assertSync(decodeUnverified(token));
  assertSync(isExpired(token));
  assertSync(getExpiration(token));
  assertSync(importPEM(pem(nodeKeyPair('P-256').publicKey), 'ES256'));
  expect(sub).toBe('x');
  for (const value of Object.values(api)) {
    if (typeof value === 'function' && !/Error$/.test(value.name)) {
      expect(value.constructor.name).not.toBe('AsyncFunction');
    }
  }
});

it('exports exactly the documented surface', () => {
  expect(Object.keys(api).sort()).toEqual(
    [
      'Algorithm',
      'JwtAlgorithmError',
      'JwtClaimError',
      'JwtError',
      'JwtErrorCode',
      'JwtExpiredError',
      'JwtHostRequirementError',
      'JwtKeyError',
      'JwtKeyNotFoundError',
      'JwtMalformedError',
      'JwtMigrationError',
      'JwtNotBeforeError',
      'JwtSignatureError',
      'createJWKS',
      'decode',
      'decodeUnverified',
      'default',
      'encode',
      'getExpiration',
      'hexToBytes',
      'importJWK',
      'importPEM',
      'isExpired',
      'sign',
      'verify',
    ].sort(),
  );
  // `decode` exists only as a tombstone: it throws, it never decodes.
  expect(() => api.decode()).toThrow(api.JwtMigrationError);
});
