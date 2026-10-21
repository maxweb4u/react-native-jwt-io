/**
 * The last public-API pass before 2.0.0 (memory_bank/backlog.md, "API review
 * before 2.0.0"): option mistakes are their own error class, and a payload
 * generic keeps the registered claims typed. Both are contracts that cannot
 * change after 2.0.0 without a major release.
 */
import crypto from 'node:crypto';
import {
  createJWKS,
  decodeUnverified,
  importPEM,
  isExpired,
  JwtAlgorithmError,
  JwtClaimError,
  JwtError,
  JwtErrorCode,
  JwtOptionError,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { nodeKeyPair, pem, SECRET_32 } from './helpers/node';

const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const option = (name: string) => expect.objectContaining({ code: 'ERR_JWT_OPTION_INVALID', option: name });

describe('JwtOptionError', () => {
  it('is a JwtError with its own code and the option name, and not a claim error', () => {
    const error = new JwtOptionError('clockTolerance', 'x');
    expect(error).toBeInstanceOf(JwtError);
    expect(error).not.toBeInstanceOf(JwtClaimError);
    expect([error.name, error.code, error.option]).toEqual(['JwtOptionError', JwtErrorCode.OptionInvalid, 'clockTolerance']);
    expect(JwtErrorCode.OptionInvalid).toBe('ERR_JWT_OPTION_INVALID');
    expect(Object.keys(error)).toEqual(['code', 'option']);
  });
});

describe('a mistake in the call is a JwtOptionError, in every function', () => {
  const token = sign({ iss: 'i' }, SECRET_32, { now: at(T), expiresIn: 60 });
  const rsa = nodeKeyPair('rsa');

  it.each([
    ['sign: an unknown option', () => sign({}, SECRET_32, { expiresin: 60 } as never), 'expiresin'],
    ['sign: options that are not an object', () => sign({}, SECRET_32, 'HS256' as never), 'options'],
    ['sign: a bad duration', () => sign({}, SECRET_32, { expiresIn: '10 fortnights' }), 'expiresIn'],
    ['sign: a claim set in the payload and in options', () => sign({ iss: 'a' }, SECRET_32, { issuer: 'b' }), 'issuer'],
    ['sign: a reserved header in options.header', () => sign({}, SECRET_32, { header: { alg: 'none' } }), 'header.alg'],
    ['sign: a header that must be a string', () => sign({}, SECRET_32, { header: { kid: 5 } }), 'header.kid'],
    ['sign: an unknown algorithm name', () => sign({}, SECRET_32, { algorithm: 'HS999' as never }), 'algorithm'],
    ['verify: an unknown option', () => verify(token, SECRET_32, { maxAge: 5 } as never), 'maxAge'],
    ['verify: an invalid now', () => verify(token, SECRET_32, { now: new Date('x') }), 'now'],
    ['verify: a clockTolerance over a day', () => verify(token, SECRET_32, { clockTolerance: '2d' }), 'clockTolerance'],
    ['verify: an issuer option that is not a string', () => verify(token, SECRET_32, { issuer: 5 as never }), 'issuer'],
    ['verify: a subject option that is not a string', () => verify(token, SECRET_32, { subject: 5 as never }), 'subject'],
    ['verify: a typ option that is not a string', () => verify(token, SECRET_32, { typ: 5 as never }), 'typ'],
    ['verify: requiredClaims that are not strings', () => verify(token, SECRET_32, { requiredClaims: [5] as never }), 'requiredClaims'],
    ['verify: an unknown algorithm name', () => verify(token, SECRET_32, { algorithm: 'none' as never }), 'algorithm'],
    ['isExpired: an unknown option', () => isExpired(token, { ignoreExpiration: true } as never), 'ignoreExpiration'],
    ['importPEM: an unknown option', () => importPEM(pem(rsa.publicKey), 'RS256', { keyId: 'k' } as never), 'keyId'],
    ['importPEM: a kid that is not a string', () => importPEM(pem(rsa.publicKey), 'RS256', { kid: 5 as never }), 'kid'],
    ['createJWKS: an unknown option', () => createJWKS({ keys: [] }, { alg: 'RS256' } as never), 'alg'],
  ])('%s', (_name, call, name) => {
    expect(call).toThrow(JwtOptionError);
    expect(call).toThrow(option(name));
  });

  it.each([
    ['verify: ignoreExpiration as a string', () => verify(token, SECRET_32, { ignoreExpiration: 'true' as never }), 'ignoreExpiration'],
    ['verify: ignoreNotBefore as a number', () => verify(token, SECRET_32, { ignoreNotBefore: 1 as never }), 'ignoreNotBefore'],
    ['verify: allowShortSecret as a string', () => verify(token, 'short', { allowShortSecret: 'yes' as never }), 'allowShortSecret'],
    ['sign: noTimestamp as a string', () => sign({}, SECRET_32, { noTimestamp: 'false' as never }), 'noTimestamp'],
    ['sign: allowShortSecret as null', () => sign({}, 'short', { allowShortSecret: null as never }), 'allowShortSecret'],
  ])('a switch must be a boolean — %s', (_name, call, name) => {
    expect(call).toThrow(option(name));
  });

  it('is reported before the token is read, so a bad token cannot hide it', () => {
    const forged = `${token.slice(0, token.lastIndexOf('.'))}.AAAA`;
    for (const bad of [token, forged, 'not a token']) {
      expect(() => verify(bad, SECRET_32, { issuer: 5 as never })).toThrow(option('issuer'));
      expect(() => verify(bad, SECRET_32, { clockTolerance: '2d' })).toThrow(option('clockTolerance'));
    }
    const noExp = sign({}, SECRET_32);
    expect(() => isExpired(noExp, { now: new Date('x') })).toThrow(option('now'));
    expect(() => isExpired('not a token', { clockTolerance: -1 })).toThrow(option('clockTolerance'));
  });

  it('createJWKS refuses an unknown algorithm name instead of skipping every key it applies to', () => {
    const jwk = rsa.publicKey.export({ format: 'jwk' }) as Jwk;
    expect(createJWKS({ keys: [jwk] }, { algorithm: 'RS256' }).keys).toHaveLength(1);
    expect(() => createJWKS({ keys: [jwk] }, { algorithm: 'RS999' as never })).toThrow(option('algorithm'));
  });

  it('a real algorithm that does not fit is still a JwtAlgorithmError', () => {
    expect(() => verify(token, SECRET_32, { algorithm: 'HS512' })).toThrow(JwtAlgorithmError);
    expect(() => sign({}, SECRET_32, { algorithm: 'RS256' })).toThrow(JwtAlgorithmError);
  });

  it('what the token says is still a JwtClaimError', () => {
    expect(() => verify(token, SECRET_32, { now: at(T), issuer: 'other' })).toThrow(JwtClaimError);
    expect(() => verify(token, SECRET_32, { now: at(T), requiredClaims: ['jti'] })).toThrow(JwtClaimError);
    expect(() => verify(sign({}, SECRET_32, { noTimestamp: true }), SECRET_32, { maxTokenAge: 60 })).toThrow(JwtClaimError);
    expect(() => sign({ exp: '1700000000' }, SECRET_32)).toThrow(JwtClaimError);
    expect(() => sign({ big: BigInt(1) }, SECRET_32)).toThrow(JwtClaimError);
  });

  it('an app can tell a bug in its call from a bad token', () => {
    const outcome = (call: () => unknown): string => {
      try {
        call();
        return 'ok';
      } catch (error) {
        if (error instanceof JwtOptionError) {
          return 'bug';
        }
        return error instanceof JwtError ? 'sign out' : 'crash';
      }
    };
    expect(outcome(() => verify(token, SECRET_32, { maxAge: '1h' } as never))).toBe('bug');
    expect(outcome(() => verify(token, crypto.randomBytes(32), { now: at(T) }))).toBe('sign out');
    expect(outcome(() => verify(token, SECRET_32, { now: at(T) }))).toBe('ok');
  });
});

describe('a payload generic adds to the registered claims', () => {
  const token = sign({ sub: 'u1', roles: ['admin'] }, SECRET_32, { now: at(T), expiresIn: 60 });

  it('keeps exp, sub and the caller’s own claims typed', () => {
    const { payload } = verify<{ roles: string[] }>(token, SECRET_32, { now: at(T) });
    // Compile-time checks: each assignment fails to type-check if the claim is not typed so.
    const roles: string[] = payload.roles;
    const exp: number | undefined = payload.exp;
    const sub: string | undefined = payload.sub;
    expect([roles, exp, sub]).toEqual([['admin'], T + 60, 'u1']);

    const decoded = decodeUnverified<{ roles: string[] }>(token).payload;
    const iat: number | undefined = decoded.iat;
    expect([decoded.roles, iat]).toEqual([['admin'], T]);
  });

  it('lets the caller narrow a registered claim', () => {
    const { payload } = verify<{ sub: string }>(token, SECRET_32, { now: at(T) });
    const sub: string = payload.sub;
    expect(sub).toBe('u1');
  });
});
