/**
 * Regressions for the review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17"). Each test names its
 * finding.
 */
import type crypto from 'node:crypto';
import {
  createJWKS,
  decodeUnverified,
  importJWK,
  importPEM,
  JwtAlgorithmError,
  JwtClaimError,
  JwtKeyError,
  sign,
  verify,
  type PayloadShape,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, pem, SECRET_32 } from './helpers/node';

const option = (name: string) => expect.objectContaining({ code: 'ERR_JWT_OPTION_INVALID', option: name });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');

describe('#1 an option out of range in sign is the option\'s fault', () => {
  it.each([
    ['expiresIn', { expiresIn: 1e11 - 1000 }],
    ['notBefore', { notBefore: 1e11 - 1000 }],
    ['now', { now: new Date(2e14) }],
  ])('%s', (name, options) => {
    expect(() => sign({}, SECRET_32, options)).toThrow(option(name));
  });

  it('a millisecond iat in the payload is the payload\'s fault, and named first', () => {
    expect(() => sign({ iat: Date.now() }, SECRET_32, { expiresIn: 5 })).toThrow(expect.objectContaining({ claim: 'iat' }));
  });
});

describe('#2 requiredClaims must be a string or a list of strings', () => {
  const token = sign({ sub: 'u' }, SECRET_32, { now: at(T), expiresIn: 60 });

  it.each([null, 5, {}, [5]])('refuses %p, which would otherwise switch the check off', (requiredClaims) => {
    expect(() => verify(token, SECRET_32, { now: at(T), requiredClaims: requiredClaims as never })).toThrow(option('requiredClaims'));
  });

  it('takes one name as a string, and an empty list as no requirement', () => {
    expect(verify(token, SECRET_32, { now: at(T), requiredClaims: 'sub' as never }).payload.sub).toBe('u');
    expect(() => verify(token, SECRET_32, { now: at(T), requiredClaims: 'jti' as never })).toThrow(JwtClaimError);
    expect(verify(token, SECRET_32, { now: at(T), requiredClaims: [] }).payload.sub).toBe('u');
  });
});

describe('#3 an option that no token could satisfy is the option\'s fault', () => {
  const token = sign({ iss: 'i', aud: 'a' }, SECRET_32, { now: at(T), expiresIn: 60 });

  it.each([
    ['issuer', { issuer: [] }],
    ['audience', { audience: [] }],
    ['maxTokenAge', { maxTokenAge: 0 }],
    ['maxTokenAge', { maxTokenAge: '0.5s' }],
  ])('verify: %s %j', (name, options) => {
    expect(() => verify(token, SECRET_32, { now: at(T), ...options })).toThrow(option(name));
  });

  it('sign: an empty audience list, which verify could never accept', () => {
    expect(() => sign({}, SECRET_32, { audience: [] })).toThrow(option('audience'));
  });
});

describe('#4 sign checks its options before the payload and the key', () => {
  it.each([
    ['a payload that is not an object', () => sign('x' as never, SECRET_32, { expiresIn: 'bogus' }), 'expiresIn'],
    ['a short secret', () => sign({}, 'short', { expiresIn: 'bogus' }), 'expiresIn'],
    ['an object that is not a key', () => sign({}, {} as never, { header: { alg: 'x' } }), 'header.alg'],
    ['a public key', () => sign({}, importPEM(pem(rsa.publicKey), 'RS256'), { keyId: 5 as never }), 'keyId'],
  ])('%s', (_name, call, name) => {
    expect(call).toThrow(option(name));
  });
});

describe('#5 a bad registered claim in the payload is the payload\'s fault', () => {
  it('aud: null with an audience option', () => {
    expect(() => sign({ aud: null }, SECRET_32, { audience: 'y' })).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim: 'aud' }));
  });

  it('a claim set in both places still names the option', () => {
    expect(() => sign({ exp: T }, SECRET_32, { expiresIn: 60 })).toThrow(option('expiresIn'));
    expect(() => sign({ iss: 'a' }, SECRET_32, { issuer: 'b' })).toThrow(option('issuer'));
  });
});

describe('#6 an algorithm that names nothing is a mistake in the call, in every function', () => {
  it.each([
    ['importPEM', () => importPEM(pem(rsa.publicKey), 'RS999' as never)],
    ['importPEM, before the PEM is looked at', () => importPEM(5 as never, 'RS999' as never)],
    ['importPEM without one', () => importPEM(pem(rsa.publicKey), undefined as never)],
    ['importJWK', () => importJWK(jwkOf(rsa.publicKey), 'RS999' as never)],
    ['importJWK, before the JWK is looked at', () => importJWK(5 as never, 'RS999' as never)],
    ['createJWKS', () => createJWKS({ keys: [] }, { algorithm: 'RS999' as never })],
    ['sign', () => sign({}, SECRET_32, { algorithm: 'RS999' as never })],
    ['verify', () => verify(sign({}, SECRET_32), SECRET_32, { algorithm: 'RS999' as never })],
  ])('%s', (_name, call) => {
    expect(call).toThrow(option('algorithm'));
  });

  it('a real algorithm that does not fit stays an algorithm or key error', () => {
    expect(() => importPEM(pem(rsa.publicKey), 'HS256')).toThrow(JwtKeyError);
    expect(() => importJWK({ ...jwkOf(rsa.publicKey), alg: 'RS256' }, 'RS384')).toThrow(JwtKeyError);
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { algorithm: 'HS512' })).toThrow(JwtAlgorithmError);
  });
});

describe('#7 the payload type cannot contradict the registered claims', () => {
  const token = sign({ sub: 'u', roles: ['admin'] }, SECRET_32, { now: at(T), expiresIn: 60 });

  it('compile-time checks (npm run typecheck), with the run-time values they describe', () => {
    const { payload } = verify<{ sub: string; roles: string[] }>(token, SECRET_32, { now: at(T) });
    const sub: string = payload.sub;
    const exp: number | undefined = payload.exp;
    // @ts-expect-error the payload is frozen, and its type says so
    expect(() => (payload.sub = 'x')).toThrow(TypeError);
    // @ts-expect-error exp is a number of seconds, never a Date
    expect(verify<{ exp: Date }>(token, SECRET_32, { now: at(T) }).payload.exp).toBe(T + 60);
    // @ts-expect-error nor a string
    expect(typeof decodeUnverified<{ iat: string }>(token).payload.iat).toBe('number');
    const narrowed: string = verify<{ aud: string }>(sign({ aud: 'a' }, SECRET_32), SECRET_32, { audience: 'a' }).payload.aud;
    // A generic of the caller's own passes its type through with PayloadShape.
    const read = <P extends PayloadShape<P>>(t: string) => verify<P>(t, SECRET_32, { now: at(T) }).payload;
    const roles: string[] = read<{ roles: string[] }>(token).roles;
    expect([sub, exp, narrowed, roles]).toEqual(['u', T + 60, 'a', ['admin']]);
  });
});

describe('#9 RSA signing is blinded when a random source exists', () => {
  const key = importPEM(pem(rsa.privateKey), 'RS256');

  it('draws random numbers for RS256 when crypto.getRandomValues is there', () => {
    const spy = jest.spyOn(globalThis.crypto, 'getRandomValues');
    try {
      const token = sign({ a: 1 }, key);
      expect(spy).toHaveBeenCalled();
      expect(verify(token, importPEM(pem(rsa.publicKey), 'RS256')).payload.a).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('still signs RS256, unblinded and identically, without one', () => {
    const blinded = sign({ a: 1 }, key, { now: at(T) });
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto') as PropertyDescriptor;
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });
    try {
      // PKCS#1 v1.5 is deterministic: blinding changes the computation, not the signature.
      expect(sign({ a: 1 }, key, { now: at(T) })).toBe(blinded);
    } finally {
      Object.defineProperty(globalThis, 'crypto', saved);
    }
  });

  it('reports a private key that does not match its public key either way', () => {
    const other = nodeKeyPair('rsa1024');
    const mixed = { ...jwkOf(rsa.privateKey), d: (jwkOf(other.privateKey).d as string) };
    delete (mixed as Record<string, unknown>).p;
    delete (mixed as Record<string, unknown>).q;
    delete (mixed as Record<string, unknown>).dp;
    delete (mixed as Record<string, unknown>).dq;
    delete (mixed as Record<string, unknown>).qi;
    const bad = importJWK(mixed, 'RS256');
    expect(() => sign({}, bad)).toThrow(/does not match its public key/);
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto') as PropertyDescriptor;
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });
    try {
      expect(() => sign({}, bad)).toThrow(/does not match its public key/);
    } finally {
      Object.defineProperty(globalThis, 'crypto', saved);
    }
  });
});

describe('#10 what an unverified token says reaches error messages escaped', () => {
  const injected = 'x"\n2026-10-17T00:00:00Z INFO login ok user=admin\u001b[2J';
  const messageOf = (call: () => unknown): string => {
    try {
      call();
      return '';
    } catch (error) {
      return (error as Error).message;
    }
  };
  /** No raw line break or escape character: a log line cannot be forged with it. */
  const clean = (message: string) => message.length > 0 && !message.includes('\n') && !message.includes('\u001b');

  it('alg', () => {
    const token = `${b64u(JSON.stringify({ alg: injected }))}.${b64u('{}')}.AAAA`;
    expect(() => verify(token, SECRET_32)).toThrow(JwtAlgorithmError);
    expect(clean(messageOf(() => verify(token, SECRET_32)))).toBe(true);
  });

  it('kid', () => {
    const set = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid: 'k1' }] });
    const token = `${b64u(JSON.stringify({ alg: 'ES256', kid: injected }))}.${b64u('{}')}.AAAA`;
    expect(() => verify(token, set)).toThrow(/^No key in the set has kid "x\\"\\n/);
    expect(clean(messageOf(() => verify(token, set)))).toBe(true);
  });
});

describe('#13 options are checked before the token is read — every kind of them', () => {
  const token = sign({}, SECRET_32, { now: at(T), expiresIn: 60 });
  const forged = `${token.slice(0, token.lastIndexOf('.'))}.AAAA`;

  it.each<[string, object]>([
    ['algorithm', { algorithm: 'none' }],
    ['allowShortSecret', { allowShortSecret: 'yes' }],
    ['ignoreExpiration', { ignoreExpiration: 1 }],
    ['ignoreNotBefore', { ignoreNotBefore: 'true' }],
    ['maxTokenAge', { maxTokenAge: 'soon' }],
    ['typ', { typ: 5 }],
    ['requiredClaims', { requiredClaims: 5 }],
    ['now', { now: 'today' }],
  ])('%s', (name, options) => {
    for (const bad of [forged, 'not a token']) {
      expect(() => verify(bad, SECRET_32, options as never)).toThrow(option(name));
    }
  });

  it('names an inherited option, and a header that does not serialize', () => {
    const inherited = Object.create(Object.create(null, { maxAge: { value: 1, enumerable: true } })) as object;
    expect(() => verify(token, SECRET_32, inherited)).toThrow(option('maxAge'));
    expect(() => sign({}, SECRET_32, { header: { x: BigInt(1) } })).toThrow(option('header'));
  });
});
