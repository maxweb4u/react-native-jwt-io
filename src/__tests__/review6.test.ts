/**
 * Regressions for the third review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17, third round"): the second
 * round's fixes with mutation testing, RFC conformance with Hermes 0.74, and
 * hostile input with the public API. Each test names its finding.
 */
import crypto from 'node:crypto';
import {
  createJWKS,
  decodeUnverified,
  getExpiration,
  importJWK,
  importPEM,
  isExpired,
  JwtClaimError,
  JwtError,
  JwtHostRequirementError,
  JwtKeyError,
  JwtMalformedError,
  JwtOptionError,
  sign,
  verify,
} from '../index';
import { type Jwk, type JwkSet } from '../types/jwt';
import { b64u, nodeKeyPair, pem, SECRET_32 } from './helpers/node';

const rsa = nodeKeyPair('rsa');
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

/** An HS256 token over `payload` (JSON text) and `header`, signed with SECRET_32. */
function hs256(payload: string, header = '{"alg":"HS256","typ":"JWT"}'): string {
  const input = `${b64u(header)}.${b64u(payload)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', SECRET_32).update(input).digest())}`;
}

function withCrypto(descriptor: PropertyDescriptor, body: () => void): void {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto') as PropertyDescriptor;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, ...descriptor });
  try {
    body();
  } finally {
    Object.defineProperty(globalThis, 'crypto', saved);
  }
}
const source = (getRandomValues: (array: Uint8Array) => unknown) => ({ value: { getRandomValues }, writable: true });

const nested = (depth: number): unknown => JSON.parse(`${'['.repeat(depth)}${']'.repeat(depth)}`);

describe('#1 deep nesting is a library error, never a RangeError', () => {
  /** What `body` returns, or the error it throws — which must be a JwtError. */
  const outcome = (body: () => unknown): unknown => {
    try {
      return body();
    } catch (error) {
      expect(error).toBeInstanceOf(JwtError);
      return error;
    }
  };

  it.each([3000, 5000, 20_000])('sign, payload at depth %i', (depth) => {
    const token = outcome(() => sign({ a: nested(depth) }, SECRET_32));
    if (typeof token === 'string') {
      expect(() => verify(token, SECRET_32)).not.toThrow(RangeError);
    }
  });

  it.each([5000, 20_000])('sign, options.header at depth %i', (depth) => {
    const token = outcome(() => sign({}, SECRET_32, { header: { x: nested(depth) } }));
    expect(typeof token === 'string' || token instanceof JwtOptionError).toBe(true);
  });

  it('verify and decodeUnverified read deep JSON without a reviver, or say it is too deep', () => {
    const token = hs256(`{"a":${'['.repeat(10_000)}${']'.repeat(10_000)}}`);
    for (const read of [() => decodeUnverified(token), () => verify(token, SECRET_32)]) {
      const result = outcome(read);
      if (result instanceof Error) {
        expect(result).toBeInstanceOf(JwtMalformedError);
        expect(result.message).toMatch(/nested too deeply/);
      }
    }
  });

  it('still drops __proto__ at every depth', () => {
    const { payload } = decodeUnverified(hs256('{"a":[{"b":{"__proto__":{"x":1}}}],"__proto__":{"admin":true}}'));
    expect(Object.prototype.hasOwnProperty.call(payload, '__proto__')).toBe(false);
    expect((payload as { admin?: unknown }).admin).toBeUndefined();
    const inner = (payload.a as { b: object }[])[0]?.b as object;
    expect(Object.prototype.hasOwnProperty.call(inner, '__proto__')).toBe(false);
    expect(Object.getPrototypeOf(inner)).toBe(Object.prototype);
  });
});

describe('#2 a toJSON that throws something other than an Error', () => {
  it.each([null, undefined, 'text', 5])('throws %p', (thrown) => {
    const bad = {
      toJSON() {
        throw thrown;
      },
    };
    expect(() => sign({ a: bad }, SECRET_32)).toThrow(JwtClaimError);
    expect(() => sign({}, SECRET_32, { header: { x: bad } })).toThrow(JwtOptionError);
  });
});

describe('#3 a time in milliseconds is refused in reading as in signing', () => {
  const ms = Date.now() - 3_600_000;

  it.each(['exp', 'nbf', 'iat'])('%s', (name) => {
    const token = hs256(`{"${name}":${ms}}`);
    expect(() => verify(token, SECRET_32)).toThrow(/looks like milliseconds/);
    expect(() => decodeUnverified(token)).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim: name }));
  });

  it('isExpired and getExpiration, which read exp alone', () => {
    const token = hs256(`{"exp":${ms}}`);
    expect(() => isExpired(token)).toThrow(/looks like milliseconds/);
    expect(() => getExpiration(token)).toThrow(/looks like milliseconds/);
    expect(isExpired(hs256('{"exp":1e11}'))).toBe(false);
  });

  it('sign names a millisecond iat before the exp computed from it', () => {
    expect(() => sign({ iat: ms, exp: ms + 60_000 }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'iat' }));
  });
});

describe('#4 claim mismatch messages are escaped and bounded', () => {
  const evil = `a\u2028FAKE LOG LINE\u0085\u009b31m\u202e${'x'.repeat(20_000)}`;

  it.each<[string, object, object]>([
    ['iss', { iss: evil }, { issuer: 'good' }],
    ['aud', { aud: evil }, { audience: 'good' }],
    ['sub', { sub: evil }, { subject: 'good' }],
  ])('%s', (_, payload, options) => {
    const token = sign(payload, SECRET_32);
    let message = '';
    try {
      verify(token, SECRET_32, options);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message.length).toBeLessThan(200);
    expect(message).not.toMatch(/[\u2028\u0085\u009b\u202e]/);
    expect(message).toContain('\\u2028');
  });

  it('typ', () => {
    const token = sign({}, SECRET_32, { header: { typ: evil } });
    expect(() => verify(token, SECRET_32, { typ: 'JWT' })).toThrow(/^Unexpected header "typ" "a\\u2028FAKE/);
  });
});

describe('#7 createJWKS checks its options before the set', () => {
  it('an unknown algorithm with a malformed set', () => {
    expect(() => createJWKS(null as unknown as JwkSet, { algorithm: 'RS999' as 'RS256' })).toThrow(JwtOptionError);
    expect(() => createJWKS({ keys: [] }, { bogus: 1 } as object)).toThrow(JwtOptionError);
  });
});

describe('#8 options are read once', () => {
  const counting = (options: object) => {
    const reads: Record<string, number> = {};
    const proxy = new Proxy(options, {
      get(target, name, receiver) {
        reads[String(name)] = (reads[String(name)] ?? 0) + 1;
        return Reflect.get(target, name, receiver) as unknown;
      },
    });
    return { proxy, reads };
  };

  it('verify', () => {
    const { proxy, reads } = counting({ algorithm: 'HS256', issuer: 'i', audience: 'a', subject: 's', typ: 'JWT', maxTokenAge: '1h' });
    verify(sign({ iss: 'i', aud: 'a', sub: 's' }, SECRET_32), SECRET_32, proxy);
    for (const name of ['algorithm', 'issuer', 'audience', 'subject', 'typ', 'maxTokenAge']) {
      expect([name, reads[name]]).toEqual([name, 1]);
    }
  });

  it('sign', () => {
    const { proxy, reads } = counting({ algorithm: 'HS256' });
    sign({}, SECRET_32, proxy);
    expect(reads.algorithm).toBe(1);
  });
});

describe('#9 an own __proto__ key in a payload to sign is dropped, whatever the build does with a spread', () => {
  it('is not in the token, and is not the payload copy’s prototype', () => {
    const payload = JSON.parse('{"__proto__":{"admin":true,"iat":5,"iss":"evil"},"sub":"x"}') as object;
    const token = sign(payload, SECRET_32, { now: new Date(1_700_000_000_000) });
    const json = Buffer.from(token.split('.')[1] as string, 'base64url').toString();
    expect(json).not.toContain('__proto__');
    expect(json).not.toContain('admin');
    expect(JSON.parse(json)).toEqual({ sub: 'x', iat: 1_700_000_000 });
    expect(() => sign(payload, SECRET_32, { issuer: 'good' })).not.toThrow();
  });
});

describe('#12 a broken random source never hangs RSA signing or blames the key', () => {
  const rs = importPEM(pem(rsa.privateKey), 'RS256');
  const ps = importPEM(pem(rsa.privateKey), 'PS256');
  const rsPublic = importPEM(pem(rsa.publicKey), 'RS256');
  const psPublic = importPEM(pem(rsa.publicKey), 'PS256');

  it('one that fills the array but returns nothing (a common jest setup)', () => {
    withCrypto(
      source((array) => {
        crypto.randomFillSync(array);
      }),
      () => {
        expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
        expect(() => sign({}, ps)).toThrow(JwtHostRequirementError);
      },
    );
  });

  it('one that returns a plain array', () => {
    withCrypto(
      source((array) => Array.from(crypto.randomFillSync(array))),
      () => {
        expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
        expect(() => sign({}, ps)).toThrow(JwtHostRequirementError);
      },
    );
  });

  it('one whose numbers never fall below the modulus (blinding would loop forever)', () => {
    let counter = 0;
    withCrypto(
      source((array) => {
        array.fill(0xff);
        array[array.length - 1] = counter++ & 0xff;
        return array;
      }),
      () => {
        expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
        expect(verify(sign({}, ps), psPublic).header.alg).toBe('PS256');
      },
    );
  });

  it('one that fills only the first array', () => {
    let first = true;
    withCrypto(
      source((array) => {
        if (first) {
          crypto.randomFillSync(array);
          first = false;
        }
        return array;
      }),
      () => {
        expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
      },
    );
  });

  it('one with a quota below a modulus', () => {
    withCrypto(
      source((array) => {
        if (array.length > 64) {
          throw new Error('quota');
        }
        return crypto.randomFillSync(array);
      }),
      () => {
        expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
        expect(verify(sign({}, ps), psPublic).header.alg).toBe('PS256');
      },
    );
  });

  it.each<[string, PropertyDescriptor]>([
    [
      'a crypto getter that throws',
      {
        get() {
          throw new Error('getter boom');
        },
      },
    ],
    [
      'a getRandomValues getter that throws',
      {
        value: Object.defineProperty({}, 'getRandomValues', {
          get() {
            throw new Error('getter boom');
          },
        }),
      },
    ],
  ])('%s', (_, descriptor) => {
    withCrypto(descriptor, () => {
      expect(verify(sign({}, rs), rsPublic).header.alg).toBe('RS256');
      expect(() => sign({}, ps)).toThrow(JwtHostRequirementError);
    });
  });

  it('PS256 without any getRandomValues names the engine, not a broken polyfill', () => {
    withCrypto({ value: undefined, writable: true }, () => {
      expect(() => sign({}, ps)).toThrow(/which this JavaScript engine does not provide/);
    });
    withCrypto(source((array) => array), () => {
      expect(() => sign({}, ps)).toThrow(/does not produce random bytes/);
    });
  });

  it('a working source still blinds: it draws a modulus-sized number', () => {
    const lengths: number[] = [];
    const real = globalThis.crypto;
    withCrypto(
      source((array) => {
        lengths.push(array.length);
        return real.getRandomValues(array);
      }),
      () => {
        sign({}, rs);
      },
    );
    expect(lengths.filter((length) => length === 256).length).toBeGreaterThanOrEqual(2);
  });
});

describe('#13 a JWK literal may carry the registered members it does not use', () => {
  it('compiles and imports', () => {
    const jwk: Jwk = {
      ...jwkOf(rsa.publicKey),
      alg: 'RS256',
      x5c: ['MIIB'],
      x5t: 'abc',
      'x5t#S256': 'def',
      x5u: 'https://example.com/cert',
      ext: true,
    };
    expect(importJWK(jwk).algorithm).toBe('RS256');
    expect(createJWKS({ keys: [{ ...jwk, kid: 'k', oth: [] }] }).skipped).toEqual([]);
  });
});

describe('#14 messages escape bidirectional and invisible characters', () => {
  it.each(['\u202e', '\u2066', '\u200f', '\u061c', '\ufeff', '\u200b', '\u007f', '\u009f'])('U+%s', (char) => {
    const token = hs256('{}', JSON.stringify({ alg: 'HS256', kid: `evil${char}next` }));
    const set = createJWKS({ keys: [{ kty: 'oct', k: b64u(SECRET_32), alg: 'HS256', kid: 'other' }] });
    let message = '';
    try {
      verify(token, set);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain(`\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
    expect(message).not.toContain(char);
  });

  it('the neighbours are left alone', () => {
    const token = hs256('{}', JSON.stringify({ alg: 'HS256', kid: 'a~b\u00a0c' }));
    const set = createJWKS({ keys: [{ kty: 'oct', k: b64u(SECRET_32), alg: 'HS256', kid: 'other' }] });
    expect(() => verify(token, set)).toThrow('No key in the set has kid "a~b\u00a0c".');
  });
});

describe('every failure here is a JwtError', () => {
  it('sanity', () => {
    expect(new JwtKeyError('x')).toBeInstanceOf(JwtError);
  });
});
