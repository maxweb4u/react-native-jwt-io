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
  isExpired,
  JwtClaimError,
  JwtError,
  JwtKeyError,
  JwtMalformedError,
  JwtOptionError,
  sign,
  verify,
} from '../index';
import { b64u, SECRET_32 } from './helpers/node';

/** An HS256 token over `payload` (JSON text) and `header`, signed with SECRET_32. */
function hs256(payload: string, header = '{"alg":"HS256","typ":"JWT"}'): string {
  const input = `${b64u(header)}.${b64u(payload)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', SECRET_32).update(input).digest())}`;
}

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
