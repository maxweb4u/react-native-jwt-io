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

const code = (c: string) => expect.objectContaining({ code: c });
const rsa = nodeKeyPair('rsa');
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
const der = (key: crypto.KeyObject) => key.export({ type: 'spki', format: 'der' });

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

describe('#5 a public key in UTF-16 is refused in either byte order', () => {
  const text = pem(rsa.publicKey);
  const be = (withBom: boolean) => {
    const bytes = Buffer.from(Buffer.from(text, 'utf16le').swap16());
    return new Uint8Array(withBom ? Buffer.concat([Buffer.from([0xfe, 0xff]), bytes]) : bytes);
  };

  it.each([
    ['UTF-16LE', new Uint8Array(Buffer.from(text, 'utf16le'))],
    ['UTF-16BE with a BOM', be(true)],
    ['UTF-16BE without one', be(false)],
  ])('%s', (_, bytes) => {
    expect(() => sign({}, bytes)).toThrow(code('ERR_JWT_KEY_INVALID'));
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

describe('#11 the key-material check stays linear', () => {
  it.each([
    ['spaces', `1${' '.repeat(65_536)}1`],
    ['tabs', `[1${'\t'.repeat(65_536)}1`],
    ['commas', `1${', '.repeat(32_768)}1`],
    ['openers', `${'['.repeat(65_536)}1`],
    ['dump lines', '00000000  30 82\n'.repeat(4096)],
  ])('%s', (_, secret) => {
    const start = Date.now();
    expect(() => sign({}, secret)).not.toThrow(RangeError);
    expect(Date.now() - start).toBeLessThan(1000);
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

describe('#15 importPEM agrees with OpenSSL on the edges', () => {
  const publicPem = pem(rsa.publicKey);

  it('reads a BEGIN line that ends with spaces', () => {
    expect(importPEM(publicPem.replace('-----BEGIN PUBLIC KEY-----', '-----BEGIN PUBLIC KEY-----  '), 'RS256').type).toBe('public');
  });

  it('refuses a broken block rather than reading the next one', () => {
    const broken = '-----BEGIN PRIVATE KEY-----\nAAA-----X\n-----END PRIVATE KEY-----\n';
    expect(() => importPEM(broken + publicPem, 'RS256')).toThrow(/is not complete/);
    expect(() => importPEM(`-----BEGIN PRIVATE KEY-----\n${publicPem}`, 'RS256')).toThrow(/is not complete/);
  });

  it('says what an EC PARAMETERS file is', () => {
    expect(() => importPEM('-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n', 'ES256')).toThrow(/only EC PARAMETERS/);
  });

  it('gives the literal \\n hint with a real newline at the end', () => {
    expect(() => importPEM(`${publicPem.trim().replace(/\n/g, '\\n')}\n`, 'RS256')).toThrow(/the two characters \\n/);
  });
});

describe('#16 more dumps of a key are refused as secrets', () => {
  const bytes = [...der(rsa.publicKey)];
  const hex = (b: number) => `0x${b.toString(16).padStart(2, '0')}`;
  const signed = (b: number) => (b > 127 ? b - 256 : b);
  const lines = (items: string[], perLine: number) =>
    Array.from({ length: Math.ceil(items.length / perLine) }, (_, i) => `  ${items.slice(i * perLine, (i + 1) * perLine).join(', ')}`).join(',\n');
  const python = `b'${bytes
    .map((b) =>
      b === 0x5c ? '\\\\' : b === 0x27 ? "\\'" : b === 9 ? '\\t' : b === 10 ? '\\n' : b === 13 ? '\\r' : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`,
    )
    .join('')}'`;
  const hexdump = (() => {
    const out: string[] = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const row = bytes.slice(offset, offset + 16);
      const pairs = row.map((b) => b.toString(16).padStart(2, '0'));
      const left = pairs.slice(0, 8).join(' ');
      const right = pairs.slice(8).join(' ');
      const text = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
      out.push(`${offset.toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  |${text}|`);
    }
    out.push(bytes.length.toString(16).padStart(8, '0'));
    return out.join('\n');
  })();
  const xxd = (() => {
    const out: string[] = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const row = bytes.slice(offset, offset + 16);
      const groups: string[] = [];
      for (let i = 0; i < row.length; i += 2) {
        groups.push(row.slice(i, i + 2).map((b) => b.toString(16).padStart(2, '0')).join(''));
      }
      const text = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
      out.push(`${offset.toString(16).padStart(8, '0')}: ${groups.join(' ').padEnd(39)}  ${text}`);
    }
    return out.join('\n');
  })();
  const jwk = jwkOf(rsa.publicKey);

  it.each([
    ['xxd -i', `unsigned char rsa2048_der[] = {\n${lines(bytes.map(hex), 12)}\n};\nunsigned int rsa2048_der_len = ${bytes.length};\n`],
    ['Go %#v', `[]byte{${bytes.map(hex).join(', ')}}`],
    ['Java new byte[]', `new byte[]{${bytes.map(signed).join(', ')}}`],
    ['Python repr', python],
    ['Python bytes([…])', `bytes([${bytes.join(', ')}])`],
    ['PowerShell [byte[]]', `[byte[]](${bytes.map(hex).join(',')})`],
    ['PowerShell @()', `@(${bytes.join(',')})`],
    ['Rust', `[${bytes.map((b) => `${b}u8`).join(', ')}]`],
    ['hexdump -C', hexdump],
    ['xxd', xxd],
    ['an INI file in capitals', `KTY=RSA\nN=${jwk.n}\nE=${jwk.e}\n`],
  ])('%s', (_, secret) => {
    expect(() => sign({}, secret)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('while ordinary secrets with numbers or brackets still work', () => {
    for (const secret of [
      'config[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17] padding',
      `${'1'.repeat(20)} and some words after it`,
      'e: x\nx: short\nn: abc\nkty: none of these',
      `0123456789abcdef0123456789abcdef`,
      `[${Array.from({ length: 32 }, (_, i) => i * 7).join(', ')}]`,
    ]) {
      expect(verify(sign({ a: 1 }, secret), secret).payload.a).toBe(1);
    }
  });
});

describe('every failure here is a JwtError', () => {
  it('sanity', () => {
    expect(new JwtKeyError('x')).toBeInstanceOf(JwtError);
  });
});
