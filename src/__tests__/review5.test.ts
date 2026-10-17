/**
 * Regressions for the second review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17, second round"): one pass
 * over the first round's fixes, one from a consumer's side. Each test names
 * its finding.
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
  JwtHostRequirementError,
  JwtKeyError,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, pem, SECRET_32 } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const option = (name: string) => expect.objectContaining({ code: 'ERR_JWT_OPTION_INVALID', option: name });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
function forge(key: string | Uint8Array): string {
  const input = `${b64u('{"alg":"HS256","typ":"JWT"}')}.${b64u('{"sub":"admin"}')}`;
  return `${input}.${b64u(crypto.createHmac('sha256', key).update(input).digest())}`;
}
const refused = (key: string | Uint8Array) => {
  expect(() => verify(forge(key), key)).toThrow(code('ERR_JWT_KEY_INVALID'));
  expect(() => sign({}, key)).toThrow(code('ERR_JWT_KEY_INVALID'));
};
const accepted = (secret: string) => expect(verify(sign({ a: 1 }, secret), secret).payload.a).toBe(1);

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');

/** Runs `body` with globalThis.crypto replaced, and puts the real one back. */
function withCrypto(replacement: unknown, body: () => void): void {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto') as PropertyDescriptor;
  Object.defineProperty(globalThis, 'crypto', { value: replacement, configurable: true, writable: true });
  try {
    body();
  } finally {
    Object.defineProperty(globalThis, 'crypto', saved);
  }
}

describe('#1 a broken getRandomValues never hangs signing or blames the key', () => {
  const rs = importPEM(pem(rsa.privateKey), 'RS256');
  const ps = importPEM(pem(rsa.privateKey), 'PS256');
  const rsPublic = importPEM(pem(rsa.publicKey), 'RS256');

  it.each<[string, unknown]>([
    ['one that returns its argument untouched (a test mock)', { getRandomValues: (array: Uint8Array) => array }],
    ['one that fills a constant', { getRandomValues: (array: Uint8Array) => array.fill(7) }],
    ['one that throws (react-native-get-random-values without its native module)', { getRandomValues: () => { throw new Error('Native module not found'); } }],
    ['one that is not a function', { getRandomValues: 5 }],
  ])('%s: RS256 signs unblinded, PS256 names the host', (_name, replacement) => {
    withCrypto(replacement, () => {
      expect(verify(sign({ a: 1 }, rs), rsPublic).payload.a).toBe(1);
      expect(() => sign({}, ps)).toThrow(JwtHostRequirementError);
      expect(() => sign({}, ps)).toThrow(/crypto\.getRandomValues/);
    });
  });
});

describe('#2 options.header is checked with the other options', () => {
  it.each([
    ['a payload that is not an object', () => sign(5 as never, SECRET_32, { header: { typ: 5 } }), 'header.typ'],
    ['a short secret', () => sign({}, 'short', { header: { cty: null } }), 'header.cty'],
    ['an object that is not a key', () => sign({}, {} as never, { header: { toJSON: () => ({ crit: ['x'] }) } }), 'header'],
    ['a BigInt', () => sign({}, 'short', { header: { x: BigInt(1) } }), 'header'],
  ])('%s does not hide it', (_name, call, name) => {
    expect(call).toThrow(option(name));
  });

  it('an explicit header kid beats the key\'s; keyId and a different header kid conflict', () => {
    const key = importPEM(pem(ec.privateKey), 'ES256', { kid: 'k1' });
    expect(decodeUnverified(sign({}, key)).header.kid).toBe('k1');
    expect(decodeUnverified(sign({}, key, { header: { kid: 'x' } })).header.kid).toBe('x');
    expect(decodeUnverified(sign({}, key, { keyId: 'y' })).header.kid).toBe('y');
    expect(decodeUnverified(sign({}, key, { keyId: 'y', header: { kid: 'y' } })).header.kid).toBe('y');
    expect(() => sign({}, key, { keyId: 'y', header: { kid: 'x' } })).toThrow(option('keyId'));
  });
});

describe('#3 expiresIn under a second is refused, as maxTokenAge 0 is', () => {
  it.each([0, 0.5, '0s', '0.9s'])('%p', (expiresIn) => {
    expect(() => sign({}, SECRET_32, { expiresIn })).toThrow(option('expiresIn'));
  });

  it('notBefore 0 is fine: nbf = iat', () => {
    const { payload } = decodeUnverified(sign({}, SECRET_32, { now: at(T), notBefore: 0 }));
    expect([payload.iat, payload.nbf]).toEqual([T, T]);
  });
});

describe('#4 more public-key dumps are refused as secrets', () => {
  const jwk = jwkOf(rsa.publicKey);
  const ecJwk = jwkOf(ec.publicKey);
  const b64 = (value: string) => Buffer.from(value, 'base64url').toString('base64');
  const spki = Array.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
  const modulusHex = (Buffer.from(jwk.n as string, 'base64url').toString('hex').match(/../g) as string[]).join(':');

  it.each<[string, string]>([
    ['XMLDSig with a ds: prefix', `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>${b64(jwk.n as string)}</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`],
    ['.NET ECDSA XML with xmlns', `<ECDSAKeyValue xmlns="http://www.w3.org/2001/04/xmldsig-more#"><PublicKey><X Value="1"/></PublicKey></ECDSAKeyValue>`],
    ['a lower-case RSAKeyValue', `<rsakeyvalue><modulus>${b64(jwk.n as string)}</modulus></rsakeyvalue>`],
    ['a DSA key in XML', '<DSAKeyValue><P>AQ==</P></DSAKeyValue>'],
    ['a SAML certificate', `<ds:X509Certificate>${rsa.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}</ds:X509Certificate>`],
    ['a TOML inline table', `jwk = { kty = "RSA", n = "${jwk.n}", e = "AQAB" }`],
    ['PyYAML of a JWKS', `keys:\n- e: AQAB\n  kty: RSA\n  n: ${jwk.n}\n`],
    ['a YAML list item without kty', `- n: ${jwk.n}\n  e: AQAB\n`],
    ['a TOML kty line after another', `[jwk]\nkty = "EC"\ncrv = "P-256"\n`],
    ['Java Arrays.toString of signed bytes', `[${spki.map((b) => (b > 127 ? b - 256 : b)).join(', ')}]`],
    ['Go fmt.Print of a []byte', `[${spki.join(' ')}]`],
    ['one byte per line', spki.join('\n')],
    ['C braces with hex', `{${spki.map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(', ')}}`],
    ['a trailing comma', `[\n${spki.map((b) => `    ${b},`).join('\n')}\n]`],
    ['JSON of a Node Buffer', JSON.stringify(Buffer.from(spki))],
    ['JSON of a Uint8Array', JSON.stringify(Uint8Array.from(spki))],
    ['openssl -text without the Public-Key line', `Modulus:\n    ${modulusHex}\nExponent: 65537 (0x10001)\n`],
    ['openssl ec -text, the public part', `pub:\n    04:${'ab:'.repeat(63)}ab\nASN1 OID: prime256v1\nNIST CURVE: P-256\n`],
    ['openssl rsa -modulus', `Modulus=${Buffer.from(jwk.n as string, 'base64url').toString('hex').toUpperCase()}`],
    ['an EC JWK as YAML', `crv: P-256\nx: ${ecJwk.x}\ny: ${ecJwk.y}\n`],
  ])('%s', (_name, key) => {
    refused(key);
  });

  it('says it is a dump', () => {
    expect(() => sign({}, `<RSAKeyValue><Modulus>AQAB</Modulus></RSAKeyValue>`)).toThrow(/text dump/);
  });

  it('config lines that merely share the names are secrets', () => {
    const long = crypto.randomBytes(48).toString('base64url');
    const modulusLength = crypto.randomBytes(128).toString('base64url').slice(0, 170);
    for (const secret of [
      `n = "${modulusLength}"\ne = "AQAB"\n`,
      `n: ${long}\ne: iqzcom=enp\n`,
      `crv: r1ic3@om\nx: ${crypto.randomBytes(32).toString('hex')}\n`,
      `n = "${long}"\ne = "stone"\n`,
      `n: ${long}\n`,
      'e: AQAB\nanother: line of the secret',
      'crv: P-256 is my favourite curve name',
      `x: ${long}\n`,
      'Public-Key: is a phrase in this secret, not a dump of one',
      'pub:\nthe bar around the corner, which is long enough for a secret',
      'Modulus: big, as the poem says, and long enough',
      'kty: what does it mean anyway, my secret',
      '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20',
    ]) {
      accepted(secret);
    }
  });

  it('a secret that is a list of numbers but not a key still works', () => {
    accepted(JSON.stringify(Array.from(crypto.randomBytes(64))));
    accepted(Array.from(crypto.randomBytes(64)).join(' '));
  });

  it('stays linear on near misses of the new patterns', () => {
    const inputs = [
      '<'.repeat(65_536),
      `<ds:${'a'.repeat(65_000)}`,
      '1 '.repeat(32_000) + 'x',
      '-1,'.repeat(21_000) + 'z',
      '0x1, '.repeat(13_000) + 'q',
      'pub:\n'.repeat(13_000),
      '- '.repeat(32_000),
    ];
    const start = Date.now();
    for (const input of inputs) {
      try {
        sign({}, input);
      } catch {
        // refused or not: only the time matters
      }
    }
    expect(Date.now() - start).toBeLessThan(1500);
  });
});

describe('#5 escaping in messages covers the other line breaks', () => {
  it.each([' ', ' ', '\u0085', '\u009b'])('%j in a kid or an alg', (character) => {
    const set = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid: 'k1' }] });
    const kidToken = `${b64u(JSON.stringify({ alg: 'ES256', kid: `x${character}FAKE` }))}.${b64u('{}')}.AAAA`;
    const algToken = `${b64u(JSON.stringify({ alg: `x${character}FAKE` }))}.${b64u('{}')}.AAAA`;
    for (const [token, key] of [
      [kidToken, set],
      [algToken, SECRET_32],
    ] as const) {
      let message = '';
      try {
        verify(token, key);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain('FAKE');
      expect(message).not.toContain(character);
    }
  });

  it('in every kid message of a key set', () => {
    const kid = 'k x';
    const skippedSet = createJWKS({ keys: [{ kty: 'RSA', kid, n: 'AQAB', e: 'AQAB', alg: 'RS256' }] });
    const twoSet = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid }, { ...jwkOf(ec.publicKey), kid }] });
    const otherAlg = createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), kid, alg: 'RS256' }] });
    const token = `${b64u(JSON.stringify({ alg: 'ES256', kid }))}.${b64u('{}')}.AAAA`;
    for (const set of [skippedSet, twoSet, otherAlg]) {
      let message = '';
      try {
        verify(token, set);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain('k\\u2028x');
    }
  });
});

describe('#6 the expiry helpers read exp alone', () => {
  // jsonwebtoken.sign({ sub: user.id }) and Laravel's jwt-auth issue numeric subs.
  const payload = b64u(JSON.stringify({ sub: 12345, jti: 7, aud: 5, iss: null, exp: T + 60 }));
  const token = `${b64u('{"alg":"HS256"}')}.${payload}.AAAA`;

  it('isExpired and getExpiration work on a token with non-standard claims', () => {
    expect(isExpired(token, { now: at(T) })).toBe(false);
    expect(getExpiration(token)).toEqual(at(T + 60));
  });

  it('but still refuse a bad exp, and decodeUnverified and verify stay strict', () => {
    const badExp = `${b64u('{"alg":"HS256"}')}.${b64u('{"exp":"soon"}')}.AAAA`;
    expect(() => isExpired(badExp)).toThrow(JwtClaimError);
    expect(() => getExpiration(badExp)).toThrow(JwtClaimError);
    expect(() => decodeUnverified(token)).toThrow(expect.objectContaining({ claim: 'iss' }));
  });
});

describe('#7 importPEM reads what OpenSSL and Node read', () => {
  const ecPem = ec.privateKey.export({ type: 'sec1', format: 'pem' }) as string;
  const ecParameters = '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n';

  it.each([
    ['openssl ecparam -genkey (EC PARAMETERS, then the key)', `${ecParameters}${ecPem}`],
    ['openssl pkcs12 -nodes (Bag Attributes first)', `Bag Attributes\n    localKeyID: 01 02\nKey Attributes: <No Attributes>\n${ecPem}`],
    ['text after END', `${ecPem}\nthis key belongs to the staging server\n`],
    ['CRLF line breaks', ecPem.replace(/\n/g, '\r\n')],
  ])('%s', (_name, text) => {
    expect(importPEM(text, 'ES256').type).toBe('private');
  });

  it('says what is wrong otherwise', () => {
    expect(() => importPEM(`${ecPem}${ecPem}`, 'ES256')).toThrow(/holds 2 blocks/);
    expect(() => importPEM(ecPem.replace(/\n/g, '\\n'), 'ES256')).toThrow(/the two characters \\n where its line breaks should be/);
    expect(() => importPEM('not a key at all', 'ES256')).toThrow(/is not a PEM block/);
    expect(() => importPEM(ecParameters, 'ES256')).toThrow(/only EC PARAMETERS — a curve, not a key/);
    expect(() => importPEM(ecPem.replace('END EC PRIVATE KEY', 'END PRIVATE KEY'), 'ES256')).toThrow(/begins with "EC PRIVATE KEY" but ends with "PRIVATE KEY"/);
    expect(() => importPEM(`${'x'.repeat(70_000)}${ecPem}`, 'ES256')).toThrow(/longer than 65536/);
    const encrypted = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n';
    expect(() => importPEM(encrypted, 'RS256')).toThrow(/Encrypted private keys/);
  });

  it('a missing END costs one scan', () => {
    const start = Date.now();
    expect(() => importPEM('-----BEGIN PUBLIC KEY-----\n'.repeat(2400), 'RS256')).toThrow(JwtKeyError);
    expect(Date.now() - start).toBeLessThan(500);
  });
});

describe('#8 key sets', () => {
  it('a JWE key without use is an encryption key, left out silently', () => {
    const set = createJWKS({
      keys: [
        { ...jwkOf(rsa.publicKey), alg: 'RSA-OAEP-256', kid: 'enc' },
        { ...jwkOf(ec.publicKey), alg: 'ECDH-ES+A128KW', kid: 'ecdh' },
      ],
    });
    expect([set.keys.length, set.skipped.length]).toEqual([0, 0]);
  });

  it('an RSA key without alg (Microsoft Entra) is reported with the set\'s own remedy', () => {
    const set = createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), kid: 'e1', use: 'sig' }] });
    expect(set.skipped[0]?.reason).toMatch(/createJWKS\(jwks, \{ algorithm: 'RS256' \}\)/);
    expect(createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), kid: 'e1' }] }, { algorithm: 'RS256' }).keys).toHaveLength(1);
  });
});

describe('#9 types', () => {
  it('compile-time (npm run typecheck): undefined registered claims, and WebCrypto JWKs', () => {
    const token = sign({ sub: 'u' }, SECRET_32);
    // A claim that may be absent is undefined at run time, and may say so.
    const sub: string | undefined = verify<{ sub: string | undefined; exp: number | undefined }>(token, SECRET_32).payload.sub;
    // The DOM's JsonWebKey, as crypto.subtle.exportKey('jwk') returns it: no index signature.
    interface DomJsonWebKey {
      alg?: string;
      crv?: string;
      d?: string;
      dp?: string;
      dq?: string;
      e?: string;
      ext?: boolean;
      k?: string;
      key_ops?: string[];
      kty?: string;
      n?: string;
      oth?: { d?: string; r?: string; t?: string }[];
      p?: string;
      q?: string;
      qi?: string;
      use?: string;
      x?: string;
      y?: string;
    }
    const webCrypto: DomJsonWebKey = { ...(jwkOf(ec.publicKey) as DomJsonWebKey), ext: true, key_ops: ['verify'] };
    expect([sub, importJWK(webCrypto).algorithm]).toEqual(['u', 'ES256']);
  });
});

describe('#10 boundaries the mutants found unpinned', () => {
  it('now and computed times may reach 1e11 seconds, not pass it', () => {
    expect(() => sign({}, SECRET_32, { now: new Date(1e14), noTimestamp: true })).not.toThrow();
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 + 1000) })).toThrow(option('now'));
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 - 60_000), expiresIn: 60 })).not.toThrow();
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 - 60_000), expiresIn: 61 })).toThrow(option('expiresIn'));
  });

  it('a millisecond iat is named before a millisecond exp', () => {
    expect(() => sign({ exp: Date.now() + 60_000, iat: Date.now() }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'iat' }));
    expect(() => sign({ nbf: Date.now(), exp: Date.now() }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'exp' }));
  });
});
