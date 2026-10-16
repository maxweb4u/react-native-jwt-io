/**
 * Regressions for the findings of the second review round of 2026-10-16
 * (memory_bank/backlog.md, "Review of 2026-10-16, second round"). Each test
 * names its finding. Tests for mutants that survived the suite are in
 * mutation.test.ts.
 */
import crypto from 'node:crypto';
import * as api from '../index';
import { createJWKS, importJWK, importPEM, isExpired, sign, verify } from '../index';
import { type Jwk } from '../types/jwt';
import { bytesToBigInt } from '../utils/bytes';
import { describeValue } from '../utils/describe';
import { b64u, nodeKeyPair, pem, SECRET_32, tlv } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
/** An HS256 token whose HMAC key is `key` exactly as given — the forgery a public key used as a secret allows. */
function forge(key: string | Uint8Array): string {
  const input = `${b64u('{"alg":"HS256","typ":"JWT"}')}.${b64u('{"sub":"admin"}')}`;
  return `${input}.${b64u(crypto.createHmac('sha256', key).update(input).digest())}`;
}

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');
const ed = nodeKeyPair('ed25519');

describe('#1 a public key is refused as a secret in every form it is shown in', () => {
  const spki = rsa.publicKey.export({ type: 'spki', format: 'der' });
  const pkcs1 = rsa.publicKey.export({ type: 'pkcs1', format: 'der' });
  const pkcs8 = ec.privateKey.export({ type: 'pkcs8', format: 'der' });
  const sshEd25519 = (() => {
    const field = (data: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, data.length]), data]);
    const raw = ed.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
    return `ssh-ed25519 ${Buffer.concat([field(Buffer.from('ssh-ed25519')), field(raw)]).toString('base64')} me@host`;
  })();
  const fakeCertificate = tlv(0x30, tlv(0x30, spki), tlv(0x30, tlv(0x06, Uint8Array.of(0x2a, 0x86, 0x48))), tlv(0x03, Uint8Array.of(0, 1)));

  it.each<[string, string | Uint8Array]>([
    ['base64 SPKI on one line (Keycloak public_key)', spki.toString('base64')],
    ['base64 SPKI wrapped at 64 columns', spki.toString('base64').replace(/(.{64})/g, '$1\n')],
    ['base64 SPKI without padding', spki.toString('base64').replace(/=+$/, '')],
    ['base64url SPKI', spki.toString('base64url')],
    ['base64 PKCS#1', pkcs1.toString('base64')],
    ['hex SPKI', spki.toString('hex')],
    ['SPKI as a Latin-1 string', spki.toString('latin1')],
    ['DER SPKI bytes', Uint8Array.from(spki)],
    ['DER PKCS#1 bytes', Uint8Array.from(pkcs1)],
    ['DER PKCS#8 bytes', Uint8Array.from(pkcs8)],
    ['base64 EC SPKI', ec.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')],
    ['base64 Ed25519 SPKI', ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')],
    ['base64 bytes as a Uint8Array', Uint8Array.from(Buffer.from(spki.toString('base64')))],
    ['an OpenSSH public key', sshEd25519],
    ['PEM armor in lower case', pem(rsa.publicKey).toLowerCase()],
    ['PEM armor with spaces', pem(rsa.publicKey).replace('-----BEGIN PUBLIC KEY-----', '----- BEGIN  PUBLIC KEY -----')],
    ['a DER certificate', fakeCertificate],
    ['a JWK with "kty" escaped', JSON.stringify(jwkOf(rsa.publicKey)).replace('"kty"', '"k\\u0074y"')],
    ['a JWKS as JSON', JSON.stringify({ keys: [jwkOf(rsa.publicKey)] })],
  ])('%s', (_name, key) => {
    expect(() => verify(forge(key), key)).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => sign({}, key)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('ordinary secrets still work: random bytes, and random base64, base64url and hex text', () => {
    for (let i = 0; i < 2000; i++) {
      const bytes = crypto.randomBytes(32 + (i % 64));
      for (const secret of [bytes, bytes.toString('base64'), bytes.toString('base64url'), bytes.toString('hex')]) {
        expect(verify(sign({ i }, secret), secret).payload.i).toBe(i);
      }
    }
  });

  it('a random secret that happens to start like DER still works', () => {
    const secret = Buffer.concat([Buffer.from([0x30, 62]), crypto.randomBytes(62)]);
    expect(verify(sign({ a: 1 }, secret), secret).payload.a).toBe(1);
  });
});

describe('#1b key material behind a wrapper is refused too (a third pass, 2026-10-16)', () => {
  const spki = rsa.publicKey.export({ type: 'spki', format: 'der' });
  const publicPem = pem(rsa.publicKey);
  const ecPoint = ec.publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);
  const sshBlob = (() => {
    const field = (data: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, data.length]), data]);
    return Buffer.concat([field(Buffer.from('ssh-ed25519')), field(ed.publicKey.export({ type: 'spki', format: 'der' }).subarray(12))]);
  })();
  const pkcs7 = tlv(0x30, tlv(0x06, Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02)), tlv(0xa0, tlv(0x30)));

  it.each<[string, string | Uint8Array]>([
    ['base64 of the PEM text (a Kubernetes secret)', Buffer.from(publicPem).toString('base64')],
    ['base64 of a JWK', Buffer.from(JSON.stringify(jwkOf(rsa.publicKey))).toString('base64')],
    ['base64 of base64 DER', Buffer.from(spki.toString('base64')).toString('base64')],
    ['a raw uncompressed EC point, bytes', Uint8Array.from(ecPoint)],
    ['a raw EC point, hex with 0x', `0x${Buffer.from(ecPoint).toString('hex')}`],
    ['a raw EC point, base64', Buffer.from(ecPoint).toString('base64')],
    ['hex with colons, as openssl -text prints', spki.toString('hex').replace(/(..)(?!$)/g, '$1:')],
    ['base64 with literal \\n escapes (.env)', spki.toString('base64').replace(/(.{64})/g, '$1\\n')],
    ['a PEM in .env form, literal \\n', publicPem.replace(/\n/g, '\\n')],
    ['a value in JSON quotes', JSON.stringify(spki.toString('base64'))],
    ['a JWK serialized twice', JSON.stringify(JSON.stringify(jwkOf(rsa.publicKey)))],
    ['URL-encoded base64', encodeURIComponent(spki.toString('base64'))],
    ['an SSH wire blob, base64 without its type', sshBlob.toString('base64')],
    ['an authorized_keys line with options', `from="10.0.0.1",no-pty ssh-ed25519 ${sshBlob.toString('base64')} me`],
    ['an SSH certificate line', `ssh-ed25519-cert-v01@openssh.com AAAA${sshBlob.toString('base64')}`],
    ['PKCS#7 DER', pkcs7],
    ['DER with a trailing newline', Uint8Array.from(Buffer.concat([spki, Buffer.from('\n')]))],
    ['UTF-8 BOM before base64', Uint8Array.from(Buffer.concat([Buffer.of(0xef, 0xbb, 0xbf), Buffer.from(spki.toString('base64'))]))],
    ['a PEM in UTF-16LE (PowerShell 5)', Uint8Array.from(Buffer.from(publicPem, 'utf16le'))],
    ['PEM with typographic dashes', publicPem.replace(/-----/g, '\u2013\u2013\u2013\u2013\u2013')],
    ['a PEM without its BEGIN line', publicPem.split('\n').slice(1).join('\n')],
    ['a JWK of n and e only, no kty', JSON.stringify({ n: (jwkOf(rsa.publicKey) as { n: string }).n, e: 'AQAB' })],
    ['a JS-literal JWK', `{kty: 'RSA', n: '${(jwkOf(rsa.publicKey) as { n: string }).n}', e: 'AQAB'}`],
    ['a Keycloak realm document', JSON.stringify({ realm: 'demo', public_key: spki.toString('base64'), 'token-service': 'https://x/' })],
  ])('%s', (_name, key) => {
    expect(() => verify(forge(key), key)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('still accepts a JSON list of rotating secrets, and prose that merely mentions keys', () => {
    for (const secret of ['{"keys":["s3cr3t-one-0123456789abcdef0123","s3cr3t-two-0123456789abcdef0123"]}', 'monkeys"keys": fake secret padding padding padding padding']) {
      expect(verify(sign({ a: 1 }, secret), secret).payload.a).toBe(1);
    }
  });

  it('stays linear on a long run of dashes', () => {
    const dashes = '-'.repeat(65536);
    const start = Date.now();
    expect(verify(sign({ a: 1 }, dashes), dashes).payload.a).toBe(1);
    expect(Date.now() - start).toBeLessThan(200);
  });
});

describe('#2 error names survive a minifier', () => {
  const errorClasses = Object.entries(api).filter(([name]) => /^Jwt\w*Error$/.test(name)) as [string, { prototype: object }][];

  it('every error class has its name as a string on its prototype, not taken from the class', () => {
    expect(errorClasses).toHaveLength(12);
    for (const [name, errorClass] of errorClasses) {
      expect([name, Object.getOwnPropertyDescriptor(errorClass.prototype, 'name')?.value]).toEqual([name, name]);
    }
  });

  it('a renamed class — what a minifier makes of it — keeps the name', () => {
    // A minifier turns `class JwtExpiredError` into `class u`; the name must not follow.
    const renamed = { u: class extends api.JwtKeyError {} }.u;
    expect(renamed.name).toBe('u');
    expect(new renamed('x').name).toBe('JwtKeyError');
    expect(String(new api.JwtExpiredError('gone', new Date(0)))).toBe('JwtExpiredError: gone');
  });

  it('name is not an own enumerable property of an error', () => {
    expect(Object.keys(new api.JwtClaimError('iss', 'x'))).toEqual(['code', 'claim']);
  });
});

describe('#3 clockTolerance is at most a day', () => {
  const expired = sign({}, SECRET_32, { now: at(T), expiresIn: 10 });

  it.each([86401, '25h', '2d', 1e11, '165000w'])('refuses %p', (clockTolerance) => {
    expect(() => verify(expired, SECRET_32, { now: at(T + 1e9), clockTolerance })).toThrow(/the most is 86400/);
    expect(() => isExpired(expired, { now: at(T + 1e9), clockTolerance })).toThrow(expect.objectContaining({ option: 'clockTolerance' }));
  });

  it('accepts a day, and maxTokenAge keeps the long cap', () => {
    expect(verify(expired, SECRET_32, { now: at(T + 86400), clockTolerance: '1d' }).payload.iat).toBe(T);
    expect(verify(expired, SECRET_32, { now: at(T + 5), maxTokenAge: '52w' }).payload.iat).toBe(T);
  });
});

describe('#4 hostile key sizes are refused before costly arithmetic', () => {
  const big = b64u(Buffer.alloc(48_000, 0xff));
  const { n } = jwkOf(rsa.publicKey) as { n: string };

  it.each([
    ['n', { kty: 'RSA', n: big, e: 'AQAB' }, /larger than 16384 bits/],
    ['e', { kty: 'RSA', n, e: big }, /exponents above 33 bits/],
    ['d', { kty: 'RSA', n, e: 'AQAB', d: big }, /larger than 16384 bits/],
  ])('a 48 KB "%s" fails at once', (_name, jwk, message) => {
    const start = Date.now();
    expect(() => importJWK(jwk as Jwk, 'RS256')).toThrow(message);
    expect(Date.now() - start).toBeLessThan(50);
  });

  it('a 48 KB DER INTEGER fails at once', () => {
    const modulus = Buffer.concat([Buffer.of(0), Buffer.alloc(48_000, 0xff)]);
    const key = tlv(0x30, tlv(0x02, modulus), tlv(0x02, Uint8Array.of(1, 0, 1)));
    const text = `-----BEGIN RSA PUBLIC KEY-----\n${Buffer.from(key).toString('base64')}\n-----END RSA PUBLIC KEY-----`;
    const start = Date.now();
    expect(() => importPEM(text, 'RS256')).toThrow(/larger than any supported key/);
    expect(Date.now() - start).toBeLessThan(50);
  });

  it('bytesToBigInt is exact', () => {
    expect(bytesToBigInt(new Uint8Array(0))).toBe(BigInt(0));
    expect(bytesToBigInt(Uint8Array.of(0, 1, 0x0f, 0xff))).toBe(BigInt(0x010fff));
  });
});

describe('#5 an RSA public exponent has at most 33 bits', () => {
  const { n } = jwkOf(rsa.publicKey) as { n: string };
  const e = (value: bigint) => b64u(Buffer.from(value.toString(16).padStart(Math.ceil(value.toString(16).length / 2) * 2, '0'), 'hex'));

  it('accepts 2^32 + 1 (33 bits), refuses 2^33 + 1', () => {
    expect(importJWK({ kty: 'RSA', n, e: e((BigInt(1) << BigInt(32)) + BigInt(1)) }, 'RS256').algorithm).toBe('RS256');
    expect(() => importJWK({ kty: 'RSA', n, e: e((BigInt(1) << BigInt(33)) + BigInt(1)) }, 'RS256')).toThrow(/above 33 bits/);
  });
});

describe('#6 one unusable key does not take down a key set', () => {
  it('the rest of the set verifies; a token without kid hears about the skipped keys', () => {
    const weak = jwkOf(nodeKeyPair('rsa1024').publicKey);
    const set = createJWKS({ keys: [{ ...weak, alg: 'RS256' }, { ...jwkOf(ec.publicKey), alg: 'RS256' }, { ...jwkOf(ec.publicKey), kid: 'e' }] });
    expect(set.keys.map((k) => k.kid)).toEqual(['e']);
    expect(set.skipped.map((s) => s.index)).toEqual([0, 1]);
    expect(Object.isFrozen(set.skipped) && Object.isFrozen(set.skipped[0])).toBe(true);
    const rs = sign({}, importJWK({ ...jwkOf(rsa.privateKey), alg: 'RS256' }));
    expect(() => verify(rs, set)).toThrow(/2 could not be imported/);
  });
});

describe('#7 options must be a plain object', () => {
  const token = sign({}, SECRET_32);

  it.each<[string, unknown, RegExp]>([
    ['a callback', () => undefined, /no callbacks/],
    ['a string', 'HS256', /got string/],
    ['a number', 5, /got number/],
    ['an array', ['HS256'], /got an array/],
    ['a Map', new Map([['maxAge', 5]]), /not a plain object/],
    ['a class instance', new (class Options {})(), /not a plain object/],
    ['an object inheriting options', Object.create({ maxTokenAge: 1, algorithm: 'HS512' }), /not a plain object/],
  ])('verify refuses %s', (_name, options, message) => {
    expect(() => verify(token, SECRET_32, options as never)).toThrow(message);
    expect(() => verify(token, SECRET_32, options as never)).toThrow(expect.objectContaining({ option: 'options' }));
  });

  it('refuses an enumerable option on a null prototype', () => {
    const options = Object.create(Object.create(null, { maxAge: { value: 1, enumerable: true } }));
    expect(() => verify(token, SECRET_32, options)).toThrow(/inherited/);
  });

  it('sign, isExpired, importPEM and createJWKS refuse non-objects too', () => {
    expect(() => sign({}, SECRET_32, 'HS256' as never)).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => isExpired(token, 30 as never)).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey), 'RS256', 'kid' as never)).toThrow(/plain object/);
    expect(() => createJWKS({ keys: [] }, 'RS256' as never)).toThrow(/plain object/);
  });

  it('a frozen or null-prototype object of known options passes', () => {
    const bare = Object.assign(Object.create(null), { clockTolerance: 5 });
    expect(verify(token, SECRET_32, Object.freeze({ clockTolerance: 5 })).header.alg).toBe('HS256');
    expect(verify(token, SECRET_32, bare).header.alg).toBe('HS256');
  });
});

describe('#8 an error message never turns into a TypeError', () => {
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  const strange = [BigInt(1), circular, Object.create(null), Symbol('s'), () => 1];

  it.each(strange.map((value) => [describeValue(value), value]))('crv %s', (_name, value) => {
    expect(() => importJWK({ kty: 'EC', crv: value, x: 'a', y: 'b' } as never)).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(createJWKS({ keys: [{ kty: 'OKP', crv: value } as never] }).keys).toHaveLength(0);
  });

  it.each(strange.map((value) => [describeValue(value), value]))('algorithm %s', (_name, value) => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { algorithm: value as never })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => sign({}, SECRET_32, { algorithm: value as never })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey), value as never)).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => importJWK(jwkOf(ec.publicKey), value as never)).toThrow(code('ERR_JWT_OPTION_INVALID'));
  });

  it('use and key_ops of any type', () => {
    for (const value of strange) {
      expect(() => importJWK({ ...jwkOf(ec.publicKey), use: value } as never)).toThrow(code('ERR_JWT_KEY_INVALID'));
      expect(() => importJWK({ ...jwkOf(ec.publicKey), key_ops: [value] } as never)).toThrow(code('ERR_JWT_KEY_INVALID'));
    }
  });

  it('describeValue shortens long values', () => {
    expect(describeValue('x'.repeat(100))).toBe(`"${'x'.repeat(64)}…"`);
    expect(describeValue([1, 2])).toBe('[1,2]');
  });
});
