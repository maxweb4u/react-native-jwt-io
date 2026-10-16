/**
 * Regressions for the findings of the second review, 2026-10-16
 * (memory_bank/backlog.md, "Review of 2026-10-16"). Each test names its finding.
 * The TextEncoder host requirement (#1) is tested in host.test.ts.
 */
import crypto from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { readNodes, readOid, readSingle } from '../keys/der';
import {
  createJWKS,
  decodeUnverified,
  getExpiration,
  importJWK,
  importPEM,
  isExpired,
  type JwtPayload,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { parseDuration } from '../utils/time';
import { b64u, nodeKeyPair, nodeVerify, pem, SECRET_32, tlv } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
const toPem = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----`;
const bigToB64u = (value: bigint) => {
  const hex = value.toString(16);
  return b64u(Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex'));
};
/** A correctly HS256-signed token over arbitrary JSON text, with any HMAC key. */
function hs256(payloadText: string, key: crypto.BinaryLike = SECRET_32): string {
  const input = `${b64u('{"alg":"HS256"}')}.${b64u(payloadText)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', key).update(input).digest())}`;
}

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');
const ed = nodeKeyPair('ed25519');

describe('#2 a public key passed as a secret is refused wherever it hides', () => {
  const publicPem = pem(rsa.publicKey);

  it('refuses PEM bytes after a long preamble (openssl pkcs12 "Bag Attributes")', () => {
    const text = `Bag Attributes\n    friendlyName: server\n    localKeyID: 01 02 03 04 05 06 07 08\nsubject=/CN=server\n${publicPem}`;
    const bytes = Uint8Array.from(Buffer.from(text));
    // The forgery the check prevents: an HS256 token keyed with the public key itself.
    const forged = hs256('{"sub":"admin"}', bytes);
    expect(() => verify(forged, bytes)).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => verify(forged, text)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses a JWK passed as JSON text or bytes', () => {
    const json = JSON.stringify(jwkOf(rsa.publicKey));
    expect(() => verify(hs256('{}', json), json)).toThrow(/importJWK/);
    expect(() => sign({}, Uint8Array.from(Buffer.from(` \n${json}`)))).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('still accepts ordinary secrets, including long binary ones', () => {
    const secret = crypto.randomBytes(100_000);
    secret[0] = 0x41; // not '{'
    expect(verify(sign({ a: 1 }, secret), secret).payload.a).toBe(1);
  });
});

describe('#3 a NumericDate outside the Date range is a claim error, not a RangeError', () => {
  it.each(['{"exp":-1e13}', '{"nbf":9e12}', '{"iat":-1e13}', '{"exp":1e20}'])('%s', (payload) => {
    const token = hs256(payload);
    expect(() => verify(token, SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => decodeUnverified(token)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('getExpiration and isExpired never produce an Invalid Date', () => {
    expect(() => getExpiration(hs256('{"exp":1e13}'))).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => isExpired(hs256('{"exp":-1e13}'))).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(getExpiration(hs256('{"exp":8.64e12}'))?.toISOString()).toBe('+275760-09-13T00:00:00.000Z');
  });

  it('sign refuses such a payload too', () => {
    expect(() => sign({ exp: -1e13 }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'exp' }));
  });
});

describe('#5 fractional durations are exact', () => {
  it.each([
    ['2.05m', 123],
    ['4.1m', 246],
    ['1.13h', 4068],
    ['0.5s', 0],
    ['1.999999s', 1],
    ['1.5 weeks', 907200],
  ])('%s is %i seconds', (input, seconds) => {
    expect(parseDuration(input)).toBe(seconds);
  });

  it('agrees with integer arithmetic for every two-decimal minute count', () => {
    for (let hundredths = 0; hundredths < 10_000; hundredths++) {
      const text = `${Math.floor(hundredths / 100)}.${String(hundredths % 100).padStart(2, '0')}m`;
      expect([text, parseDuration(text)]).toEqual([text, Math.floor((hundredths * 60) / 100)]);
    }
  });

  it('sign uses the exact value', () => {
    const { payload } = decodeUnverified(sign({}, SECRET_32, { now: at(T), expiresIn: '2.05m' }));
    expect((payload.exp as number) - (payload.iat as number)).toBe(123);
  });
});

describe('#6 createJWKS accepts null options, like sign and verify', () => {
  it('reads the algorithm as absent', () => {
    const jwks = { keys: [{ ...jwkOf(ec.publicKey), kid: 'e' }] };
    expect(createJWKS(jwks, null as never).keys).toHaveLength(1);
    expect(createJWKS({ keys: [jwkOf(rsa.publicKey)] }, null as never).skipped).toHaveLength(1);
  });
});

describe('#7 sign never issues a token its own verify refuses', () => {
  it.each([{ kid: 5 }, { typ: 5 }, { cty: null }, { typ: { a: 1 } }])('header %p', (header) => {
    expect(() => sign({}, SECRET_32, { header })).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID' }));
  });

  it('string values still pass', () => {
    const token = sign({}, SECRET_32, { header: { kid: 'k', typ: 'at+jwt', cty: 'x' } });
    expect(verify(token, SECRET_32).header).toEqual({ alg: 'HS256', typ: 'at+jwt', kid: 'k', cty: 'x' });
  });
});

describe('#8 an RSA key micro-rsa-dsa-dh cannot use is refused at import, with the reason', () => {
  const { n } = jwkOf(rsa.publicKey) as { n: string };

  it('refuses a public exponent above 33 bits (the limit is ours; micro-rsa-dsa-dh allows 256)', () => {
    const e = bigToB64u((BigInt(1) << BigInt(320)) + BigInt(1));
    expect(() => importJWK({ kty: 'RSA', n, e }, 'RS256')).toThrow(/exponents above 33 bits/);
  });

  it('refuses a modulus above 16384 bits', () => {
    const big = Buffer.alloc(2049, 0xff); // 16392 bits, odd
    expect(() => importJWK({ kty: 'RSA', n: b64u(big), e: 'AQAB' }, 'RS256')).toThrow(/larger than 16384 bits/);
  });

  it.each([
    ['even', 'AQAA'],
    ['below 3', 'AQ'],
  ])('refuses an %s public exponent', (_name, e) => {
    expect(() => importJWK({ kty: 'RSA', n, e }, 'RS256')).toThrow(/public exponent must be odd/);
  });

  it('refuses a negative INTEGER in a DER key', () => {
    const spki = Buffer.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
    // The modulus INTEGER starts 02 82 01 01 00 …; dropping the 00 makes it negative.
    const at = spki.indexOf(Buffer.from([0x02, 0x82, 0x01, 0x01, 0x00]));
    const rsaKey = Uint8Array.from(Buffer.concat([tlv(0x02, spki.subarray(at + 5, at + 5 + 256)), tlv(0x02, Uint8Array.of(1, 0, 1))]));
    expect(() => importPEM(toPem('RSA PUBLIC KEY', tlv(0x30, rsaKey)), 'RS256')).toThrow(/positive integer/);
  });
});

describe('#9 an RSA private key without primes is checked when it signs', () => {
  it('refuses to issue a token its public key cannot verify', () => {
    const own = jwkOf(rsa.privateKey) as Record<string, string>;
    // Odd and in range, so nothing at import can tell it from the real d.
    const d = BigInt(`0x${Buffer.from(own.d as string, 'base64url').toString('hex')}`) - BigInt(2);
    const mismatched = importJWK({ kty: 'RSA', n: own.n, e: own.e, d: bigToB64u(d) }, 'RS256');
    expect(() => sign({}, mismatched)).toThrow(/does not match its public key/);
  });

  it('a matching key without primes signs as before', () => {
    const own = jwkOf(rsa.privateKey) as Record<string, string>;
    const token = sign({ ok: true }, importJWK({ kty: 'RSA', n: own.n, e: own.e, d: own.d }, 'RS256'));
    expect(nodeVerify('RS256', rsa.publicKey, token)).toBe(true);
  });
});

describe('#10 a PKCS#8 v2 public key must be the private key\'s own', () => {
  /** Rebuilds a PKCS#8 key as version 2 with `[1] publicKey`, from parts. */
  function v2(der: Uint8Array, embedded: Uint8Array, unusedBits = 0): string {
    const [, algorithm, privateKey] = readNodes(readSingle(der, 0x30).content);
    const parts = [tlv(0x02, Uint8Array.of(1)), tlv(0x30, algorithm!.content), tlv(0x04, privateKey!.content)];
    return toPem('PRIVATE KEY', tlv(0x30, ...parts, tlv(0x81, Uint8Array.of(unusedBits), embedded)));
  }
  const spkiBits = (key: crypto.KeyObject) => {
    const [, bits] = readNodes(readSingle(key.export({ type: 'spki', format: 'der' }), 0x30).content);
    return bits!.content.subarray(1);
  };
  const pkcs8 = (key: crypto.KeyObject) => key.export({ type: 'pkcs8', format: 'der' });
  const otherEd = crypto.generateKeyPairSync('ed25519');
  const otherEc = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const otherRsa = nodeKeyPair('rsa1024');

  it.each([
    ['Ed25519', ed, 'EdDSA'],
    ['EC', ec, 'ES256'],
    ['RSA', rsa, 'RS256'],
  ] as const)('accepts a %s key with its own public key', (_name, pair, alg) => {
    expect(importPEM(v2(pkcs8(pair.privateKey), spkiBits(pair.publicKey)), alg).type).toBe('private');
  });

  it.each([
    ['Ed25519', ed, otherEd, 'EdDSA'],
    ['EC', ec, otherEc, 'ES256'],
    ['RSA', rsa, otherRsa, 'RS256'],
  ] as const)('refuses a %s key with another key\'s public key', (_name, pair, other, alg) => {
    expect(() => importPEM(v2(pkcs8(pair.privateKey), spkiBits(other.publicKey)), alg)).toThrow(
      /embedded public key does not match/,
    );
  });

  it('refuses a public key with unused bits, or an empty one, instead of skipping the check', () => {
    const der = pkcs8(ed.privateKey);
    expect(() => importPEM(v2(der, spkiBits(otherEd.publicKey), 5), 'EdDSA')).toThrow(/byte-aligned/);
    expect(() => importPEM(v2(der, new Uint8Array(0)), 'EdDSA')).toThrow(/byte-aligned/);
  });

  it('refuses [1] before [0], or twice', () => {
    const [version, algorithm, privateKey] = readNodes(readSingle(pkcs8(ed.privateKey), 0x30).content);
    const head = [tlv(0x02, Uint8Array.of(1)), tlv(0x30, algorithm!.content), tlv(0x04, privateKey!.content)];
    const pub = tlv(0x81, Uint8Array.of(0), spkiBits(ed.publicKey));
    const attributes = tlv(0xa0, new Uint8Array(0));
    expect(version!.content[0]).toBe(0);
    expect(importPEM(toPem('PRIVATE KEY', tlv(0x30, ...head, attributes, pub)), 'EdDSA').type).toBe('private');
    expect(() => importPEM(toPem('PRIVATE KEY', tlv(0x30, ...head, pub, attributes)), 'EdDSA')).toThrow(/unexpected data/);
    expect(() => importPEM(toPem('PRIVATE KEY', tlv(0x30, ...head, pub, pub)), 'EdDSA')).toThrow(/unexpected data/);
  });

  it('Ed25519 PKCS#8 v1 keys still import', () => {
    expect(importPEM(pem(ed.privateKey), 'EdDSA').type).toBe('private');
  });
});

describe('#11 RSASSA-PSS parameters are read and enforced', () => {
  const pss = (hash: 'sha256' | 'sha384' | 'sha512', saltLength: number) =>
    crypto.generateKeyPairSync('rsa-pss', {
      modulusLength: 2048,
      hashAlgorithm: hash,
      mgf1HashAlgorithm: hash,
      // @types/node types it as a string; Node takes a number of bytes.
      saltLength: saltLength as unknown as string,
    });
  const sha512 = pss('sha512', 64);

  it('a key restricted to SHA-512 is PS512 only', () => {
    expect(() => importPEM(pem(sha512.publicKey), 'PS256')).toThrow(/restricted to SHA-512/);
    expect(() => importPEM(pem(sha512.privateKey), 'PS384')).toThrow(/restricted to SHA-512/);
    const token = sign({ ok: true }, importPEM(pem(sha512.privateKey), 'PS512'));
    expect(verify(token, importPEM(pem(sha512.publicKey), 'PS512')).payload.ok).toBe(true);
    expect(nodeVerify('PS512', sha512.publicKey, token)).toBe(true);
  });

  it('a key that demands a longer salt than RFC 7518 uses is refused', () => {
    expect(() => importPEM(pem(pss('sha256', 64).publicKey), 'PS256')).toThrow(/salt longer than 32 bytes/);
  });

  it('an unrestricted RSASSA-PSS key works with every PS*', () => {
    const open = crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048, publicExponent: 65537 });
    for (const alg of ['PS256', 'PS384', 'PS512'] as const) {
      expect(importPEM(pem(open.publicKey), alg).algorithm).toBe(alg);
    }
  });

  it.each([
    ['an INTEGER', tlv(0x02, Uint8Array.of(5))],
    ['an OCTET STRING', tlv(0x04, Uint8Array.of(1, 2))],
    ['NULL', tlv(0x05, new Uint8Array(0))],
    ['the SHA-1 defaults', tlv(0x30, new Uint8Array(0))],
  ])('refuses %s as parameters', (_name, parameters) => {
    const [, bits] = readNodes(readSingle(rsa.publicKey.export({ type: 'spki', format: 'der' }), 0x30).content);
    const oid = tlv(0x06, Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]));
    const spki = tlv(0x30, tlv(0x30, oid, parameters), tlv(0x03, bits!.content));
    expect(() => importPEM(toPem('PUBLIC KEY', spki), 'PS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('#12 an OID has one encoding', () => {
  it('refuses a subidentifier with a leading 0x80', () => {
    const minimal = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    const padded = Uint8Array.from([0x2a, 0x80, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    expect(readOid({ tag: 0x06, content: minimal })).toBe('1.2.840.113549.1.1.1');
    expect(() => readOid({ tag: 0x06, content: padded })).toThrow(/non-minimal OID/);
    const spki = Buffer.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
    const at = spki.indexOf(Buffer.from(minimal));
    const [, bits] = readNodes(readSingle(spki, 0x30).content);
    const bad = tlv(0x30, tlv(0x30, tlv(0x06, padded), tlv(0x05, new Uint8Array(0))), tlv(0x03, bits!.content));
    expect(at).toBeGreaterThan(0);
    expect(() => importPEM(toPem('PUBLIC KEY', bad), 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('#13 a SEC1 EC private key is read strictly', () => {
  const sec1 = ec.privateKey.export({ type: 'sec1', format: 'der' });
  const [version, d, params, pub] = readNodes(readSingle(sec1, 0x30).content) as [
    { content: Uint8Array },
    { content: Uint8Array },
    { tag: number; content: Uint8Array },
    { tag: number; content: Uint8Array },
  ];
  const build = (...rest: Uint8Array[]) =>
    toPem('EC PRIVATE KEY', tlv(0x30, tlv(0x02, version.content), tlv(0x04, d.content), ...rest));
  const p0 = tlv(params.tag, params.content);
  const p1 = tlv(pub.tag, pub.content);

  it('accepts [0] then [1]', () => {
    expect(importPEM(build(p0, p1), 'ES256').type).toBe('private');
  });

  it.each([
    ['[1] before [0]', [p1, p0]],
    ['[0] twice', [p0, p0, p1]],
    ['[1] twice', [p0, p1, p1]],
  ])('refuses %s', (_name, rest) => {
    expect(() => importPEM(build(...rest), 'ES256')).toThrow(/unexpected data in the EC private key/);
  });

  it('refuses a public key that is not the private key\'s', () => {
    const otherSec1 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'sec1', format: 'der' });
    const otherPub = readNodes(readSingle(otherSec1, 0x30).content)[3]!;
    expect(() => importPEM(build(p0, tlv(otherPub.tag, otherPub.content)), 'ES256')).toThrow(/embedded public key does not match/);
  });

  it.each([
    ['zero', new Uint8Array(32)],
    ['the group order', Buffer.from('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex')],
  ])('refuses a scalar equal to %s', (_name, scalar) => {
    const key = toPem('EC PRIVATE KEY', tlv(0x30, tlv(0x02, version.content), tlv(0x04, scalar), p0));
    expect(() => importPEM(key, 'ES256')).toThrow(/not a valid P-256 scalar/);
  });

  it('pads a short scalar, as some generators write one', () => {
    const scalar = Uint8Array.from(crypto.randomBytes(32));
    scalar[0] = 0;
    scalar[1] = scalar[1]! | 1;
    const key = importPEM(toPem('EC PRIVATE KEY', tlv(0x30, tlv(0x02, version.content), tlv(0x04, scalar.subarray(1)), p0)), 'ES256');
    const point = p256.getPublicKey(scalar, false);
    const publicKey = importJWK({ kty: 'EC', crv: 'P-256', x: b64u(point.subarray(1, 33)), y: b64u(point.subarray(33)) });
    expect(verify(sign({ ok: 1 }, key), publicKey).payload.ok).toBe(1);
  });
});

describe('#14 a JWK crv must be a string', () => {
  it('skips, or refuses, an array crv', () => {
    const jwk = { ...jwkOf(ec.publicKey), crv: ['P-256'] } as unknown as Jwk;
    expect(() => importJWK(jwk)).toThrow(/cannot be used for JWS signatures \(curve \["P-256"\]\)/);
    expect(createJWKS({ keys: [jwk] }).keys).toHaveLength(0);
  });
});

describe('#15 two PEM blocks are named as such', () => {
  it('says "not a single PEM block", not "not valid base64"', () => {
    const block = pem(rsa.publicKey).trim();
    expect(() => importPEM(`${block}\n${block}`, 'RS256')).toThrow(/not a single PEM block/);
  });
});

describe('#16 options.algorithm pins the token alg, for a key set too', () => {
  const rsaJwk = { ...jwkOf(rsa.publicKey), alg: 'RS256', kid: 'r' };
  const set = createJWKS({ keys: [rsaJwk, { ...jwkOf(ec.publicKey), kid: 'e' }] });
  const rs256 = sign({}, importJWK({ ...jwkOf(rsa.privateKey), alg: 'RS256', kid: 'r' }));
  const es256 = sign({}, importJWK({ ...jwkOf(ec.privateKey), kid: 'nope' }));

  it('refuses a token whose alg is not the pinned one, naming the option', () => {
    expect(() => verify(rs256, set, { algorithm: 'ES256' })).toThrow(/options.algorithm is "ES256"/);
    expect(() => verify(es256, set, { algorithm: 'RS256' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('accepts a token whose alg is the pinned one', () => {
    expect(verify(rs256, set, { algorithm: 'RS256' }).header.kid).toBe('r');
  });

  it('accepts an imported key\'s own algorithm, and still refuses another', () => {
    const key = importPEM(pem(rsa.publicKey), 'RS256');
    expect(verify(rs256, key, { algorithm: 'RS256' }).header.alg).toBe('RS256');
    expect(() => verify(rs256, key, { algorithm: 'RS512' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });
});

describe('#17 sign accepts interface-typed payloads', () => {
  it('compiles and signs', () => {
    interface Claims {
      sub: string;
      roles: string[];
    }
    const claims: Claims = { sub: 'u', roles: ['a'] };
    expect(verify<Claims>(sign(claims, SECRET_32), SECRET_32).payload.roles).toEqual(['a']);
  });
});

describe('#18 unknown options are errors, not silently ignored', () => {
  const token = sign({}, SECRET_32, { now: at(T), expiresIn: 60 });

  it.each([
    ['expiresin', /"expiresIn"/],
    ['expiresIN', /Known options/],
  ])('sign refuses %s', (name, hint) => {
    expect(() => sign({}, SECRET_32, { [name]: '1h' } as never)).toThrow(
      expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim: name }),
    );
    expect(() => sign({}, SECRET_32, { [name]: '1h' } as never)).toThrow(hint);
  });

  it.each([
    ['maxAge', /"maxTokenAge"/],
    ['algorithms', /one "algorithm"/],
    ['clockTimestamp', /"now"/],
    ['complete', /always returns/],
    ['constructor', /Known options/],
  ])('verify refuses jsonwebtoken\'s %s', (name, hint) => {
    expect(() => verify(token, SECRET_32, { [name]: 1 } as never)).toThrow(hint);
  });

  it('isExpired, importPEM and createJWKS refuse unknown options too', () => {
    expect(() => isExpired(token, { tolerance: 5 } as never)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey), 'RS256', { keyId: 'k' } as never)).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => createJWKS({ keys: [] }, { alg: 'RS256' } as never)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('options with only known names pass', () => {
    expect(verify(token, SECRET_32, { now: at(T), clockTolerance: 5, algorithm: 'HS256' }).payload.iat).toBe(T);
  });
});

describe('#19 verified results are frozen all the way down', () => {
  it('a verified aud array cannot be edited after the check', () => {
    const { payload } = verify(sign({ aud: ['app'], nested: { a: [1] } }, SECRET_32), SECRET_32, { audience: 'app' });
    expect(() => (payload.aud as string[]).push('admin')).toThrow(TypeError);
    expect(Object.isFrozen((payload.nested as { a: number[] }).a)).toBe(true);
  });
});

describe('#20 the subject option is type-checked like the others', () => {
  it('refuses a non-string subject as a caller error', () => {
    const token = sign({ sub: '5' }, SECRET_32);
    expect(() => verify(token, SECRET_32, { subject: 5 as never })).toThrow(/"subject" option must be a string/);
    expect(verify(token, SECRET_32, { subject: '5' }).payload.sub).toBe('5');
  });
});

describe('#21 typ is compared as RFC 7515 §4.1.9 says', () => {
  const withTyp = (typ: string) => sign({}, SECRET_32, { header: { typ } });

  it.each([
    ['JWT', 'application/jwt'],
    ['application/JWT', 'jwt'],
    ['at+jwt', 'application/at+JWT'],
  ])('header %s matches option %s', (header, option) => {
    expect(verify(withTyp(header), SECRET_32, { typ: option }).header.typ).toBe(header);
  });

  it('a typ with a slash is not given an application/ prefix', () => {
    expect(() => verify(withTyp('a/b'), SECRET_32, { typ: 'application/a/b' })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
});

describe('#22 noTimestamp does not add iat, and keeps one the payload has', () => {
  it('is documented behaviour', () => {
    expect(decodeUnverified(sign({}, SECRET_32, { noTimestamp: true })).payload.iat).toBeUndefined();
    expect(decodeUnverified(sign({ iat: T }, SECRET_32, { noTimestamp: true })).payload.iat).toBe(T);
  });
});

describe('#23 key checks that no test exercised before', () => {
  it('refuses an Ed25519 public key that is not a canonical point (strict RFC 8032, not ZIP-215)', () => {
    // y = 2^255 - 1 ≥ p: ZIP-215 would reduce it, RFC 8032 refuses it.
    const nonCanonical = Buffer.alloc(32, 0xff);
    nonCanonical[31] = 0x7f;
    expect(() => importJWK({ kty: 'OKP', crv: 'Ed25519', x: b64u(nonCanonical) })).toThrow(/not a valid Ed25519 public key/);
    const spki = tlv(0x30, tlv(0x30, tlv(0x06, Uint8Array.of(0x2b, 0x65, 0x70))), tlv(0x03, Uint8Array.of(0), nonCanonical));
    expect(() => importPEM(toPem('PUBLIC KEY', spki), 'EdDSA')).toThrow(/Ed25519 public key is invalid/);
  });

  it('refuses an Ed25519 JWK whose d is not x\'s', () => {
    const own = jwkOf(ed.privateKey);
    const other = jwkOf(crypto.generateKeyPairSync('ed25519').privateKey);
    expect(() => importJWK({ ...own, d: other.d })).toThrow(/"d" does not match its "x"/);
  });

  it('refuses a bare secret with an asymmetric algorithm', () => {
    expect(() => sign({}, SECRET_32, { algorithm: 'RS256' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('signs ECDSA with low S, deterministically (RFC 6979)', () => {
    const key = importJWK(jwkOf(ec.privateKey));
    const halfOrder = p256.Point.Fn.ORDER / BigInt(2);
    const first = sign({ n: 0 }, key, { now: at(T) });
    expect(sign({ n: 0 }, key, { now: at(T) })).toBe(first);
    for (let i = 0; i < 40; i++) {
      const signature = Buffer.from(sign({ n: i }, key).split('.')[2]!, 'base64url');
      expect(BigInt(`0x${signature.subarray(32).toString('hex')}`) <= halfOrder).toBe(true);
    }
  });

  it('the payload type reaches verify', () => {
    const payload: JwtPayload = verify(sign({ sub: 'x' }, SECRET_32), SECRET_32).payload;
    expect(payload.sub).toBe('x');
  });
});
