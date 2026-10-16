/**
 * Tests that kill the mutants which survived the suite on 2026-10-16: each
 * names the mutant (K:<id>) and fails if that check is removed or weakened.
 * Mutation testing, its results and the equivalent mutants are described in
 * memory_bank/engineering/testing-policy.md#mutation-testing.
 */
import crypto from 'node:crypto';
import { readNodes, readOid, readSingle } from '../keys/der';
import { createJWKS, decodeUnverified, importJWK, importPEM, sign, verify } from '../index';
import { type Jwk } from '../types/jwt';
import { parseDuration } from '../utils/time';
import { utf8Decode } from '../utils/utf8';
import { b64u, nodeKeyPair, pem, SECRET_32, SECRET_48, tlv } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const T = 1_700_000_000;
const at = (s: number) => new Date(s * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
const toPem = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----`;
const bigToB64u = (value: bigint) => {
  const hex = value.toString(16);
  return b64u(Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex'));
};
function hs256(payloadText: string, key: crypto.BinaryLike = SECRET_32, headerText = '{"alg":"HS256"}'): string {
  const input = `${b64u(headerText)}.${b64u(payloadText)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', key).update(input).digest())}`;
}
const sigBytes = (token: string) => Buffer.from(token.split('.')[2]!, 'base64url');
const withSig = (token: string, sig: Uint8Array) => `${token.split('.').slice(0, 2).join('.')}.${b64u(sig)}`;

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');
const ed = nodeKeyPair('ed25519');
const O = {
  pss: Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]),
  mgf1: Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08]),
  rsaEnc: Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
  sha256: Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
  sha384: Uint8Array.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
};
const alg = (oid: Uint8Array, ...params: Uint8Array[]) => tlv(0x30, tlv(0x06, oid), ...params);
const int = (...b: number[]) => tlv(0x02, Uint8Array.from(b));
const rsaBits = readNodes(readSingle(rsa.publicKey.export({ type: 'spki', format: 'der' }), 0x30).content)[1]!.content;
const pssSpki = (...fields: Uint8Array[]) =>
  toPem('PUBLIC KEY', tlv(0x30, alg(O.pss, tlv(0x30, ...fields)), tlv(0x03, rsaBits)));
const h0 = (h: Uint8Array) => tlv(0xa0, alg(h));
const m1 = (h: Uint8Array, mgf = O.mgf1) => tlv(0xa1, alg(mgf, alg(h)));
const s2 = (n: number) => tlv(0xa2, int(n));
const t3 = (n: number) => tlv(0xa3, int(n));

describe('PSS parameters', () => {
  it('sanity: full SHA-256 parameters import', () => {
    expect(importPEM(pssSpki(h0(O.sha256), m1(O.sha256), s2(32), t3(1)), 'PS256').algorithm).toBe('PS256');
  });
  it('K:P1 MGF1 hash differs from the digest', () => {
    expect(() => importPEM(pssSpki(h0(O.sha256), m1(O.sha384), s2(32)), 'PS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM(pssSpki(h0(O.sha256), s2(32)), 'PS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
  it('K:P5 trailer field other than 1', () => {
    expect(() => importPEM(pssSpki(h0(O.sha256), m1(O.sha256), s2(32), t3(2)), 'PS256')).toThrow(/trailer/);
  });
  it('K:P6 mask function that is not MGF1', () => {
    expect(() => importPEM(pssSpki(h0(O.sha256), m1(O.sha256, O.sha256), s2(32)), 'PS256')).toThrow(/not MGF1/);
  });
  it('K:P7 a field twice, or out of order', () => {
    expect(() => importPEM(pssSpki(h0(O.sha256), h0(O.sha256), m1(O.sha256)), 'PS256')).toThrow(/malformed RSASSA-PSS/);
    expect(() => importPEM(pssSpki(h0(O.sha256), s2(32), m1(O.sha256)), 'PS256')).toThrow(/malformed RSASSA-PSS/);
  });
  it('K:P28 hash AlgorithmIdentifier with non-NULL parameters', () => {
    const h = tlv(0xa0, alg(O.sha256, int(5)));
    expect(() => importPEM(pssSpki(h, m1(O.sha256)), 'PS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('PKCS#8 v2 embedded public key', () => {
  const pkcs8 = (key: crypto.KeyObject) => key.export({ type: 'pkcs8', format: 'der' });
  function build(der: Uint8Array, embedded: Uint8Array, version = 1): string {
    const [, a, k] = readNodes(readSingle(der, 0x30).content);
    return toPem('PRIVATE KEY', tlv(0x30, int(version), tlv(0x30, a!.content), tlv(0x04, k!.content), tlv(0x81, Uint8Array.of(0), embedded)));
  }
  it('K:P10 RSA embedded key with the same n but another e', () => {
    const rsaPub = readNodes(readSingle(rsaBits.subarray(1), 0x30).content);
    const embedded = tlv(0x30, tlv(0x02, rsaPub[0]!.content), int(3));
    expect(() => importPEM(build(pkcs8(rsa.privateKey), embedded), 'RS256')).toThrow(/embedded public key does not match/);
  });
  it('K:P16 a v1 (version 0) key may not carry [1]', () => {
    expect(() => importPEM(build(pkcs8(ed.privateKey), ed.publicKey.export({ type: 'spki', format: 'der' }).subarray(12), 0), 'EdDSA')).toThrow(
      /unexpected data/,
    );
  });
  it('K:P21 RSASSA-PSS v2 key with another key\'s public key', () => {
    const pss = crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
    expect(() => importPEM(build(pkcs8(pss.privateKey), rsaBits.subarray(1)), 'PS256')).toThrow(/embedded public key does not match/);
  });
});

describe('DER', () => {
  it('K:D5 long-form length with a leading zero byte', () => {
    const bytes = Uint8Array.from([0x04, 0x82, 0x00, 0x80, ...new Uint8Array(0x80)]);
    expect(() => readNodes(bytes)).toThrow(/non-minimal length/);
  });
  it('K:D6 truncated OID', () => {
    expect(() => readOid({ tag: 0x06, content: Uint8Array.of(0x2a, 0x86) })).toThrow(/truncated OID/);
  });
  it('K:D7 NULL parameters with content', () => {
    const spki = tlv(0x30, alg(O.rsaEnc, tlv(0x05, Uint8Array.of(0))), tlv(0x03, rsaBits));
    expect(() => importPEM(toPem('PUBLIC KEY', spki), 'RS256')).toThrow(/unexpected algorithm parameters/);
  });
});

describe('signature bytes', () => {
  it('K:BY1 an HMAC tag with bytes appended', () => {
    const token = sign({}, SECRET_32);
    expect(() => verify(withSig(token, Buffer.concat([sigBytes(token), Buffer.of(0)])), SECRET_32)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
  it('K:X2 a 4n+1-character signature segment', () => {
    const token = sign({}, SECRET_48, { algorithm: 'HS384' });
    expect(token.split('.')[2]!.length % 4).toBe(0);
    expect(() => verify(`${token}A`, SECRET_48, { algorithm: 'HS384' })).toThrow(code('ERR_JWT_MALFORMED'));
  });
  it('K:X3 a non-ASCII character aliasing a base64url one', () => {
    const token = sign({}, SECRET_32);
    const last = token.charCodeAt(token.length - 1);
    expect(() => verify(token.slice(0, -1) + String.fromCharCode(last + 128), SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });
  it('K:B2 a PS256 key whose d does not match', () => {
    const own = jwkOf(rsa.privateKey) as Record<string, string>;
    const d = BigInt(`0x${Buffer.from(own.d as string, 'base64url').toString('hex')}`) - BigInt(2);
    const mismatched = importJWK({ kty: 'RSA', n: own.n, e: own.e, d: bigToB64u(d) }, 'PS256');
    expect(() => sign({}, mismatched)).toThrow(/does not match its public key/);
  });
  it('K:B5 an RSA signature with a leading zero byte', () => {
    const key = importJWK({ ...jwkOf(rsa.privateKey), alg: 'RS256' });
    const pub = importJWK({ ...jwkOf(rsa.publicKey), alg: 'RS256' });
    const token = sign({}, key);
    expect(() => verify(withSig(token, Buffer.concat([Buffer.of(0), sigBytes(token)])), pub)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
  it('K:B6 an ECDSA signature with a byte appended or prepended', () => {
    const token = sign({}, importJWK(jwkOf(ec.privateKey)));
    const pub = importJWK(jwkOf(ec.publicKey));
    expect(() => verify(withSig(token, Buffer.concat([sigBytes(token), Buffer.of(0)])), pub)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
    expect(() => verify(withSig(token, Buffer.concat([Buffer.of(0), sigBytes(token)])), pub)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
  it('K:B7 an Ed25519 signature with a byte appended', () => {
    const token = sign({}, importJWK(jwkOf(ed.privateKey)));
    const pub = importJWK(jwkOf(ed.publicKey));
    expect(() => verify(withSig(token, Buffer.concat([sigBytes(token), Buffer.of(0)])), pub)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
});

describe('encodings', () => {
  it('K:X5 a PEM body with extra padding', () => {
    const body = pem(rsa.publicKey).trim().replace('\n-----END', '\n====\n-----END');
    expect(() => importPEM(body, 'RS256')).toThrow(/not valid base64/);
  });
  it('K:U4 a lead byte followed by a non-continuation byte', () => {
    expect(utf8Decode(Uint8Array.of(0xc3, 0x41))).toBeNull();
  });
  it('K:PA3 an empty alg', () => {
    expect(() => decodeUnverified(hs256('{}', SECRET_32, '{"alg":""}'))).toThrow(code('ERR_JWT_MALFORMED'));
  });
  it('K:PA4 nested header values are frozen', () => {
    const { header } = verify(sign({}, SECRET_32, { header: { x5c: ['a'] } }), SECRET_32);
    expect(Object.isFrozen(header.x5c)).toBe(true);
  });
});

describe('keys', () => {
  it('K:E2 an RSA JWK with p but no q', () => {
    const { q: _q, ...noQ } = jwkOf(rsa.privateKey) as Record<string, string>;
    expect(() => importJWK({ ...noQ, kty: 'RSA' }, 'RS256')).toThrow(/missing "q"/);
  });
  it('K:JW3 two keys share a kid, with different algorithms', () => {
    const set = createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), alg: 'RS256', kid: 'k' }, { ...jwkOf(ec.publicKey), kid: 'k' }] });
    const token = sign({ ok: 1 }, importJWK({ ...jwkOf(ec.privateKey), kid: 'k' }));
    expect(verify(token, set).payload.ok).toBe(1);
  });
  it('K:JW4 createJWKS algorithm does not apply to EC keys', () => {
    expect(createJWKS({ keys: [jwkOf(rsa.publicKey), jwkOf(ec.publicKey)] }, { algorithm: 'RS256' }).keys).toHaveLength(2);
  });
  it('K:K3 a 16384-bit modulus is accepted', () => {
    expect(importJWK({ kty: 'RSA', n: b64u(Buffer.alloc(2048, 0xff)), e: 'AQAB' }, 'RS256').algorithm).toBe('RS256');
  });
  it('K:K7 a 2047-bit modulus is refused', () => {
    const n = Buffer.alloc(256, 0xff);
    n[0] = 0x7f;
    expect(() => importJWK({ kty: 'RSA', n: b64u(n), e: 'AQAB' }, 'RS256')).toThrow(/at least 2048 bits/);
  });
  it('K:K8 a 34-bit exponent is refused, a 33-bit one accepted', () => {
    const { n } = jwkOf(rsa.publicKey) as { n: string };
    expect(() => importJWK({ kty: 'RSA', n, e: bigToB64u((BigInt(1) << BigInt(33)) + BigInt(1)) }, 'RS256')).toThrow(/above 33 bits/);
    expect(importJWK({ kty: 'RSA', n, e: bigToB64u((BigInt(1) << BigInt(32)) + BigInt(1)) }, 'RS256').algorithm).toBe('RS256');
  });
  it('K:RK1 a PEM label with digits passed as a secret', () => {
    const text = pem(rsa.publicKey).replace(/PUBLIC KEY/g, 'X509 CERTIFICATE');
    expect(() => verify(hs256('{"sub":"admin"}', text), text)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
  it('K:RK7 PEM bytes after a preamble longer than 4096 bytes', () => {
    const bytes = Uint8Array.from(Buffer.from(`${'x'.repeat(5000)}\n${pem(rsa.publicKey)}`));
    expect(() => verify(hs256('{"sub":"admin"}', bytes), bytes)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
  it('K:RK8 a JWK whose kty is not the first member', () => {
    const { n, e } = jwkOf(rsa.publicKey) as { n: string; e: string };
    const json = JSON.stringify({ e, kty: 'RSA', n });
    expect(() => verify(hs256('{}', json), json)).toThrow(/importJWK/);
  });
});

describe('claims and options', () => {
  it('K:C12 an iat one second in the future', () => {
    expect(() => verify(sign({ iat: T + 1 }, SECRET_32), SECRET_32, { now: at(T) })).toThrow(/issued in the future/);
  });
  it('K:C13 audience required but the token has none', () => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { audience: 'app' })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => verify(sign({ aud: [] }, SECRET_32), SECRET_32, { audience: 'app' })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
  it('K:C14 requiredClaims names an Object.prototype member', () => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { requiredClaims: ['constructor'] })).toThrow(/no "constructor" claim/);
  });
  it('K:T4 a duration of exactly the cap is accepted', () => {
    expect(parseDuration('100000000000s')).toBe(1e11);
  });
  it('K:T6 a 65-character duration is refused even when small', () => {
    expect(parseDuration(`${'0'.repeat(63)}1s`)).toBeNull();
  });
  it('K:O1 no prototype text in the hint', () => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { constructor: 1 } as never)).toThrow(/^Unknown option "constructor"\. Known/);
  });
  it('K:O2 an unknown option after a known one', () => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { now: at(T), maxAge: 5 } as never)).toThrow(/"maxTokenAge"/);
  });
  it('K:S5 a header toJSON that adds crit', () => {
    const header = { toJSON: () => ({ alg: 'HS256', typ: 'JWT', crit: ['exp'] }) };
    expect(() => sign({}, SECRET_32, { header })).toThrow(code('ERR_JWT_OPTION_INVALID'));
  });
  it('K:S7 an iat in milliseconds', () => {
    expect(() => sign({ iat: T * 1000 }, SECRET_32)).toThrow(/milliseconds/);
  });
  it('K:S8 an own __proto__ in options.header is ignored', () => {
    const header = {};
    Object.defineProperty(header, '__proto__', { value: { toJSON: () => ({ alg: 'HS256', x: 1 }) }, enumerable: true });
    expect(decodeUnverified(sign({}, SECRET_32, { header })).header.x).toBeUndefined();
  });
  it('K:V2 NONE is reported as alg none', () => {
    expect(() => verify(hs256('{}', SECRET_32, '{"alg":"NONE"}'), SECRET_32)).toThrow(/alg "none"/);
  });
  it('K:V4 b64:true is refused too', () => {
    expect(() => verify(hs256('{}', SECRET_32, '{"alg":"HS256","b64":true}'), SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });
});
