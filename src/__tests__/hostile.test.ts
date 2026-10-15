/**
 * Hostile input: everything here is written by whoever sent the token.
 * SC-3, SC-4, SC-6, and the 1.x defects V1-5 and V1-6 in memory_bank/backlog.md.
 */
import { createJWKS, importJWK, importPEM, sign, verify } from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, nodeSign, pem, SECRET_32 } from './helpers/node';
import crypto from 'node:crypto';

const code = (c: string) => expect.objectContaining({ code: c });
const good = sign({ sub: 'u1' }, SECRET_32);
const [goodHeader, goodPayload, goodSignature] = good.split('.') as [string, string, string];
const segment = (value: unknown) => b64u(JSON.stringify(value));

/** A correctly HS256-signed token over arbitrary header and payload text. */
function hs256(headerText: string, payloadText: string): string {
  const input = `${b64u(headerText)}.${b64u(payloadText)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', SECRET_32).update(input).digest())}`;
}

describe('shape (SC-6): malformed tokens fail before any crypto runs', () => {
  it.each([
    ['not a string', 42],
    ['empty', ''],
    ['two segments', `${goodHeader}.${goodPayload}`],
    ['four segments', `${good}.x`],
    ['empty header', `.${goodPayload}.${goodSignature}`],
    ['empty payload', `${goodHeader}..${goodSignature}`],
    ['padding in a segment', `${goodHeader}=.${goodPayload}.${goodSignature}`],
    ['standard base64 alphabet', `${goodHeader}.${goodPayload}.${goodSignature.replace(/-/g, '+').replace(/_/g, '/')}+`],
    ['whitespace', `${goodHeader} .${goodPayload}.${goodSignature}`],
    ['header is not JSON', `${b64u('{alg:')}.${goodPayload}.${goodSignature}`],
    ['payload is an array', `${goodHeader}.${segment([1, 2])}.${goodSignature}`],
    ['payload is a string', `${goodHeader}.${segment('sub')}.${goodSignature}`],
    ['payload is null', `${goodHeader}.${segment(null)}.${goodSignature}`],
    ['header has no alg', `${segment({ typ: 'JWT' })}.${goodPayload}.${goodSignature}`],
    ['header alg is not a string', `${segment({ alg: 256 })}.${goodPayload}.${goodSignature}`],
    ['payload is not UTF-8', `${goodHeader}.${b64u(Uint8Array.of(0x7b, 0xc0, 0x80, 0x7d))}.${goodSignature}`],
    ['oversized', `${goodHeader}.${'A'.repeat(70000)}.${goodSignature}`],
  ])('%s', (_name, token) => {
    expect(() => verify(token as string, SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });

  it('names JWE when it sees five segments', () => {
    expect(() => verify('a.b.c.d.e', SECRET_32)).toThrow(/JWE/);
  });

  it('rejects non-canonical base64url (non-zero trailing bits) in the signature', () => {
    // The last character of a 43-character segment carries two unused bits.
    const last = goodSignature[goodSignature.length - 1] as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    // Flipping the lowest bit sets one of the unused bits and keeps a valid character.
    const twin = alphabet[alphabet.indexOf(last) ^ 1] as string;
    expect(() => verify(`${goodHeader}.${goodPayload}.${goodSignature.slice(0, -1)}${twin}`, SECRET_32)).toThrow(
      code('ERR_JWT_MALFORMED'),
    );
  });
});

describe('algorithm (SC-3)', () => {
  it.each(['none', 'None', 'NONE'])('never accepts alg %s, signed or not', (alg) => {
    const header = segment({ alg, typ: 'JWT' });
    expect(() => verify(`${header}.${goodPayload}.`, SECRET_32)).toThrow(code('ERR_JWT_ALGORITHM'));
    expect(() => verify(`${header}.${goodPayload}.${goodSignature}`, SECRET_32)).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('rejects an unsupported algorithm', () => {
    expect(() => verify(hs256(JSON.stringify({ alg: 'HS1' }), '{}'), SECRET_32)).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('rejects a token whose alg differs from the key, even within the HMAC family', () => {
    const hs512 = nodeSign('HS512', SECRET_32, { sub: 'x' });
    expect(() => verify(hs512, SECRET_32)).toThrow(code('ERR_JWT_ALGORITHM'));
    expect(() => verify(good, SECRET_32, { algorithm: 'HS512' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('rejects an RS256 token verified with a PS256 key and vice versa', () => {
    const pair = nodeKeyPair('rsa');
    const rs = nodeSign('RS256', pair.privateKey, {});
    expect(() => verify(rs, importPEM(pem(pair.publicKey), 'PS256'))).toThrow(code('ERR_JWT_ALGORITHM'));
  });
});

describe('algorithm confusion (SC-4)', () => {
  const pair = nodeKeyPair('rsa');
  const publicPem = pem(pair.publicKey);
  // The classic forgery: alg switched to HS256, HMAC keyed with the public key's text.
  const forged = nodeSign('HS256', publicPem, { sub: 'admin' });

  it('refuses a PEM passed as a string, instead of using it as an HMAC secret', () => {
    expect(() => verify(forged, publicPem)).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => verify(forged, publicPem, { allowShortSecret: true })).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses the forged token against the imported RSA key', () => {
    expect(() => verify(forged, importPEM(publicPem, 'RS256'))).toThrow(code('ERR_JWT_ALGORITHM'));
  });

  it('refuses it through a JWKS too', () => {
    const jwks = createJWKS({ keys: [{ ...(pair.publicKey.export({ format: 'jwk' }) as Jwk), alg: 'RS256', kid: 'k1' }] });
    const withKid = nodeSign('HS256', publicPem, { sub: 'admin' }, { kid: 'k1' });
    expect(() => verify(withKid, jwks)).toThrow(code('ERR_JWT_ALGORITHM'));
  });
});

describe('header', () => {
  it('rejects unknown critical extensions (RFC 7515 §4.1.11)', () => {
    expect(() => verify(hs256(JSON.stringify({ alg: 'HS256', crit: ['exp'] }), '{}'), SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });

  it('rejects unencoded payloads (b64)', () => {
    expect(() => verify(hs256(JSON.stringify({ alg: 'HS256', b64: false }), '{}'), SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });

  it('rejects a non-string kid', () => {
    expect(() => verify(hs256(JSON.stringify({ alg: 'HS256', kid: 1 }), '{}'), SECRET_32)).toThrow(code('ERR_JWT_MALFORMED'));
  });
});

describe('signature', () => {
  it('rejects a wrong key', () => {
    expect(() => verify(good, 'another-32-byte-secret-for-tests')).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });

  it('rejects a stripped signature', () => {
    expect(() => verify(`${goodHeader}.${goodPayload}.`, SECRET_32)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });

  it('rejects a DER-encoded ECDSA signature, which JWS does not use', () => {
    const pair = nodeKeyPair('P-256');
    const input = `${segment({ alg: 'ES256' })}.${segment({ sub: 'x' })}`;
    const der = crypto.sign('sha256', Buffer.from(input), pair.privateKey);
    expect(() => verify(`${input}.${b64u(der)}`, importPEM(pem(pair.publicKey), 'ES256'))).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });

  it('rejects an all-zero ECDSA and Ed25519 signature without throwing anything else', () => {
    const ec = importPEM(pem(nodeKeyPair('P-256').publicKey), 'ES256');
    const ed = importJWK(nodeKeyPair('ed25519').publicKey.export({ format: 'jwk' }) as Jwk);
    expect(() => verify(`${segment({ alg: 'ES256' })}.${goodPayload}.${b64u(new Uint8Array(64))}`, ec)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
    expect(() => verify(`${segment({ alg: 'EdDSA' })}.${goodPayload}.${b64u(new Uint8Array(64))}`, ed)).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
});

describe('payload', () => {
  it('drops __proto__ so a payload cannot reach a prototype', () => {
    const token = hs256('{"alg":"HS256"}', '{"sub":"x","__proto__":{"isAdmin":true},"a":{"__proto__":{"polluted":1}}}');
    const { payload } = verify<Record<string, unknown>>(token, SECRET_32);
    const copy = Object.assign({}, payload) as Record<string, unknown>;
    expect(copy.isAdmin).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(payload, '__proto__')).toBe(false);
  });

  it('treats a string exp as an invalid claim, not as "no expiry"', () => {
    expect(() => verify(hs256('{"alg":"HS256"}', '{"exp":"9999999999"}'), SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
});
