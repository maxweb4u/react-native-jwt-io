/**
 * SC-1: every algorithm, both directions, against Node's crypto — with keys
 * imported from PEM and from JWK.
 */
import { decodeUnverified, importJWK, importPEM, sign, verify } from '../index';
import { type Algorithm } from '../types/algorithm';
import { type Jwk } from '../types/jwt';
import { KEY_KIND, nodeKeyPair, nodeSign, nodeVerify, pem, SECRET_32, SECRET_48, SECRET_64 } from './helpers/node';

const ASYMMETRIC = Object.keys(KEY_KIND) as (keyof typeof KEY_KIND)[];
const HMAC: [Algorithm, string][] = [
  ['HS256', SECRET_32],
  ['HS384', SECRET_48],
  ['HS512', SECRET_64],
];
const payload = { sub: 'interop', name: 'Привет 👋', nested: { a: [1, 2, 3] } };

describe.each(HMAC)('%s', (alg, secret) => {
  const options = { algorithm: alg as 'HS256' };

  it('signs tokens Node verifies', () => {
    const token = sign(payload, secret, options);
    expect(nodeVerify(alg, secret, token)).toBe(true);
  });

  it('verifies tokens Node signs', () => {
    const token = nodeSign(alg, secret, payload);
    expect(verify(token, secret, options).payload).toEqual(payload);
  });

  it('accepts the secret as an oct JWK', () => {
    const jwk: Jwk = { kty: 'oct', k: Buffer.from(secret).toString('base64url'), alg };
    const token = nodeSign(alg, secret, payload);
    expect(verify(token, importJWK(jwk)).payload.sub).toBe('interop');
  });
});

describe.each(ASYMMETRIC)('%s', (alg) => {
  const pair = nodeKeyPair(KEY_KIND[alg]);
  const privatePem = importPEM(pem(pair.privateKey), alg);
  const publicPem = importPEM(pem(pair.publicKey), alg);
  const privateJwk = importJWK(pair.privateKey.export({ format: 'jwk' }) as Jwk, alg);
  const publicJwk = importJWK(pair.publicKey.export({ format: 'jwk' }) as Jwk, alg);

  it('signs tokens Node verifies (PEM key)', () => {
    const token = sign(payload, privatePem);
    expect(decodeUnverified(token).header.alg).toBe(alg);
    expect(nodeVerify(alg, pair.publicKey, token)).toBe(true);
  });

  it('signs tokens Node verifies (JWK key)', () => {
    expect(nodeVerify(alg, pair.publicKey, sign(payload, privateJwk))).toBe(true);
  });

  it('verifies tokens Node signs, with PEM and JWK public keys', () => {
    const token = nodeSign(alg, pair.privateKey, payload);
    expect(verify(token, publicPem).payload).toEqual(payload);
    expect(verify(token, publicJwk).payload).toEqual(payload);
  });

  it('verifies with the private key too', () => {
    expect(verify(nodeSign(alg, pair.privateKey, payload), privatePem).payload.sub).toBe('interop');
  });

  it('rejects a token whose payload was changed after signing', () => {
    const [h, , s] = nodeSign(alg, pair.privateKey, payload).split('.');
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...payload, sub: 'admin' })).toString('base64url')}.${s}`;
    expect(() => verify(forged, publicPem)).toThrow(expect.objectContaining({ code: 'ERR_JWT_SIGNATURE_INVALID' }));
  });
});

describe('ECDSA signature malleability', () => {
  // noble 2.x rejects high-S signatures by default; OpenSSL produces them about
  // half the time. Twenty Node signatures all but guarantee some are high-S.
  it.each(['ES256', 'ES384', 'ES512', 'ES256K'] as const)('%s accepts every signature Node produces', (alg) => {
    const pair = nodeKeyPair(KEY_KIND[alg]);
    const key = importPEM(pem(pair.publicKey), alg);
    for (let i = 0; i < 20; i++) {
      expect(verify(nodeSign(alg, pair.privateKey, { i }), key).payload.i).toBe(i);
    }
  });
});

describe('deterministic signatures', () => {
  it('RS256 and HS256 match Node byte for byte', () => {
    const pair = nodeKeyPair('rsa');
    const fixed = { sub: 'same', iat: 1700000000 };
    expect(sign(fixed, importPEM(pem(pair.privateKey), 'RS256'))).toBe(nodeSign('RS256', pair.privateKey, fixed));
    expect(sign(fixed, SECRET_32)).toBe(nodeSign('HS256', SECRET_32, fixed));
  });
});

describe('RFC 7515 Appendix A.1 (HS256)', () => {
  // The specification's own example: a header and payload with CRLF
  // whitespace inside the JSON, and an exp in 2011.
  const token =
    'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9' +
    '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
    '.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const key = importJWK({
    kty: 'oct',
    k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
    alg: 'HS256',
  });

  it('verifies, and is expired today', () => {
    expect(verify(token, key, { now: new Date('2011-03-22T00:00:00Z') }).payload).toEqual({
      iss: 'joe',
      exp: 1300819380,
      'http://example.com/is_root': true,
    });
    expect(() => verify(token, key)).toThrow(expect.objectContaining({ code: 'ERR_JWT_EXPIRED' }));
  });
});
