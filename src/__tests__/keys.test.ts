/**
 * Key import and binding: SC-2, SC-10, SC-12, FM-2.
 * See memory_bank/domain/keys.md.
 */
import crypto from 'node:crypto';
import { createJWKS, importJWK, importPEM, sign, verify } from '../index';
import { type Jwk } from '../types/jwt';
import { nodeKeyPair, nodeSign, pem, SECRET_32 } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');
const ed = nodeKeyPair('ed25519');
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

describe('importPEM', () => {
  it('reads PKCS#1 RSA keys, public and private', () => {
    const privatePkcs1 = rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    const publicPkcs1 = rsa.publicKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    const token = sign({ sub: 'p1' }, importPEM(privatePkcs1, 'RS256'));
    expect(verify(token, importPEM(publicPkcs1, 'RS256')).payload.sub).toBe('p1');
  });

  it('reads SEC1 EC private keys', () => {
    const sec1 = ec.privateKey.export({ type: 'sec1', format: 'pem' }) as string;
    const token = sign({ sub: 's1' }, importPEM(sec1, 'ES256'));
    expect(verify(token, importPEM(pem(ec.publicKey), 'ES256')).payload.sub).toBe('s1');
  });

  it('reports the key type', () => {
    expect(importPEM(pem(rsa.privateKey), 'RS256').type).toBe('private');
    expect(importPEM(pem(rsa.publicKey), 'RS256').type).toBe('public');
    expect(importPEM(pem(rsa.publicKey), 'RS256', { kid: 'k' }).kid).toBe('k');
  });

  it('refuses a key that does not fit the algorithm', () => {
    expect(() => importPEM(pem(ec.publicKey), 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM(pem(ec.publicKey), 'ES384')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey), 'EdDSA')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey), 'HS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('needs the algorithm (SC-2)', () => {
    // @ts-expect-error the algorithm is required
    expect(() => importPEM(pem(rsa.publicKey))).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses RSA keys below 2048 bits (SC-12)', () => {
    const weak = nodeKeyPair('rsa1024');
    expect(() => importPEM(pem(weak.publicKey), 'RS256')).toThrow(/2048/);
    expect(() => importJWK(jwkOf(weak.publicKey), 'RS256')).toThrow(/2048/);
  });

  it('refuses certificates, encrypted keys, garbage, and two blocks', () => {
    expect(() => importPEM('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----', 'RS256')).toThrow(/certificates/);
    const encrypted = rsa.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'x' }) as string;
    expect(() => importPEM(encrypted, 'RS256')).toThrow(/Encrypted/);
    expect(() => importPEM('-----BEGIN PUBLIC KEY-----\n@@@@\n-----END PUBLIC KEY-----', 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM(pem(rsa.publicKey) + pem(rsa.publicKey), 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importPEM('-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----', 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses unsupported curves', () => {
    const p224 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp224r1' });
    expect(() => importPEM(pem(p224.publicKey), 'ES256')).toThrow(/curve/);
  });
});

describe('importJWK binding (SC-2)', () => {
  it('derives the algorithm from the curve', () => {
    expect(importJWK(jwkOf(ec.publicKey)).algorithm).toBe('ES256');
    expect(importJWK(jwkOf(nodeKeyPair('P-521').publicKey)).algorithm).toBe('ES512');
    expect(importJWK(jwkOf(nodeKeyPair('secp256k1').publicKey)).algorithm).toBe('ES256K');
    expect(importJWK(jwkOf(ed.publicKey)).algorithm).toBe('EdDSA');
  });

  it('refuses RSA and oct JWKs with no alg and no argument', () => {
    expect(() => importJWK(jwkOf(rsa.publicKey))).toThrow(/several algorithms/);
    expect(() => importJWK({ kty: 'oct', k: Buffer.from(SECRET_32).toString('base64url') })).toThrow(/several algorithms/);
  });

  it('honours the JWK alg and refuses a contradicting argument', () => {
    const jwk = { ...jwkOf(rsa.publicKey), alg: 'PS256' };
    expect(importJWK(jwk).algorithm).toBe('PS256');
    expect(() => importJWK(jwk, 'RS256')).toThrow(/bound to exactly one/);
  });

  it('refuses encryption keys and unsupported types', () => {
    expect(() => importJWK({ ...jwkOf(rsa.publicKey), use: 'enc' }, 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importJWK(jwkOf(crypto.generateKeyPairSync('x25519').publicKey))).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(() => importJWK({ ...jwkOf(rsa.publicKey), alg: 'RSA-OAEP' })).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses a private key whose d does not match its public part', () => {
    const other = jwkOf(nodeKeyPair('P-256').privateKey);
    const mismatched = { ...jwkOf(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey), d: other.d };
    expect(() => importJWK(mismatched)).toThrow(/does not match/);
  });

  it('refuses a point that is not on the curve, and wrong lengths', () => {
    const jwk = jwkOf(ec.publicKey);
    const bent = Buffer.from(jwk.y as string, 'base64url');
    bent[31] = (bent[31] as number) ^ 1;
    expect(() => importJWK({ ...jwk, y: bent.toString('base64url') })).toThrow(/not a point/);
    expect(() => importJWK({ ...jwk, x: 'AAAA' })).toThrow(/32 bytes/);
  });

  it('refuses plain objects posing as keys', () => {
    const fake = { algorithm: 'HS256', type: 'secret' };
    // @ts-expect-error not a JwtKey
    expect(() => verify(sign({}, SECRET_32), fake)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('createJWKS (SC-10, FM-2)', () => {
  const k1 = { ...jwkOf(rsa.publicKey), kid: 'k1', alg: 'RS256' };
  const k2 = { ...jwkOf(ec.publicKey), kid: 'k2' };
  const enc = { ...jwkOf(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey), kid: 'e1', use: 'enc' };
  const x25519 = { ...jwkOf(crypto.generateKeyPairSync('x25519').publicKey), kid: 'x1' };
  const jwks = createJWKS({ keys: [k1, k2, enc, x25519] });

  it('skips keys that are not for signatures', () => {
    expect(jwks.keys.map((key) => key.kid)).toEqual(['k1', 'k2']);
  });

  it('selects by kid', () => {
    expect(verify(nodeSign('RS256', rsa.privateKey, { sub: 'a' }, { kid: 'k1' }), jwks).payload.sub).toBe('a');
    expect(verify(nodeSign('ES256', ec.privateKey, { sub: 'b' }, { kid: 'k2' }), jwks).payload.sub).toBe('b');
  });

  it('reports an unknown kid distinctly from a bad signature', () => {
    const token = nodeSign('RS256', rsa.privateKey, {}, { kid: 'rotated-away' });
    expect(() => verify(token, jwks)).toThrow(code('ERR_JWT_KEY_NOT_FOUND'));
  });

  it('uses the only key for the alg when the token has no kid, and refuses to guess between two', () => {
    expect(verify(nodeSign('ES256', ec.privateKey, { sub: 'c' }), jwks).payload.sub).toBe('c');
    const two = createJWKS({ keys: [k1, { ...k1, kid: 'k1b' }] });
    expect(() => verify(nodeSign('RS256', rsa.privateKey, {}), two)).toThrow(code('ERR_JWT_KEY_NOT_FOUND'));
  });

  it('needs an algorithm for RSA keys published without alg', () => {
    const bare = { ...jwkOf(rsa.publicKey), kid: 'azure-style' };
    expect(() => createJWKS({ keys: [bare] })).toThrow(/azure-style/);
    expect(createJWKS({ keys: [bare] }, { algorithm: 'RS256' }).keys[0]?.algorithm).toBe('RS256');
  });

  it('refuses a malformed supported key rather than skipping it', () => {
    expect(() => createJWKS({ keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }] })).toThrow(code('ERR_JWT_KEY_INVALID'));
    // @ts-expect-error not a JWKS
    expect(() => createJWKS([k1])).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('using keys', () => {
  it('a public key cannot sign', () => {
    expect(() => sign({}, importPEM(pem(rsa.publicKey), 'RS256'))).toThrow(/public key cannot sign/);
  });

  it('signing writes the key kid into the header', () => {
    const key = importJWK({ ...jwkOf(ec.privateKey), kid: 'device-1' });
    expect(sign({}, key).split('.')[0]).toBe(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'device-1' })).toString('base64url'));
  });

  it('a key cannot be used under another algorithm', () => {
    const key = importPEM(pem(rsa.privateKey), 'RS256');
    // @ts-expect-error algorithm applies to bare secrets only
    expect(() => sign({}, key, { algorithm: 'RS512' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });
});

describe('DER parsing under corruption', () => {
  // Deterministic, so a failure reproduces.
  let seed = 42;
  const random = (max: number) => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % max;
  };
  const toPem = (label: string, der: Uint8Array) =>
    `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----`;

  const samples: [string, Uint8Array, 'RS256' | 'ES256' | 'EdDSA'][] = [
    ['PUBLIC KEY', rsa.publicKey.export({ type: 'spki', format: 'der' }), 'RS256'],
    ['PRIVATE KEY', rsa.privateKey.export({ type: 'pkcs8', format: 'der' }), 'RS256'],
    ['PUBLIC KEY', ec.publicKey.export({ type: 'spki', format: 'der' }), 'ES256'],
    ['EC PRIVATE KEY', ec.privateKey.export({ type: 'sec1', format: 'der' }), 'ES256'],
    ['PRIVATE KEY', ed.privateKey.export({ type: 'pkcs8', format: 'der' }), 'EdDSA'],
  ];

  it.each(samples)('a corrupted %s for %s is a JwtKeyError or a valid key, nothing else', (label, der, alg) => {
    for (let round = 0; round < 400; round++) {
      const bytes = Uint8Array.from(der);
      if (round % 2 === 0) {
        bytes[random(bytes.length)] = random(256);
      }
      const cut = round % 3 === 0 ? bytes.subarray(0, random(bytes.length)) : bytes;
      try {
        importPEM(toPem(label, cut), alg);
      } catch (error) {
        expect(error).toEqual(code('ERR_JWT_KEY_INVALID'));
      }
    }
  });
});
