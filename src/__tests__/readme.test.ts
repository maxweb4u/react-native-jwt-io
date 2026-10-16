/**
 * The README's examples, run as written (with fixture keys), so the
 * documentation cannot drift from the API.
 */
import crypto from 'node:crypto';
import jwt, {
  createJWKS,
  decodeUnverified,
  getExpiration,
  hexToBytes,
  importJWK,
  importPEM,
  isExpired,
  JwtError,
  JwtOptionError,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { nodeKeyPair, nodeSign, pem, SECRET_32, SECRET_64 } from './helpers/node';

it('Read a token from your server', () => {
  const accessToken = sign({ sub: 'u1', roles: ['admin'] }, SECRET_32, { expiresIn: '1h' });
  const { payload } = decodeUnverified<{ sub: string; roles: string[] }>(accessToken);
  expect(payload.roles).toEqual(['admin']);
  expect(isExpired(accessToken, { clockTolerance: '30s' })).toBe(false);
  expect(getExpiration(accessToken)).toBeInstanceOf(Date);
});

it('Verify with a public key', () => {
  const rsa = nodeKeyPair('rsa');
  const token = nodeSign('RS256', rsa.privateKey, { sub: 'u1', iss: 'https://auth.example.com', aud: 'my-app' });
  const key = importPEM(pem(rsa.publicKey), 'RS256');
  const { header, payload } = verify<{ sub: string }>(token, key, {
    issuer: 'https://auth.example.com',
    audience: 'my-app',
    clockTolerance: 30,
  });
  expect([header.alg, payload.sub]).toEqual(['RS256', 'u1']);
});

it('Verify with a JWKS', () => {
  const rsa = nodeKeyPair('rsa');
  const json = { keys: [{ ...(rsa.publicKey.export({ format: 'jwk' }) as Jwk), kid: 'k1' }] };
  const token = nodeSign('RS256', rsa.privateKey, { sub: 'u1' }, { kid: 'k1' });
  expect(verify(token, createJWKS(json, { algorithm: 'RS256' })).payload.sub).toBe('u1');
});

it('Sign on the device', () => {
  const devicePrivateJwk = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' }) as Jwk;
  const key = importJWK(devicePrivateJwk);
  const token = sign({ sub: 'device-1' }, key, { expiresIn: '5m', audience: 'api' });
  expect(verify(token, key, { audience: 'api' }).header.alg).toBe('ES256');
});

it('HMAC secrets', () => {
  const token = sign({ sub: 'u1' }, SECRET_32, { expiresIn: '1h' });
  expect(verify(token, SECRET_32).payload.sub).toBe('u1');
  const strong = sign({ sub: 'u1' }, SECRET_64, { algorithm: 'HS512' });
  expect(verify(strong, SECRET_64, { algorithm: 'HS512' }).header.alg).toBe('HS512');
});

it('Migrating from 1.x', () => {
  expect(() => jwt.encode()).toThrow(/sign\(payload, key, options\)/);
  const legacy = sign({ id: 'u1' }, hexToBytes('deadbeef'), { allowShortSecret: true });
  expect(verify(legacy, hexToBytes('deadbeef'), { allowShortSecret: true }).payload.id).toBe('u1');
});

it('Errors: keep JwtOptionError apart from a bad token', () => {
  const rsa = nodeKeyPair('rsa');
  const key = importPEM(pem(rsa.publicKey), 'RS256');
  const signOut = () => 'signed out';
  const check = (token: string, options: object) => {
    try {
      return verify(token, key, { issuer: 'https://auth.example.com', ...options });
    } catch (error) {
      if (error instanceof JwtOptionError) throw error; // a bug in the call: let it surface
      if (error instanceof JwtError) return signOut(); // the token is not acceptable
      throw error;
    }
  };
  const good = nodeSign('RS256', rsa.privateKey, { iss: 'https://auth.example.com' });
  const other = nodeSign('RS256', rsa.privateKey, { iss: 'https://elsewhere.example.com' });
  expect(check(good, {})).toMatchObject({ payload: { iss: 'https://auth.example.com' } });
  expect(check(other, {})).toBe('signed out');
  expect(() => check(other, { maxAge: '1h' })).toThrow(JwtOptionError);
});
