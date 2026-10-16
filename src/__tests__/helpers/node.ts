/**
 * Node's `crypto` as an independent implementation of every algorithm: the
 * interop oracle. Test-only; nothing in src/ outside __tests__ may import it.
 * See memory_bank/engineering/testing-policy.md.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { type Algorithm } from '../../types/algorithm';

export const b64u = (data: string | Uint8Array): string => Buffer.from(data).toString('base64url');

export interface NodeKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

const cache = new Map<string, NodeKeyPair>();

export function nodeKeyPair(kind: 'rsa' | 'rsa1024' | 'P-256' | 'P-384' | 'P-521' | 'secp256k1' | 'ed25519'): NodeKeyPair {
  const cached = cache.get(kind);
  if (cached) {
    return cached;
  }
  let pair: NodeKeyPair;
  if (kind === 'rsa' || kind === 'rsa1024') {
    pair = crypto.generateKeyPairSync('rsa', { modulusLength: kind === 'rsa' ? 2048 : 1024 });
  } else if (kind === 'ed25519') {
    pair = crypto.generateKeyPairSync('ed25519');
  } else {
    pair = crypto.generateKeyPairSync('ec', { namedCurve: kind === 'P-256' ? 'prime256v1' : kind === 'P-384' ? 'secp384r1' : kind === 'P-521' ? 'secp521r1' : 'secp256k1' });
  }
  cache.set(kind, pair);
  return pair;
}

export const KEY_KIND: Record<Exclude<Algorithm, 'HS256' | 'HS384' | 'HS512'>, Parameters<typeof nodeKeyPair>[0]> = {
  RS256: 'rsa',
  RS384: 'rsa',
  RS512: 'rsa',
  PS256: 'rsa',
  PS384: 'rsa',
  PS512: 'rsa',
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
  ES256K: 'secp256k1',
  EdDSA: 'ed25519',
};

export const pem = (key: KeyObject): string =>
  key.type === 'public'
    ? (key.export({ type: 'spki', format: 'pem' }) as string)
    : (key.export({ type: 'pkcs8', format: 'pem' }) as string);

function hashName(alg: Algorithm): string {
  return `sha${alg.slice(2, 5)}`;
}

function nodeSignOptions(alg: Algorithm, key: KeyObject): crypto.SignKeyObjectInput | KeyObject {
  if (alg.startsWith('PS')) {
    return { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(alg.slice(2)) / 8 };
  }
  if (alg.startsWith('ES')) {
    return { key, dsaEncoding: 'ieee-p1363' };
  }
  return key;
}

/** Signs a JWT with Node only. */
export function nodeSign(alg: Algorithm, key: KeyObject | string, payload: object, header: object = {}): string {
  const input = `${b64u(JSON.stringify({ alg, typ: 'JWT', ...header }))}.${b64u(JSON.stringify(payload))}`;
  let signature: Buffer;
  if (alg.startsWith('HS')) {
    signature = crypto.createHmac(hashName(alg), key as string).update(input).digest();
  } else {
    const k = key as KeyObject;
    signature = crypto.sign(alg === 'EdDSA' ? null : hashName(alg), Buffer.from(input), nodeSignOptions(alg, k));
  }
  return `${input}.${b64u(signature)}`;
}

/** Verifies a JWT with Node only. */
export function nodeVerify(alg: Algorithm, key: KeyObject | string, token: string): boolean {
  const [h, p, s] = token.split('.') as [string, string, string];
  const input = Buffer.from(`${h}.${p}`);
  const signature = Buffer.from(s, 'base64url');
  if (alg.startsWith('HS')) {
    const expected = crypto.createHmac(hashName(alg), key as string).update(input).digest();
    return expected.length === signature.length && crypto.timingSafeEqual(expected, signature);
  }
  const k = key as KeyObject;
  return crypto.verify(alg === 'EdDSA' ? null : hashName(alg), input, nodeSignOptions(alg, k), signature);
}

/** One DER TLV, its length in the shortest form, as test inputs are built by hand. */
export function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const content = Buffer.concat(parts);
  const n = content.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Uint8Array.of(tag, ...length), content]);
}

export const SECRET_32 = 'a-32-byte-secret-for-hs256-tests';
export const SECRET_48 = 'a-48-byte-secret-for-hs384-tests-padding-padding';
export const SECRET_64 = 'a-64-byte-secret-for-hs512-tests-padding-padding-padding-padding';
