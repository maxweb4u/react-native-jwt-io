/**
 * Tests that kill the mutants of the second review round's code
 * which survived the suite: each names its mutant (K2:<id>) and fails if that
 * check is removed or weakened. The five equivalent mutants are described in
 * memory_bank/engineering/testing-policy.md#mutation-testing.
 */
import crypto from 'node:crypto';
import * as api from '../index';
import { createJWKS, importJWK, importPEM, isExpired, sign, verify } from '../index';
import { type Jwk } from '../types/jwt';
import { describeValue } from '../utils/describe';
import { b64u, nodeKeyPair, pem, SECRET_32, tlv } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
const toPem = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----`;
const refused = (key: string | Uint8Array) => expect(() => sign({}, key)).toThrow(/passed as a secret/);
const works = (key: string | Uint8Array) => expect(verify(sign({ a: 1 }, key), key).payload.a).toBe(1);
const fill = (n: number, byte = 0x41) => new Uint8Array(n).fill(byte);
/** An unsigned big-endian integer of `length` bytes: top byte `top`, last byte 1, zeros between. */
const bigBytes = (length: number, top: number) => {
  const out = new Uint8Array(length);
  out[0] = top;
  out[length - 1] = 1;
  return out;
};

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');
const spki = rsa.publicKey.export({ type: 'spki', format: 'der' });

describe('key material passed as a secret', () => {
  it('K2:RK1 PEM armor with three dashes', () => {
    refused(pem(rsa.publicKey).replace(/-----/g, '---'));
  });

  it('K2:RK5,RK6,RK7,RK8,RK9 every OpenSSH public key form, also after leading whitespace', () => {
    refused('\n  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host');
    refused('ssh-ed448 AAAACXNzaC1lZDQ0OAAAADkA0000000000000000000000000000000000000000000000000000 me@host');
    refused('ssh-dss AAAAB3NzaC1kc3MAAACBAP0000000000000000000000000000000000000000000000 me@host');
    refused('ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBA000000 me@host');
    refused('sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAI000000 me@host');
  });

  it('K2:RK11,RK12,RK13 JWK-like text that is not valid JSON (trailing commas) still counts', () => {
    refused('[{"kty": "RSA", "e": "AQAB", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",}]');
    refused('\n{"kty": "RSA", "e": "AQAB", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiA",}');
  });

  it('K2:RK15 an escaped "kty" after leading whitespace', () => {
    refused(`  \n${JSON.stringify(jwkOf(rsa.publicKey)).replace('"kty"', '"k\\u0074y"')}`);
  });

  it('K2:RK16,RK17 an array of JWKs with "kty" escaped', () => {
    refused(`[${JSON.stringify(jwkOf(rsa.publicKey)).replace('"kty"', '"k\\u0074y"')}]`);
  });

  it('K2:RK17 a JSON array whose first element is not an object is not a JWK (an array has an inherited "keys")', () => {
    works(JSON.stringify(Array.from({ length: 16 }, (_, i) => i * 1000)));
  });

  it('K2:RK18 a JWKS with "keys" escaped', () => {
    refused(JSON.stringify({ keys: [jwkOf(rsa.publicKey)] }).replace('"keys"', '"k\\u0065ys"').replace('"kty"', '"k\\u0074y"'));
  });

  it('a JSON array of arrays is a secret, not a JWK (Array.prototype.keys is inherited)', () => {
    works('[["a-32-byte-secret-for-hs256-tests"]]');
    works('[[], [], [], [], [], [], [], [], [], [], [], []]');
  });

  it('K2:RK22,RK23 a string with a character above U+00FF is not Latin-1 DER, wherever the character is', () => {
    const latin = spki.toString('latin1');
    const bump = (i: number) => latin.slice(0, i) + String.fromCharCode(latin.charCodeAt(i) + 256) + latin.slice(i + 1);
    works(bump(100)); // RK22: the loop must stop at the first such character
    works(bump(latin.length - 1)); // RK23: a truncated copy must not be pushed
  });

  it('K2:RK31 DER as upper-case hex', () => {
    refused(spki.toString('hex').toUpperCase());
  });

  it('K2:RK32 PEM bytes whose armor crosses the 4096-byte chunk boundary', () => {
    // "-----BEGIN": the "E" lands on index 4095, the last byte of the first chunk.
    refused(Uint8Array.from(Buffer.concat([Buffer.alloc(4089, 'x'), Buffer.from(pem(rsa.publicKey))])));
  });

  it('K2:RK33 a 1 MiB byte secret does not overflow the argument list', () => {
    works(fill(1 << 20, 7));
  });

  it('K2:PK3,PK4,PK5,PK6 only SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING } is taken for a certificate', () => {
    const seq = tlv(0x30, fill(20));
    const bits = tlv(0x03, Uint8Array.of(0, ...fill(20)));
    works(tlv(0x30, seq, seq, tlv(0x04, fill(20)))); // PK3
    works(tlv(0x30, seq, tlv(0x04, fill(20)), bits)); // PK4
    works(tlv(0x30, tlv(0x02, Uint8Array.of(0)), seq, bits)); // PK5
    works(tlv(0x30, seq, seq, bits, tlv(0x05))); // PK6
  });

  it('K2:PK7 a key of an unsupported algorithm or curve is still a key', () => {
    refused(Uint8Array.from(crypto.generateKeyPairSync('ed448').publicKey.export({ type: 'spki', format: 'der' })));
    const p224 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp224r1' });
    refused(Uint8Array.from(p224.publicKey.export({ type: 'spki', format: 'der' })));
  });

  it('K2:PK11 DER PKCS#1 RSA private key bytes', () => {
    refused(Uint8Array.from(rsa.privateKey.export({ type: 'pkcs1', format: 'der' })));
  });

  it('K2:PK12 DER SEC1 EC private key bytes', () => {
    refused(Uint8Array.from(ec.privateKey.export({ type: 'sec1', format: 'der' })));
  });
});

describe('error names', () => {
  const errorClasses = Object.entries(api).filter(([name]) => /^Jwt\w*Error$/.test(name)) as [string, new (...args: never[]) => Error][];

  it('K2:E5,E7,E8 name is described like Error.prototype.name: writable, configurable, not enumerable', () => {
    const { value: _value, ...expected } = Object.getOwnPropertyDescriptor(Error.prototype, 'name')!;
    expect(errorClasses).toHaveLength(11);
    for (const [name, errorClass] of errorClasses) {
      const { value, ...descriptor } = Object.getOwnPropertyDescriptor(errorClass.prototype, 'name')!;
      expect([name, value, descriptor]).toEqual([name, name, expected]);
    }
    const error = new api.JwtKeyError('x');
    expect(Object.keys(error)).not.toContain('name');
    error.name = 'Renamed';
    expect(error.name).toBe('Renamed');
  });
});

describe('describeValue', () => {
  it('K2:DS1 a string of exactly 64 characters is not cut', () => {
    expect(describeValue('a'.repeat(64))).toBe(JSON.stringify('a'.repeat(64)));
    expect(describeValue('a'.repeat(65))).toBe(JSON.stringify(`${'a'.repeat(64)}…`));
  });
  it('K2:DS3 an object whose JSON is 65 characters is cut at 64', () => {
    const value = { a: 'b'.repeat(57) };
    expect(JSON.stringify(value)).toHaveLength(65);
    expect(describeValue(value)).toBe(`${JSON.stringify(value).slice(0, 64)}…`);
    expect(describeValue({ a: 'b'.repeat(56) })).toBe(JSON.stringify({ a: 'b'.repeat(56) }));
  });
  it('K2:DS5,DS6,DS7 values JSON cannot show are named by kind', () => {
    expect(describeValue([BigInt(1)])).toBe('an array');
    expect(describeValue({ a: BigInt(1) })).toBe('an object');
    expect(describeValue(() => 1)).toBe('a function');
    expect(describeValue(Symbol('s'))).toBe('a symbol');
  });
});

describe('option hints', () => {
  it('K2:O7 keyid', () => {
    expect(() => sign({}, SECRET_32, { keyid: 'a' } as never)).toThrow(/calls it "keyId"/);
  });
  it('K2:O9 ignoreNotBeforeClaim', () => {
    expect(() => verify(sign({}, SECRET_32), SECRET_32, { ignoreNotBeforeClaim: true } as never)).toThrow(/calls it "ignoreNotBefore"/);
  });
});

describe('RSA sizes', () => {
  it('K2:BY7 leading zero bytes do not count towards a JWK integer size', () => {
    const e = b64u(Uint8Array.of(0, 0, 0, 0, 0, 1, 0, 1));
    expect(importJWK({ ...jwkOf(rsa.publicKey), e }, 'RS256').algorithm).toBe('RS256');
  });
  it('K2:D1 a 16384-bit modulus, with its sign byte, is a valid DER integer', () => {
    const n = tlv(0x02, Uint8Array.of(0, ...bigBytes(2048, 0x80)));
    const key = importPEM(toPem('RSA PUBLIC KEY', tlv(0x30, n, tlv(0x02, Uint8Array.of(1, 0, 1)))), 'RS256');
    expect(key.algorithm).toBe('RS256');
  });
  it('K2:D2 one byte more is refused by the DER reader, before any key check', () => {
    const n = tlv(0x02, Uint8Array.of(0, ...bigBytes(2049, 0x80)));
    expect(() => importPEM(toPem('RSA PUBLIC KEY', tlv(0x30, n, tlv(0x02, Uint8Array.of(1, 0, 1)))), 'RS256')).toThrow(
      /an integer is larger than any supported key uses/,
    );
  });
  it('K2:J1 a JWK "n" is size-checked before it is converted', () => {
    expect(() => importJWK({ kty: 'RSA', n: b64u(bigBytes(2049, 1)), e: 'AQAB' }, 'RS256')).toThrow(/the JWK "n" is longer/);
  });
  it('K2:J4 a JWK "p" is size-checked before it is converted', () => {
    expect(() => importJWK({ ...jwkOf(rsa.privateKey), p: b64u(bigBytes(2049, 1)) }, 'RS256')).toThrow(/the JWK "p" is longer/);
  });
});

describe('JWKS skipped keys', () => {
  const broken = { kty: 'RSA', kid: 'a', n: '!!', e: 'AQAB' };

  it('K2:JS2 an error that is not a JwtKeyError is not swallowed as a skipped key', () => {
    const hostile = {
      kty: 'RSA',
      e: 'AQAB',
      get n(): string {
        throw new TypeError('boom');
      },
    };
    expect(() => createJWKS({ keys: [hostile as unknown as Jwk] })).toThrow(TypeError);
  });
  it('K2:JS4 a skipped key with a non-string kid is listed without one', () => {
    const set = createJWKS({ keys: [{ kty: 'RSA', n: 'AQAB', e: 'AQAB', kid: 5 } as unknown as Jwk] });
    expect(set.skipped).toEqual([{ index: 0, reason: expect.stringMatching(/kid/) }]);
    expect(Object.keys(set.skipped[0]!)).toEqual(['index', 'reason']);
  });
  it('K2:JS8 a kid that names no skipped key is "not found", even when another key was skipped', () => {
    const set = createJWKS({ keys: [broken as Jwk] }, { algorithm: 'RS256' });
    expect(set.skipped).toHaveLength(1);
    expect(() => verify(sign({}, SECRET_32, { keyId: 'b' }), set)).toThrow(code('ERR_JWT_KEY_NOT_FOUND'));
    expect(() => verify(sign({}, SECRET_32, { keyId: 'a' }), set)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
  it('K2:JS9 the no-kid message mentions skipped keys only when there are some', () => {
    const set = createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), alg: 'RS256' }] });
    expect(set.skipped).toHaveLength(0);
    expect(() => verify(sign({}, SECRET_32), set)).toThrow(/no key in the set is for HS256\.$/);
  });
});

describe('isExpired options', () => {
  const token = sign({ exp: 4_000_000_000 }, SECRET_32);
  it('K2:X1 null options mean no options', () => {
    expect(isExpired(token, null as never)).toBe(false);
  });
  it('K2:X3 an option isExpired does not use is refused', () => {
    expect(() => isExpired(token, { maxAge: 10 } as never)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => isExpired(token, { ignoreExpiration: true } as never)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
});
