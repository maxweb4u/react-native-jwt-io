/**
 * Regressions for the findings of the independent review of 2026-10-15
 * (memory_bank/backlog.md, "Review of 2026-10-15"). Each test names its finding.
 */
import crypto from 'node:crypto';
import { readOid, readSingle } from '../keys/der';
import {
  Algorithm,
  createJWKS,
  decodeUnverified,
  hexToBytes,
  importJWK,
  importPEM,
  isExpired,
  JwtErrorCode,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, nodeSign, pem, SECRET_32, tlv } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;
/** A correctly HS256-signed token over arbitrary JSON text. */
function hs256(headerText: string, payloadText: string): string {
  const input = `${b64u(headerText)}.${b64u(payloadText)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', SECRET_32).update(input).digest())}`;
}
const toPem = (label: string, der: Uint8Array) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----`;

describe('#1 an invalid "now" never switches the time checks off', () => {
  const expired = sign({}, SECRET_32, { now: at(T), expiresIn: 10 });

  it.each([new Date('x'), 5, '2026-01-01', null])('verify refuses now = %p', (now) => {
    expect(() => verify(expired, SECRET_32, { now: now as Date })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('isExpired and sign refuse it too', () => {
    expect(() => isExpired(expired, { now: new Date('x') })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => sign({}, SECRET_32, { now: new Date('x') })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
});

describe('#2 an absurd clockTolerance is refused, not treated as infinite', () => {
  const expired = sign({}, SECRET_32, { now: at(T), expiresIn: 10 });

  // A 400-digit string is cut by the length limit first; these reach the arithmetic.
  it.each([1e300, Number.MAX_VALUE, `${'9'.repeat(60)}w`, `${'9'.repeat(63)}s`, 1e11 + 1])(
    'verify and isExpired refuse clockTolerance %p, which would switch exp off',
    (clockTolerance) => {
      expect(() => verify(expired, SECRET_32, { now: at(T + 1e9), clockTolerance })).toThrow(
        expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim: 'clockTolerance' }),
      );
      expect(() => isExpired(expired, { now: at(T + 1e9), clockTolerance })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    },
  );

  it('rejects a string too long to be a duration', () => {
    expect(() => verify(expired, SECRET_32, { clockTolerance: `${'9'.repeat(400)}s` })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });
});

describe('#3 fractional NumericDates are compared exactly', () => {
  it('expires a fractional exp at the fraction, not at the next second', () => {
    const token = hs256('{"alg":"HS256"}', `{"exp":${T}.5}`);
    expect(verify(token, SECRET_32, { now: new Date(T * 1000 + 400) }).payload.exp).toBe(T + 0.5);
    expect(() => verify(token, SECRET_32, { now: new Date(T * 1000 + 700) })).toThrow(code('ERR_JWT_EXPIRED'));
  });

  it('accepts a fractional iat issued a moment ago', () => {
    const token = hs256('{"alg":"HS256"}', `{"iat":${T}.2}`);
    expect(verify(token, SECRET_32, { now: new Date(T * 1000 + 500) }).payload.iat).toBe(T + 0.2);
  });
});

describe('#4 "algorithm" constrains a key set too', () => {
  it('refuses a token whose key in the set is for another algorithm', () => {
    const ec = nodeKeyPair('P-256');
    const set = createJWKS({ keys: [jwkOf(ec.publicKey)] });
    const token = nodeSign('ES256', ec.privateKey, { a: 1 });
    expect(verify(token, set).header.alg).toBe('ES256');
    expect(() => verify(token, set, { algorithm: 'HS512' })).toThrow(code('ERR_JWT_ALGORITHM'));
  });
});

describe('#5 duplicate kids are ambiguous, not a guess', () => {
  it('refuses to pick between two keys with the same kid and alg', () => {
    const a = nodeKeyPair('P-256');
    const b = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const set = createJWKS({ keys: [{ ...jwkOf(a.publicKey), kid: 'k' }, { ...jwkOf(b.publicKey), kid: 'k' }] });
    expect(() => verify(nodeSign('ES256', b.privateKey, {}, { kid: 'k' }), set)).toThrow(code('ERR_JWT_KEY_NOT_FOUND'));
  });
});

describe('#6 RSA keys are checked at import', () => {
  const rsa = nodeKeyPair('rsa');
  const priv = jwkOf(rsa.privateKey);
  const other = jwkOf(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey);

  it('refuses an even modulus and an out-of-range d', () => {
    const n = BigInt(`0x${Buffer.from(priv.n as string, 'base64url').toString('hex')}`);
    const even = Buffer.from((n + BigInt(1)).toString(16), 'hex').toString('base64url');
    expect(() => importJWK({ kty: 'RSA', n: even, e: 'AQAB' }, 'RS256')).toThrow(/odd/);
    expect(() => importJWK({ kty: 'RSA', n: priv.n, e: 'AQAB', d: 'AQ' }, 'RS256')).toThrow(/out of range/);
    expect(() => importJWK({ kty: 'RSA', n: priv.n, e: 'AQAB', d: priv.n }, 'RS256')).toThrow(/out of range/);
  });

  it('refuses a JWK whose private parts do not belong together', () => {
    expect(() => importJWK({ ...priv, d: other.d }, 'RS256')).toThrow(/belong together/);
  });

  it('refuses a PKCS#1 PEM whose private parts do not belong together', () => {
    // Node accepts the mismatched JWK and re-encodes it, so the PEM carries the wrong d.
    const mismatched = crypto.createPrivateKey({ key: { ...priv, d: other.d } as crypto.JsonWebKey, format: 'jwk' });
    const pkcs1 = mismatched.export({ type: 'pkcs1', format: 'pem' }) as string;
    expect(() => importPEM(pkcs1, 'RS256')).toThrow(/belong together/);
  });

  it('turns a signing failure inside the crypto package into a JwtKeyError', () => {
    // d = 2 is in range and the JWK has no primes, so import cannot tell; signing can.
    const key = importJWK({ kty: 'RSA', n: priv.n, e: 'AQAB', d: 'Ag' }, 'RS256');
    expect(() => sign({}, key)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('#7 importPEM refuses a non-string kid', () => {
  it('throws instead of writing kid: 5 into tokens it then rejects', () => {
    const ec = nodeKeyPair('P-256');
    // @ts-expect-error kid must be a string
    expect(() => importPEM(pem(ec.privateKey), 'ES256', { kid: 5 })).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('#8 caller mistakes are JwtErrors, not TypeErrors', () => {
  const token = sign({}, SECRET_32);

  it('treats null options as no options', () => {
    // @ts-expect-error null is not an options object
    expect(verify(token, SECRET_32, null).header.alg).toBe('HS256');
    // @ts-expect-error null is not an options object
    expect(sign({}, SECRET_32, null)).toMatch(/^ey/);
  });

  it('names a malformed option', () => {
    // @ts-expect-error audience cannot be null
    expect(() => sign({}, SECRET_32, { audience: null })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    // @ts-expect-error issuer must be a string
    expect(() => sign({}, SECRET_32, { issuer: 5 })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    // @ts-expect-error audience must be strings
    expect(() => verify(token, SECRET_32, { audience: 5 })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => hexToBytes('zz')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});

describe('#9 registered claims and header fields have the types the API promises', () => {
  it.each([
    ['{"sub":{"id":1}}', 'sub'],
    ['{"iss":5}', 'iss'],
    ['{"jti":[]}', 'jti'],
    ['{"aud":[1,"a"]}', 'aud'],
    ['{"aud":{}}', 'aud'],
    ['{"nbf":"soon"}', 'nbf'],
  ])('payload %s is refused for its %s', (payloadText, claim) => {
    const token = hs256('{"alg":"HS256"}', payloadText);
    expect(() => verify(token, SECRET_32)).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim }));
    expect(() => decodeUnverified(token)).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim }));
  });

  it.each(['typ', 'cty', 'kid'])('a non-string header %s is malformed', (name) => {
    expect(() => decodeUnverified(hs256(`{"alg":"HS256","${name}":5}`, '{}'))).toThrow(code('ERR_JWT_MALFORMED'));
  });

  it('sign refuses the same wrong types', () => {
    expect(() => sign({ sub: 123 }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'sub' }));
  });
});

describe('#10 what is signed is what was checked', () => {
  it('refuses a header whose toJSON rewrites alg', () => {
    const header = { toJSON: () => ({ alg: 'none' }) };
    expect(() => sign({}, SECRET_32, { header })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('refuses a payload whose toJSON returns a non-object or wrong types', () => {
    expect(() => sign({ toJSON: () => 'x' }, SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => sign({ toJSON: () => ({ exp: 'never' }) }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'exp' }));
  });
});

describe('#11 DER is read strictly', () => {
  const ec = nodeKeyPair('P-256');
  const rsa = nodeKeyPair('rsa');

  it('refuses unexpected data after a PKCS#8 private key', () => {
    const der = ec.privateKey.export({ type: 'pkcs8', format: 'der' });
    // Append NULL inside the outer SEQUENCE, re-encoding its length.
    const bad = tlv(0x30, readSingle(der, 0x30).content, Uint8Array.of(0x05, 0x00));
    expect(importPEM(toPem('PRIVATE KEY', tlv(0x30, readSingle(der, 0x30).content)), 'ES256').type).toBe('private');
    expect(() => importPEM(toPem('PRIVATE KEY', bad), 'ES256')).toThrow(/unexpected data after the private key/);
  });

  it('refuses non-NULL RSA algorithm parameters', () => {
    const der = Buffer.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
    const at = der.indexOf(Buffer.from([0x05, 0x00]));
    der[at] = 0x04; // NULL → empty OCTET STRING
    expect(() => importPEM(toPem('PUBLIC KEY', der), 'RS256')).toThrow(code('ERR_JWT_KEY_INVALID'));
  });

  it('refuses non-minimal lengths and integers', () => {
    const der = Buffer.from(rsa.publicKey.export({ type: 'pkcs1', format: 'der' }));
    // 30 82 01 0a → long form is fine here; re-encode e (02 03 01 00 01) with a leading zero.
    const e = der.indexOf(Buffer.from([0x02, 0x03, 0x01, 0x00, 0x01]));
    const padded = Buffer.concat([der.subarray(0, e), Buffer.from([0x02, 0x04, 0x00, 0x01, 0x00, 0x01])]);
    const fixed = Buffer.from(padded);
    fixed.writeUInt16BE(fixed.readUInt16BE(2) + 1, 2);
    expect(() => importPEM(toPem('RSA PUBLIC KEY', fixed), 'RS256')).toThrow(/non-minimal/);
    const longShort = Buffer.from([0x30, 0x81, 0x03, 0x02, 0x01, 0x01]);
    expect(() => importPEM(toPem('RSA PUBLIC KEY', longShort), 'RS256')).toThrow(/non-minimal/);
  });

  it('decodes a multi-byte first OID subidentifier', () => {
    expect(readOid({ tag: 0x06, content: Uint8Array.from([0x88, 0x37, 0x03]) })).toBe('2.999.3');
    expect(readOid({ tag: 0x06, content: Uint8Array.from([0x2a, 0x86, 0x48]) })).toBe('1.2.840');
  });
});

describe('#12 key_ops is honoured', () => {
  it('skips a JWK whose key_ops excludes sign and verify', () => {
    const jwk = { ...jwkOf(nodeKeyPair('P-256').publicKey), key_ops: ['encrypt'] };
    expect(() => importJWK(jwk)).toThrow(/key_ops/);
    expect(importJWK({ ...jwk, key_ops: ['verify'] }).algorithm).toBe('ES256');
  });
});

describe('#13 an RSASSA-PSS key is bound to PS* only', () => {
  it('refuses RS256 for a key whose OID is id-RSASSA-PSS', () => {
    const pss = crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
    const spki = pem(pss.publicKey);
    expect(() => importPEM(spki, 'RS256')).toThrow(/RSASSA-PSS/);
    const token = nodeSign('PS256', pss.privateKey, { sub: 'pss' });
    expect(verify(token, importPEM(spki, 'PS256')).payload.sub).toBe('pss');
  });
});

describe('#15 results and constants are frozen', () => {
  it('freezes header, payload and the exported constant objects', () => {
    const { header, payload } = verify(sign({ a: 1 }, SECRET_32), SECRET_32);
    expect(Object.isFrozen(header) && Object.isFrozen(payload)).toBe(true);
    expect(Object.isFrozen(Algorithm) && Object.isFrozen(JwtErrorCode)).toBe(true);
  });
});

describe('#16 computed times are checked like given ones', () => {
  it('refuses an expiresIn that overflows into an implausible exp', () => {
    // The longest duration accepted, added to now, is past the plausible range.
    expect(() => sign({}, SECRET_32, { expiresIn: 1e11 })).toThrow(expect.objectContaining({ claim: 'exp' }));
    expect(() => sign({}, SECRET_32, { expiresIn: 1e300 })).toThrow(expect.objectContaining({ claim: 'expiresIn' }));
  });
});

describe('speculative: a PEM passed as bytes is not an HMAC secret', () => {
  it('refuses PEM text in a Uint8Array', () => {
    const bytes = Uint8Array.from(Buffer.from(pem(nodeKeyPair('rsa').publicKey)));
    expect(() => verify(sign({}, SECRET_32), bytes)).toThrow(code('ERR_JWT_KEY_INVALID'));
  });
});
