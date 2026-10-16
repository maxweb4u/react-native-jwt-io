/**
 * Signing options and claim validation: SC-5, SC-7, SC-8, SC-16, FM-3.
 * See memory_bank/domain/validation.md.
 */
import crypto from 'node:crypto';
import { decodeUnverified, getExpiration, hexToBytes, isExpired, sign, verify } from '../index';
import { SECRET_32 } from './helpers/node';

const code = (c: string) => expect.objectContaining({ code: c });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);

describe('sign', () => {
  it('sets iat to the signing time, and exp/nbf relative to it', () => {
    const { payload } = decodeUnverified(sign({ sub: 'u' }, SECRET_32, { now: at(T), expiresIn: '15m', notBefore: 10 }));
    expect(payload).toEqual({ sub: 'u', iat: T, exp: T + 900, nbf: T + 10 });
  });

  it('omits iat with noTimestamp, and keeps a caller-supplied iat', () => {
    expect(decodeUnverified(sign({}, SECRET_32, { noTimestamp: true })).payload.iat).toBeUndefined();
    expect(decodeUnverified(sign({ iat: 5 }, SECRET_32, { now: at(T) })).payload.iat).toBe(5);
  });

  it('writes the registered claims from options', () => {
    const token = sign({}, SECRET_32, { issuer: 'i', subject: 's', audience: ['a', 'b'], jwtId: 'j', noTimestamp: true });
    expect(decodeUnverified(token).payload).toEqual({ iss: 'i', sub: 's', aud: ['a', 'b'], jti: 'j' });
  });

  it('refuses a claim set twice', () => {
    expect(() => sign({ exp: T }, SECRET_32, { expiresIn: 60 })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => sign({ iss: 'a' }, SECRET_32, { issuer: 'b' })).toThrow(code('ERR_JWT_OPTION_INVALID'));
  });

  it('refuses milliseconds where seconds belong (FM-3)', () => {
    expect(() => sign({ exp: Date.now() + 3_600_000 }, SECRET_32)).toThrow(/milliseconds/);
    expect(() => sign({ exp: '1700000000' }, SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('refuses a bad duration', () => {
    expect(() => sign({}, SECRET_32, { expiresIn: '10 fortnights' })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => sign({}, SECRET_32, { expiresIn: -5 })).toThrow(code('ERR_JWT_OPTION_INVALID'));
  });

  it('takes extra header parameters but never alg, crit or b64', () => {
    expect(decodeUnverified(sign({}, SECRET_32, { header: { cty: 'x', typ: 'at+jwt' } })).header).toEqual({ alg: 'HS256', typ: 'at+jwt', cty: 'x' });
    expect(() => sign({}, SECRET_32, { header: { alg: 'none' } })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(() => sign({}, SECRET_32, { header: { crit: ['x'] } })).toThrow(code('ERR_JWT_OPTION_INVALID'));
  });

  it('refuses payloads that are not plain JSON objects', () => {
    // @ts-expect-error not an object
    expect(() => sign('sub', SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => sign(new Date() as unknown as Record<string, unknown>, SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(() => sign({ big: BigInt(1) }, SECRET_32)).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('round-trips non-ASCII text (SC-8)', () => {
    const text = 'Привет 👋 — 你好 — ✓';
    expect(verify(sign({ text }, SECRET_32), SECRET_32).payload.text).toBe(text);
  });
});

describe('secrets', () => {
  it('reads a string secret as UTF-8, never as hex (SC-7, 1.x defect V1-4)', () => {
    const token = sign({}, 'deadbeef', { allowShortSecret: true, noTimestamp: true });
    const [h, p, s] = token.split('.') as [string, string, string];
    const utf8 = crypto.createHmac('sha256', Buffer.from('deadbeef', 'utf8')).update(`${h}.${p}`).digest('base64url');
    expect(s).toBe(utf8);
  });

  it('reproduces 1.x signatures for hex-looking secrets through hexToBytes', () => {
    const asHex = Buffer.from('deadbeef', 'hex');
    const input = `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from('{"id":"u1"}').toString('base64url')}`;
    const v1Token = `${input}.${crypto.createHmac('sha256', asHex).update(input).digest('base64url')}`;
    expect(verify(v1Token, hexToBytes('deadbeef'), { allowShortSecret: true }).payload).toEqual({ id: 'u1' });
  });

  it('refuses short secrets unless allowShortSecret (SC-16)', () => {
    expect(() => sign({}, 'your_secret_key')).toThrow(/at least 32 bytes/);
    const legacy = sign({}, 'your_secret_key', { allowShortSecret: true });
    expect(() => verify(legacy, 'your_secret_key')).toThrow(code('ERR_JWT_KEY_INVALID'));
    expect(verify(legacy, 'your_secret_key', { allowShortSecret: true }).header.alg).toBe('HS256');
    expect(() => sign({}, SECRET_32, { algorithm: 'HS512' })).toThrow(/at least 64 bytes/);
    expect(() => sign({}, '', { allowShortSecret: true })).toThrow(/empty/);
  });

  it('accepts a Uint8Array secret', () => {
    const bytes = crypto.randomBytes(32);
    expect(verify(sign({ a: 1 }, bytes), bytes).payload.a).toBe(1);
  });
});

describe('verify: time claims (SC-5)', () => {
  const token = sign({ sub: 'u' }, SECRET_32, { now: at(T), expiresIn: 100, notBefore: 10 });

  it('accepts a token inside its window', () => {
    expect(verify(token, SECRET_32, { now: at(T + 50) }).payload.sub).toBe('u');
  });

  it('expires exactly at exp', () => {
    expect(verify(token, SECRET_32, { now: at(T + 99) }).payload.sub).toBe('u');
    expect(() => verify(token, SECRET_32, { now: at(T + 100) })).toThrow(code('ERR_JWT_EXPIRED'));
    try {
      verify(token, SECRET_32, { now: at(T + 100) });
    } catch (error) {
      expect((error as { expiredAt: Date }).expiredAt).toEqual(at(T + 100));
    }
  });

  it('is not valid before nbf', () => {
    expect(() => verify(token, SECRET_32, { now: at(T + 9) })).toThrow(code('ERR_JWT_NOT_BEFORE'));
    expect(verify(token, SECRET_32, { now: at(T + 10) }).payload.sub).toBe('u');
  });

  it('honours clockTolerance at both ends', () => {
    expect(verify(token, SECRET_32, { now: at(T + 105), clockTolerance: '10s' }).payload.sub).toBe('u');
    expect(verify(token, SECRET_32, { now: at(T + 5), clockTolerance: 5 }).payload.sub).toBe('u');
    expect(() => verify(token, SECRET_32, { now: at(T + 110), clockTolerance: 10 })).toThrow(code('ERR_JWT_EXPIRED'));
  });

  it('refuses a token issued in the future', () => {
    const future = sign({}, SECRET_32, { now: at(T + 60) });
    expect(() => verify(future, SECRET_32, { now: at(T) })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
    expect(verify(future, SECRET_32, { now: at(T), clockTolerance: 60 }).payload.iat).toBe(T + 60);
  });

  it('enforces maxTokenAge from iat, and requires iat for it', () => {
    const issued = sign({}, SECRET_32, { now: at(T) });
    expect(verify(issued, SECRET_32, { now: at(T + 3599.999), maxTokenAge: '1h' }).payload.iat).toBe(T);
    // The same boundary as exp: at exactly iat + maxTokenAge the token is too old.
    expect(() => verify(issued, SECRET_32, { now: at(T + 3600), maxTokenAge: '1h' })).toThrow(code('ERR_JWT_EXPIRED'));
    expect(() => verify(sign({}, SECRET_32, { noTimestamp: true }), SECRET_32, { maxTokenAge: 60 })).toThrow(code('ERR_JWT_CLAIM_INVALID'));
  });

  it('skips exp and nbf only when told to, and still checks the signature', () => {
    expect(verify(token, SECRET_32, { now: at(T + 1000), ignoreExpiration: true }).payload.sub).toBe('u');
    expect(verify(token, SECRET_32, { now: at(T), ignoreNotBefore: true }).payload.sub).toBe('u');
    expect(() => verify(token, 'another-32-byte-secret-for-tests', { ignoreExpiration: true })).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });

  it('checks claims only after the signature holds', () => {
    const expired = sign({}, SECRET_32, { now: at(T), expiresIn: 1 });
    expect(() => verify(expired, 'another-32-byte-secret-for-tests', { now: at(T + 100) })).toThrow(code('ERR_JWT_SIGNATURE_INVALID'));
  });
});

describe('verify: other claims (SC-5)', () => {
  const token = sign({}, SECRET_32, { issuer: 'https://issuer', audience: ['app', 'web'], subject: 'u1', header: { typ: 'application/at+JWT' } });

  it('matches iss, aud, sub and typ', () => {
    expect(verify(token, SECRET_32, { issuer: ['x', 'https://issuer'], audience: 'web', subject: 'u1', typ: 'at+jwt' }).payload.sub).toBe('u1');
  });

  it.each([
    [{ issuer: 'https://evil' }, 'iss'],
    [{ audience: 'admin' }, 'aud'],
    [{ subject: 'u2' }, 'sub'],
    [{ typ: 'JWT' }, 'typ'],
    [{ requiredClaims: ['jti'] }, 'jti'],
  ])('refuses %j', (options, claim) => {
    expect(() => verify(token, SECRET_32, options)).toThrow(expect.objectContaining({ code: 'ERR_JWT_CLAIM_INVALID', claim }));
  });

  it('returns a frozen result', () => {
    expect(Object.isFrozen(verify(token, SECRET_32))).toBe(true);
  });
});

describe('expiry helpers', () => {
  const token = sign({}, SECRET_32, { now: at(T), expiresIn: 60 });

  it('isExpired and getExpiration read exp without verifying', () => {
    expect(isExpired(token, { now: at(T + 59) })).toBe(false);
    expect(isExpired(token, { now: at(T + 60) })).toBe(true);
    expect(isExpired(token, { now: at(T + 65), clockTolerance: '10s' })).toBe(false);
    expect(() => isExpired(token, { clockTolerance: -1 })).toThrow(code('ERR_JWT_OPTION_INVALID'));
    expect(getExpiration(token)).toEqual(at(T + 60));
  });

  it('treat a token without exp as never expiring', () => {
    const forever = sign({}, SECRET_32);
    expect(isExpired(forever)).toBe(false);
    expect(getExpiration(forever)).toBeNull();
  });

  it('throw on a malformed token', () => {
    expect(() => isExpired('nope')).toThrow(code('ERR_JWT_MALFORMED'));
  });
});
