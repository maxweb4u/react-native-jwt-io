/**
 * Regressions for the second review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17, second round"): one pass
 * over the first round's fixes, one from a consumer's side. Each test names
 * its finding.
 */
import type crypto from 'node:crypto';
import {
  createJWKS,
  decodeUnverified,
  importPEM,
  sign,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, pem, SECRET_32 } from './helpers/node';

const option = (name: string) => expect.objectContaining({ code: 'ERR_JWT_OPTION_INVALID', option: name });
const T = 1_700_000_000;
const at = (seconds: number) => new Date(seconds * 1000);
const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');

describe('#2 options.header is checked with the other options', () => {
  it.each([
    ['a payload that is not an object', () => sign(5 as never, SECRET_32, { header: { typ: 5 } }), 'header.typ'],
    ['a short secret', () => sign({}, 'short', { header: { cty: null } }), 'header.cty'],
    ['an object that is not a key', () => sign({}, {} as never, { header: { toJSON: () => ({ crit: ['x'] }) } }), 'header'],
    ['a BigInt', () => sign({}, 'short', { header: { x: BigInt(1) } }), 'header'],
  ])('%s does not hide it', (_name, call, name) => {
    expect(call).toThrow(option(name));
  });

  it('an explicit header kid beats the key\'s; keyId and a different header kid conflict', () => {
    const key = importPEM(pem(ec.privateKey), 'ES256', { kid: 'k1' });
    expect(decodeUnverified(sign({}, key)).header.kid).toBe('k1');
    expect(decodeUnverified(sign({}, key, { header: { kid: 'x' } })).header.kid).toBe('x');
    expect(decodeUnverified(sign({}, key, { keyId: 'y' })).header.kid).toBe('y');
    expect(decodeUnverified(sign({}, key, { keyId: 'y', header: { kid: 'y' } })).header.kid).toBe('y');
    expect(() => sign({}, key, { keyId: 'y', header: { kid: 'x' } })).toThrow(option('keyId'));
  });
});

describe('#3 expiresIn under a second is refused, as maxTokenAge 0 is', () => {
  it.each([0, 0.5, '0s', '0.9s'])('%p', (expiresIn) => {
    expect(() => sign({}, SECRET_32, { expiresIn })).toThrow(option('expiresIn'));
  });

  it('notBefore 0 is fine: nbf = iat', () => {
    const { payload } = decodeUnverified(sign({}, SECRET_32, { now: at(T), notBefore: 0 }));
    expect([payload.iat, payload.nbf]).toEqual([T, T]);
  });
});

describe('#5 escaping in messages covers the other line breaks', () => {
  it.each([' ', ' ', '\u0085', '\u009b'])('%j in a kid or an alg', (character) => {
    const set = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid: 'k1' }] });
    const kidToken = `${b64u(JSON.stringify({ alg: 'ES256', kid: `x${character}FAKE` }))}.${b64u('{}')}.AAAA`;
    const algToken = `${b64u(JSON.stringify({ alg: `x${character}FAKE` }))}.${b64u('{}')}.AAAA`;
    for (const [token, key] of [
      [kidToken, set],
      [algToken, SECRET_32],
    ] as const) {
      let message = '';
      try {
        verify(token, key);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain('FAKE');
      expect(message).not.toContain(character);
    }
  });

  it('in every kid message of a key set', () => {
    const kid = 'k x';
    const skippedSet = createJWKS({ keys: [{ kty: 'RSA', kid, n: 'AQAB', e: 'AQAB', alg: 'RS256' }] });
    const twoSet = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid }, { ...jwkOf(ec.publicKey), kid }] });
    const otherAlg = createJWKS({ keys: [{ ...jwkOf(rsa.publicKey), kid, alg: 'RS256' }] });
    const token = `${b64u(JSON.stringify({ alg: 'ES256', kid }))}.${b64u('{}')}.AAAA`;
    for (const set of [skippedSet, twoSet, otherAlg]) {
      let message = '';
      try {
        verify(token, set);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain('k\\u2028x');
    }
  });
});

describe('#10 boundaries the mutants found unpinned', () => {
  it('now and computed times may reach 1e11 seconds, not pass it', () => {
    expect(() => sign({}, SECRET_32, { now: new Date(1e14), noTimestamp: true })).not.toThrow();
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 + 1000) })).toThrow(option('now'));
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 - 60_000), expiresIn: 60 })).not.toThrow();
    expect(() => sign({}, SECRET_32, { now: new Date(1e14 - 60_000), expiresIn: 61 })).toThrow(option('expiresIn'));
  });

  it('a millisecond iat is named before a millisecond exp', () => {
    expect(() => sign({ exp: Date.now() + 60_000, iat: Date.now() }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'iat' }));
    expect(() => sign({ nbf: Date.now(), exp: Date.now() }, SECRET_32)).toThrow(expect.objectContaining({ claim: 'exp' }));
  });
});
