/**
 * Regressions for the second review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17, second round"): one pass
 * over the first round's fixes, one from a consumer's side. Each test names
 * its finding.
 */
import type crypto from 'node:crypto';
import {
  createJWKS,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, SECRET_32 } from './helpers/node';

const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

const rsa = nodeKeyPair('rsa');
const ec = nodeKeyPair('P-256');

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

