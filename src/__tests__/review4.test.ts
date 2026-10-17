/**
 * Regressions for the review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17"). Each test names its
 * finding.
 */
import type crypto from 'node:crypto';
import {
  createJWKS,
  JwtAlgorithmError,
  verify,
} from '../index';
import { type Jwk } from '../types/jwt';
import { b64u, nodeKeyPair, SECRET_32 } from './helpers/node';

const jwkOf = (key: crypto.KeyObject) => key.export({ format: 'jwk' }) as Jwk;

const ec = nodeKeyPair('P-256');

describe('#10 what an unverified token says reaches error messages escaped', () => {
  const injected = 'x"\n2026-10-17T00:00:00Z INFO login ok user=admin\u001b[2J';
  const messageOf = (call: () => unknown): string => {
    try {
      call();
      return '';
    } catch (error) {
      return (error as Error).message;
    }
  };
  /** No raw line break or escape character: a log line cannot be forged with it. */
  const clean = (message: string) => message.length > 0 && !message.includes('\n') && !message.includes('\u001b');

  it('alg', () => {
    const token = `${b64u(JSON.stringify({ alg: injected }))}.${b64u('{}')}.AAAA`;
    expect(() => verify(token, SECRET_32)).toThrow(JwtAlgorithmError);
    expect(clean(messageOf(() => verify(token, SECRET_32)))).toBe(true);
  });

  it('kid', () => {
    const set = createJWKS({ keys: [{ ...jwkOf(ec.publicKey), kid: 'k1' }] });
    const token = `${b64u(JSON.stringify({ alg: 'ES256', kid: injected }))}.${b64u('{}')}.AAAA`;
    expect(() => verify(token, set)).toThrow(/^No key in the set has kid "x\\"\\n/);
    expect(clean(messageOf(() => verify(token, set)))).toBe(true);
  });
});

