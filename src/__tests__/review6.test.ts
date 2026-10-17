/**
 * Regressions for the third review of 2026-10-17, before 2.0.0-rc.0
 * (memory_bank/backlog.md, "Review of 2026-10-17, third round"): the second
 * round's fixes with mutation testing, RFC conformance with Hermes 0.74, and
 * hostile input with the public API. Each test names its finding.
 */
import crypto from 'node:crypto';
import {
  createJWKS,
  sign,
  verify,
} from '../index';
import { b64u, SECRET_32 } from './helpers/node';

/** An HS256 token over `payload` (JSON text) and `header`, signed with SECRET_32. */
function hs256(payload: string, header = '{"alg":"HS256","typ":"JWT"}'): string {
  const input = `${b64u(header)}.${b64u(payload)}`;
  return `${input}.${b64u(crypto.createHmac('sha256', SECRET_32).update(input).digest())}`;
}

describe('#4 claim mismatch messages are escaped and bounded', () => {
  const evil = `a\u2028FAKE LOG LINE\u0085\u009b31m\u202e${'x'.repeat(20_000)}`;

  it.each<[string, object, object]>([
    ['iss', { iss: evil }, { issuer: 'good' }],
    ['aud', { aud: evil }, { audience: 'good' }],
    ['sub', { sub: evil }, { subject: 'good' }],
  ])('%s', (_, payload, options) => {
    const token = sign(payload, SECRET_32);
    let message = '';
    try {
      verify(token, SECRET_32, options);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message.length).toBeLessThan(200);
    expect(message).not.toMatch(/[\u2028\u0085\u009b\u202e]/);
    expect(message).toContain('\\u2028');
  });

  it('typ', () => {
    const token = sign({}, SECRET_32, { header: { typ: evil } });
    expect(() => verify(token, SECRET_32, { typ: 'JWT' })).toThrow(/^Unexpected header "typ" "a\\u2028FAKE/);
  });
});

describe('#14 messages escape bidirectional and invisible characters', () => {
  it.each(['\u202e', '\u2066', '\u200f', '\u061c', '\ufeff', '\u200b', '\u007f', '\u009f'])('U+%s', (char) => {
    const token = hs256('{}', JSON.stringify({ alg: 'HS256', kid: `evil${char}next` }));
    const set = createJWKS({ keys: [{ kty: 'oct', k: b64u(SECRET_32), alg: 'HS256', kid: 'other' }] });
    let message = '';
    try {
      verify(token, set);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain(`\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
    expect(message).not.toContain(char);
  });

  it('the neighbours are left alone', () => {
    const token = hs256('{}', JSON.stringify({ alg: 'HS256', kid: 'a~b\u00a0c' }));
    const set = createJWKS({ keys: [{ kty: 'oct', k: b64u(SECRET_32), alg: 'HS256', kid: 'other' }] });
    expect(() => verify(token, set)).toThrow('No key in the set has kid "a~b\u00a0c".');
  });
});

