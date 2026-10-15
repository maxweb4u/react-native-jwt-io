/** base64url, UTF-8 and durations — the parsing everything else stands on. */
import crypto from 'node:crypto';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { hexToBytes } from '../utils/bytes';
import { parseDuration } from '../utils/time';
import { utf8Decode, utf8Encode } from '../utils/utf8';

describe('base64url', () => {
  it('matches Node for every length from 0 to 64', () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = crypto.randomBytes(length);
      const text = Buffer.from(bytes).toString('base64url');
      expect(base64UrlEncode(bytes)).toBe(text);
      expect(Buffer.from(base64UrlDecode(text) as Uint8Array)).toEqual(bytes);
    }
  });

  it.each([
    ['padding', 'QQ=='],
    ['standard alphabet', 'a+b/'],
    ['whitespace', 'QU JD'],
    ['impossible length', 'QUJDR'],
    ['non-zero trailing bits', 'QR'],
    ['non-ASCII', 'QUJDé'],
  ])('rejects %s', (_name, text) => {
    expect(base64UrlDecode(text)).toBeNull();
  });
});

describe('base64 (PEM bodies)', () => {
  it('decodes what Node encodes, with padding', () => {
    for (let length = 0; length <= 10; length++) {
      const bytes = crypto.randomBytes(length);
      const text = Buffer.from(bytes).toString('base64');
      expect(Buffer.from(base64Decode(text) as Uint8Array)).toEqual(bytes);
    }
  });

  it('rejects missing padding and misplaced =', () => {
    expect(base64Decode('QQ')).toBeNull();
    expect(base64Decode('Q=Q=')).toBeNull();
    expect(base64Decode('Q===')).toBeNull();
  });
});

describe('UTF-8', () => {
  it('matches Node for ASCII, Cyrillic, CJK, emoji and a lone surrogate', () => {
    for (const text of ['', 'jwt', 'Привет', '你好', '👋🏽', 'a\uD800b']) {
      const bytes = utf8Encode(text);
      expect(Buffer.from(bytes)).toEqual(Buffer.from(text, 'utf8'));
      expect(utf8Decode(bytes)).toBe(Buffer.from(text, 'utf8').toString('utf8'));
    }
  });

  it.each([
    ['overlong NUL', [0xc0, 0x80]],
    ['overlong slash', [0xe0, 0x80, 0xaf]],
    ['encoded surrogate', [0xed, 0xa0, 0x80]],
    ['above U+10FFFF', [0xf4, 0x90, 0x80, 0x80]],
    ['truncated', [0xe2, 0x82]],
    ['stray continuation', [0x80]],
    ['invalid lead byte', [0xff]],
  ])('rejects %s', (_name, bytes) => {
    expect(utf8Decode(Uint8Array.from(bytes))).toBeNull();
  });
});

describe('durations', () => {
  it.each([
    [90, 90],
    [1.9, 1],
    ['30s', 30],
    ['15m', 900],
    ['2h', 7200],
    ['7d', 604800],
    ['1 week', 604800],
    ['1.5h', 5400],
  ])('%j is %i seconds', (input, seconds) => {
    expect(parseDuration(input)).toBe(seconds);
  });

  it.each([-1, NaN, Infinity, '', '15', '15x', '5 constructor', 'm15'])('%j is not a duration', (input) => {
    expect(parseDuration(input as number | string)).toBeNull();
  });
});

describe('hexToBytes', () => {
  it('decodes and validates', () => {
    expect(Array.from(hexToBytes('DeadBeef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(() => hexToBytes('abc')).toThrow(expect.objectContaining({ code: 'ERR_JWT_KEY_INVALID' }));
    expect(() => hexToBytes('zz')).toThrow(expect.objectContaining({ code: 'ERR_JWT_KEY_INVALID' }));
  });
});
