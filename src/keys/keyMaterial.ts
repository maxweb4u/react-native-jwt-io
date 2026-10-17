import { normalizeEcPublicKey } from '../crypto/curves';
import { base64UrlDecode } from '../utils/base64';
import { hexToBytes } from '../utils/bytes';
import { parseJson } from '../utils/json';
import { type EcCurve } from './JwtKey';
import { isKeyDer } from './pem';

/**
 * Recognises public-key material passed where an HMAC secret is expected —
 * the precondition of RS256-to-HS256 confusion: whoever knows the public key
 * can then forge HS256 tokens. It looks through the forms keys are stored and
 * pasted in, unwrapping them a few levels deep:
 *
 * - PEM armor, anywhere and leniently (any case, any dash, BEGIN or END);
 * - OpenSSH public keys, authorized_keys lines and SSH certificates;
 * - JWK and JWKS JSON, and JSON documents carrying a key (a Keycloak realm);
 * - DER of a key, certificate or PKCS#7, an SSH wire blob, a raw EC point;
 * - each as bytes, or as base64, base64url, hex (`0x`, colons) or Latin-1
 *   text; with a UTF-8 or UTF-16 (either byte order) encoding, literal `\n` escapes, JSON quotes,
 *   URL encoding, or base64 of any of these (as Kubernetes secrets hold them);
 * - text dumps tools write: .NET `RSAKeyValue` XML and XMLDSig, a JWK as YAML,
 *   TOML or INI, `openssl … -text` output, DER as a list of numbers in the
 *   shapes JSON, Java, Go, C, `xxd -i`, Rust, PowerShell and Node write, as a
 *   Python bytes literal, or as a `hexdump -C` or `xxd` dump (added after the
 *   reviews of 2026-10-17).
 *
 * Measured against 425 forms of six key types and 520,000 generated secrets on
 * 2026-10-16: what is left undetected cannot be told from random bytes (a bare
 * RSA modulus, a bare Ed25519 or EC x coordinate). See
 * memory_bank/domain/keys.md#inputs. Every pattern here is linear in the input.
 */
export function describeKeyMaterial(key: string | Uint8Array): string | null {
  return inspect(key, 0);
}

const MAX_DEPTH = 3;

// [-‐‑‒–—―−]{3}, not {3,}: a run of dashes must not make the match quadratic.
const PEM_ARMOR = /[-‐-―−]{3}[ \t]*(?:BEGIN|END)[ \t]+[A-Z0-9]/i;
const SSH_PUBLIC_KEY =
  /(?:^|\s)(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9-]+@openssh\.com)(?:-cert-v01@openssh\.com)?\s+AAAA/;
const JWK_MEMBER = /[{,]\s*['"]?kty['"]?\s*[:=]/;
// The same members as YAML (block or list item) or TOML lines. `[ \t]*`, not
// `\s*`: across lines it would be quadratic. Values are checked as far as they
// can be, so an ordinary config line ("e: x", "crv: abc") is not a key.
const LINE = String.raw`^[ \t]*(?:-[ \t]+)?['"]?`;
// Case-insensitive: an INI or .env file writes KTY=RSA.
const JWK_LINE = new RegExp(`${LINE}kty['"]?[ \\t]*[:=][ \\t]*['"]?(?:RSA|EC|OKP|oct)\\b`, 'mi');
// At least a 1024-bit modulus (171 base64url characters): too small for this
// library to import, not too small to forge HS256 tokens with.
const JWK_MODULUS_LINE = new RegExp(`${LINE}n['"]?[ \\t]*[:=][ \\t]*['"]?[A-Za-z0-9+/_-]{171}`, 'mi');
const JWK_EXPONENT_LINE = new RegExp(`${LINE}e['"]?[ \\t]*[:=][ \\t]*['"]?[A-Za-z0-9+/_-]{1,8}['"]?[ \\t]*,?[ \\t]*$`, 'mi');
const JWK_CURVE_LINE = new RegExp(`${LINE}crv['"]?[ \\t]*[:=][ \\t]*['"]?(?:P-256|P-384|P-521|secp256k1|Ed25519|Ed448|X25519|X448)\\b`, 'm');
const JWK_X_LINE = new RegExp(`${LINE}x['"]?[ \\t]*[:=][ \\t]*['"]?[A-Za-z0-9+/_-]{43}`, 'm');
// .NET RSA.ToXmlString and its EC/DSA relatives, XMLDSig <ds:KeyValue>, a
// SAML <ds:X509Certificate>: with or without a namespace prefix and attributes.
// The attribute run is bounded: [^<>]* would be quadratic on "<<<<…".
const XML_KEY = /<[ \t]*(?:[\w.-]{1,32}:)?(?:RSAKeyValue|DSAKeyValue|ECDSAKeyValue|ECKeyValue|Modulus|X509Certificate)\b[^<>]{0,512}>/i;
// `openssl rsa|ec|pkey -text`, whole or in part: "Public-Key: (2048 bit)",
// "ED25519 Public-Key:", a "Modulus:" or "pub:" line followed by hex, an
// "ASN1 OID:" line, or `openssl rsa -modulus`.
const OPENSSL_TEXT =
  /(?:Public|Private)-Key:[ \t]*(?:\(\d+ bit|$)|^[ \t]*(?:modulus|pub|priv):[ \t]*\r?\n[ \t]+[0-9a-f]{2}:|^ASN1 OID:[ \t]*\w|^Modulus=[0-9A-F]{64}/im;
const BASE64ISH = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX = /^(?:[0-9a-fA-F]{2})+$/;

const PEM = "A PEM key was passed as a secret. Import it with importPEM and the key's algorithm, such as importPEM(pem, 'RS256') or importPEM(pem, 'ES256')";
const SSH = 'An OpenSSH public key was passed as a secret. Convert it (ssh-keygen -e -m PKCS8 -f key.pub) and import it with importPEM';
const JWK = 'A JWK was passed as a secret. Parse it and import it with importJWK(jwk)';
const DER = 'A binary or encoded public key was passed as a secret. Import it with importPEM or importJWK';
const DUMP = 'A key in a text dump (XML, YAML, TOML or openssl -text) was passed as a secret. Export it as PEM or JWK and import it with importPEM or importJWK';

function inspect(key: string | Uint8Array, depth: number): string | null {
  const texts: string[] = [];
  if (typeof key === 'string') {
    texts.push(key);
    const bytes = latin1Bytes(key);
    if (bytes && bytesAreKey(bytes)) {
      return DER;
    }
  } else {
    const bytes = withoutUtf8Bom(key);
    if (bytesAreKey(bytes) || bytesAreKey(withoutTrailingWhitespace(bytes))) {
      return DER;
    }
    texts.push(latin1(bytes));
    const utf16 = utf16Text(bytes);
    if (utf16 !== null) {
      texts.push(utf16);
    }
  }
  for (const text of texts) {
    for (const variant of unwrapped(text)) {
      const found = inspectText(variant, depth);
      if (found !== null) {
        return found;
      }
    }
  }
  return null;
}

function inspectText(text: string, depth: number): string | null {
  if (PEM_ARMOR.test(text)) {
    return PEM;
  }
  if (SSH_PUBLIC_KEY.test(text)) {
    return SSH;
  }
  if (JWK_MEMBER.test(text) || jsonCarriesKey(text, depth)) {
    return JWK;
  }
  if (
    XML_KEY.test(text) ||
    OPENSSL_TEXT.test(text) ||
    JWK_LINE.test(text) ||
    (JWK_MODULUS_LINE.test(text) && JWK_EXPONENT_LINE.test(text)) ||
    (JWK_CURVE_LINE.test(text) && JWK_X_LINE.test(text))
  ) {
    return DUMP;
  }
  for (const bytes of decodings(text)) {
    if (bytesAreKey(bytes)) {
      return DER;
    }
    // base64 of PEM text, of a JWK, of base64: look once more inside.
    if (depth < MAX_DEPTH && isPrintable(bytes)) {
      const inner = inspect(latin1(bytes), depth + 1);
      if (inner !== null) {
        return inner;
      }
    }
  }
  return null;
}

/** The text itself, and what it says once JSON quotes, literal escapes or URL encoding are removed. */
function unwrapped(text: string): string[] {
  const variants = [text];
  const trimmed = text.trim();
  if (trimmed.length > 1 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      const inner = parseJson(trimmed);
      if (typeof inner === 'string') {
        variants.push(inner);
      }
    } catch {
      // not a JSON string
    }
  }
  if (/\\[nrt]/.test(text)) {
    variants.push(text.replace(/\\[nrt]/g, '\n'));
  }
  if (/%[0-9A-Fa-f]{2}/.test(text)) {
    try {
      variants.push(decodeURIComponent(text));
    } catch {
      // not URL encoding
    }
  }
  return variants;
}

/** The bytes `text` could encode: hex (bare, `0x`, colons, `\x`) and base64 or base64url. */
function decodings(text: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  const hex = text.trim().replace(/^0x/i, '').replace(/\\x|[:\s]/gi, '');
  if (HEX.test(hex)) {
    out.push(hexToBytes(hex));
  }
  for (const bytes of [numericBytes(text), pythonBytes(text), hexDumpBytes(text)]) {
    if (bytes) {
      out.push(bytes);
    }
  }
  const compact = text.replace(/\s+/g, '');
  if (BASE64ISH.test(compact)) {
    const decoded = base64UrlDecode(compact.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'));
    if (decoded && decoded.length > 0) {
      out.push(decoded);
    }
  }
  return out;
}

const NUMBER_TOKEN = /^(-?)(?:(\d{1,3})|0[xX]([0-9a-fA-F]{1,2}))(?:_?[ui]8)?$/;
const OPENERS = '[{(';
const CLOSERS = ']})';
// A declaration before the numbers — `unsigned char key_der[] = {`, `[]byte{`,
// `new byte[]{`, `[byte[]](`, `bytes([`, `@(` — and after them `};`, with
// xxd's `unsigned int key_der_len = 294;`.
const MAX_PREFIX = 64;
const MAX_SUFFIX = 96;
const MAX_GAP = 64;

/**
 * Bytes written as numbers: a JSON array, a comma list, Java's
 * Arrays.toString of signed bytes, Go's [48 130 …] and []byte{0x30, …}, C's
 * and `xxd -i`'s {0x30, 0x82, …}, Rust's 48u8, PowerShell's @(…), one per
 * line, a trailing comma. Tokenized by hand, not by a regex, which on a
 * near-miss would backtrack — quadratically on a run of spaces, exponentially
 * on ambiguous separators.
 */
function numericBytes(text: string): Uint8Array | null {
  const span = numberSpan(text);
  if (span === null) {
    return null;
  }
  const tokens = text.slice(span[0], span[1]).split(/[\s,]+/).filter((token) => token.length > 0);
  if (tokens.length < 16) {
    return null;
  }
  const bytes = new Uint8Array(tokens.length);
  for (let i = 0; i < tokens.length; i++) {
    const match = NUMBER_TOKEN.exec(tokens[i] as string);
    if (!match) {
      return null;
    }
    const magnitude = match[2] !== undefined ? Number(match[2]) : parseInt(match[3] as string, 16);
    const value = match[1] === '-' ? -magnitude : magnitude;
    if (!(value >= -128 && value <= 255)) {
      return null;
    }
    bytes[i] = value & 0xff;
  }
  return bytes;
}

/**
 * Where the list of numbers is: after the first opening bracket, within the
 * first characters, that a number follows, up to the first closing bracket;
 * or, with no bracket, the whole text when it starts with a number.
 */
function numberSpan(text: string): [number, number] | null {
  const limit = Math.min(text.length, MAX_PREFIX + 1);
  for (let i = 0; i < limit; i++) {
    if (!OPENERS.includes(text[i] as string)) {
      continue;
    }
    let start = i + 1;
    while (start < text.length && start - i <= MAX_GAP && isSpace(text.charCodeAt(start))) {
      start++;
    }
    if (!startsNumber(text, start)) {
      continue;
    }
    let end = start;
    while (end < text.length && !CLOSERS.includes(text[end] as string)) {
      end++;
    }
    return text.length - end > MAX_SUFFIX ? null : [start, end];
  }
  let start = 0;
  while (start < text.length && start <= MAX_GAP && isSpace(text.charCodeAt(start))) {
    start++;
  }
  return startsNumber(text, start) ? [start, text.length] : null;
}

function startsNumber(text: string, at: number): boolean {
  return isDigit(text.charCodeAt(at)) || (text[at] === '-' && isDigit(text.charCodeAt(at + 1)));
}

function isSpace(unit: number): boolean {
  return unit === 0x20 || unit === 0x09 || unit === 0x0a || unit === 0x0d;
}

function isDigit(unit: number): boolean {
  return unit >= 0x30 && unit <= 0x39;
}

/** A Python bytes literal, as repr() writes it: b'0\x82\x01"0\r\x06\t*\x86H…'. */
function pythonBytes(text: string): Uint8Array | null {
  const trimmed = text.trim();
  const quote = trimmed[1];
  if (trimmed.length < 4 || trimmed[0] !== 'b' || (quote !== "'" && quote !== '"') || trimmed[trimmed.length - 1] !== quote) {
    return null;
  }
  const out: number[] = [];
  const escapes: Record<string, number> = { n: 10, r: 13, t: 9, '\\': 92, "'": 39, '"': 34 };
  for (let i = 2; i < trimmed.length - 1; i++) {
    const unit = trimmed.charCodeAt(i);
    if (unit !== 0x5c) {
      if (unit < 0x20 || unit > 0x7e) {
        return null;
      }
      out.push(unit);
      continue;
    }
    const next = trimmed[i + 1] as string;
    if (next === 'x') {
      const value = parseInt(trimmed.slice(i + 2, i + 4), 16);
      if (!/^[0-9a-fA-F]{2}$/.test(trimmed.slice(i + 2, i + 4))) {
        return null;
      }
      out.push(value);
      i += 3;
    } else if (escapes[next] !== undefined) {
      out.push(escapes[next] as number);
      i += 1;
    } else {
      return null;
    }
  }
  return Uint8Array.from(out);
}

const DUMP_OFFSET = /^[0-9a-fA-F]{6,8}:?[ \t]+/;

/**
 * `hexdump -C` (offset, sixteen hex bytes, |text|) and `xxd` (offset:, eight
 * groups of four hex digits, two spaces, text), line by line.
 */
function hexDumpBytes(text: string): Uint8Array | null {
  let hex = '';
  let lines = 0;
  for (const line of text.split(/\r?\n/)) {
    const offset = DUMP_OFFSET.exec(line);
    if (!offset) {
      if (line.trim().length === 0 || /^[0-9a-fA-F]{6,8}$/.test(line.trim())) {
        continue; // hexdump ends with the length as an offset alone
      }
      return null;
    }
    // xxd's offset ends with a colon and its text follows two spaces; the
    // text of hexdump -C is between bars. Either text may hold the other's mark.
    let body = line.slice(offset[0].length);
    const end = offset[0].includes(':') ? body.indexOf('  ') : body.indexOf('|');
    if (end >= 0) {
      body = body.slice(0, end);
    }
    hex += body.replace(/[ \t]/g, '');
    lines++;
  }
  return lines >= 2 && HEX.test(hex) ? hexToBytes(hex) : null;
}

/** An array of byte values, or an object keyed "0", "1", … as JSON.stringify(new Uint8Array(…)) writes it. */
function jsonBytes(node: object): Uint8Array | null {
  const values = Array.isArray(node) ? node : Object.keys(node).every((key, i) => key === String(i)) ? Object.values(node) : null;
  if (!values || values.length < 16 || !values.every((v) => Number.isInteger(v) && v >= -128 && v <= 255)) {
    return null;
  }
  return Uint8Array.from(values as number[], (v) => v & 0xff);
}

/** JSON that is a JWK, a JWKS or a list of keys, or holds one up to three levels down (a Keycloak realm's `public_key`). */
function jsonCarriesKey(text: string, depth: number): boolean {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return false;
  }
  let value: unknown;
  try {
    value = parseJson(trimmed);
  } catch {
    return false;
  }
  const visit = (node: unknown, level: number): boolean => {
    if (level > 3 || node === null) {
      return false;
    }
    if (typeof node === 'string') {
      return level > 0 && node.length >= 40 && depth < MAX_DEPTH && inspect(node, depth + 1) !== null;
    }
    if (typeof node === 'object') {
      // DER as numbers: [48, 130, …], or Buffer's { type: "Buffer", data: [...] }.
      const bytes = jsonBytes(node);
      if (bytes && bytesAreKey(bytes)) {
        return true;
      }
    }
    if (Array.isArray(node)) {
      return node.some((item) => visit(item, level + 1));
    }
    if (typeof node === 'object') {
      const object = node as Record<string, unknown>;
      if (
        'kty' in object ||
        (typeof object.n === 'string' && typeof object.e === 'string') ||
        (typeof object.crv === 'string' && typeof object.x === 'string')
      ) {
        return true;
      }
      return Object.values(object).some((item) => visit(item, level + 1));
    }
    return false;
  };
  return visit(value, 0);
}

const PKCS7_OID_PREFIX = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07];
const EC_POINT_CURVES: Record<number, readonly EcCurve[]> = { 65: ['P-256', 'secp256k1'], 97: ['P-384'], 133: ['P-521'] };

/** DER of a key or certificate, PKCS#7, an SSH wire-format public key, or an uncompressed EC point on a supported curve. */
function bytesAreKey(bytes: Uint8Array): boolean {
  if (bytes.length === 0) {
    return false;
  }
  if (isKeyDer(bytes)) {
    return true;
  }
  if (bytes[0] === 0x30) {
    for (let offset = 2; offset <= 6; offset++) {
      if (PKCS7_OID_PREFIX.every((byte, i) => bytes[offset + i] === byte)) {
        return true;
      }
    }
  }
  const nameLength = bytes[3] as number;
  if (bytes.length > 11 && bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && nameLength >= 7 && nameLength <= 40) {
    const name = latin1(bytes.subarray(4, 4 + nameLength));
    if (/^(?:ssh-|ecdsa-sha2-|sk-)/.test(name)) {
      return true;
    }
  }
  if (bytes[0] === 0x04) {
    for (const curve of EC_POINT_CURVES[bytes.length] ?? []) {
      if (normalizeEcPublicKey(curve, bytes)) {
        return true;
      }
    }
  }
  return false;
}

function isPrintable(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (!((byte >= 0x20 && byte < 0x7f) || byte === 0x09 || byte === 0x0a || byte === 0x0d)) {
      return false;
    }
  }
  return bytes.length > 0;
}

function withoutUtf8Bom(bytes: Uint8Array): Uint8Array {
  return bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? bytes.subarray(3) : bytes;
}

function withoutTrailingWhitespace(bytes: Uint8Array): Uint8Array {
  let end = bytes.length;
  while (end > 0 && [0x00, 0x09, 0x0a, 0x0d, 0x20].includes(bytes[end - 1] as number)) {
    end--;
  }
  return bytes.subarray(0, end);
}

/**
 * UTF-16 text, when the bytes look like it: a BOM, or a zero in every second
 * byte. Windows PowerShell 5 writes little-endian files so, and big-endian
 * ones with -Encoding BigEndianUnicode.
 */
function utf16Text(bytes: Uint8Array): string | null {
  const littleBom = bytes[0] === 0xff && bytes[1] === 0xfe;
  const bigBom = bytes[0] === 0xfe && bytes[1] === 0xff;
  const little = littleBom || (bytes.length > 3 && bytes[1] === 0 && bytes[3] === 0 && bytes[0] !== 0);
  const big = bigBom || (bytes.length > 3 && bytes[0] === 0 && bytes[2] === 0 && bytes[1] !== 0);
  if (!little && !big) {
    return null;
  }
  let text = '';
  for (let i = littleBom || bigBom ? 2 : 0; i + 1 < bytes.length; i += 2) {
    const first = bytes[i] as number;
    const second = bytes[i + 1] as number;
    text += String.fromCharCode(little ? first | (second << 8) : (first << 8) | second);
  }
  return text;
}

/** A string of code units below 256 as bytes, or null. */
function latin1Bytes(text: string): Uint8Array | null {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit > 0xff) {
      return null;
    }
    bytes[i] = unit;
  }
  return bytes;
}

/** Bytes as Latin-1 text, in chunks so a long input cannot overflow the argument list. */
export function latin1(bytes: Uint8Array): string {
  let text = '';
  for (let i = 0; i < bytes.length; i += 4096) {
    text += String.fromCharCode(...bytes.subarray(i, i + 4096));
  }
  return text;
}
