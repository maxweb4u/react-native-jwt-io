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
 *   text; with a UTF-8 or UTF-16 encoding, literal `\n` escapes, JSON quotes,
 *   URL encoding, or base64 of any of these (as Kubernetes secrets hold them);
 * - text dumps tools write: .NET `RSAKeyValue` XML, a JWK as YAML or TOML,
 *   `openssl … -text` output, DER as a list of decimal bytes (added after the
 *   review of 2026-10-17).
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
const JWK_MEMBER = /[{,]\s*['"]?kty['"]?\s*:/;
// The same members as YAML or TOML lines. `[ \t]*`, not `\s*`: across lines it would be quadratic.
const JWK_LINE = /^[ \t]*['"]?kty['"]?[ \t]*[:=]/m;
const JWK_MODULUS_LINE = /^[ \t]*['"]?n['"]?[ \t]*[:=][ \t]*['"]?[A-Za-z0-9+/_-]{64}/m;
const JWK_EXPONENT_LINE = /^[ \t]*['"]?e['"]?[ \t]*[:=]/m;
const JWK_CURVE_LINE = /^[ \t]*['"]?crv['"]?[ \t]*[:=]/m;
const JWK_X_LINE = /^[ \t]*['"]?x['"]?[ \t]*[:=]/m;
// .NET RSA.ToXmlString and its EC/DSA relatives.
const XML_KEY = /<[ \t]*(?:RSAKeyValue|DSAKeyValue|ECDSAKeyValue|Modulus)[ \t]*>/i;
// `openssl rsa|ec|pkey -text`: "Public-Key: (2048 bit)", "ED25519 Public-Key:", then the numbers.
const OPENSSL_TEXT = /(?:Public|Private)-Key:[ \t]*(?:\(\d+ bit|$)/m;
// DER as decimal bytes, as JSON.stringify(Array.from(bytes)) or a comma list writes it.
const DECIMAL_BYTES = /^\[?[ \t\r\n]*\d{1,3}(?:[ \t\r\n]*,[ \t\r\n]*\d{1,3}){15,}[ \t\r\n]*\]?$/;
const BASE64ISH = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX = /^(?:[0-9a-fA-F]{2})+$/;

const PEM = "A PEM key was passed as a secret. Import it with importPEM(pem, 'RS256')";
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
  const trimmed = text.trim();
  if (DECIMAL_BYTES.test(trimmed)) {
    const values = trimmed.replace(/[[\]\s]/g, '').split(',').map(Number);
    if (values.every((value) => value <= 255)) {
      out.push(Uint8Array.from(values));
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

/** UTF-16LE text, when the bytes look like it: a BOM, or a zero in every second byte. Windows PowerShell 5 writes files so. */
function utf16Text(bytes: Uint8Array): string | null {
  const bom = bytes[0] === 0xff && bytes[1] === 0xfe;
  if (!bom && !(bytes.length > 3 && bytes[1] === 0 && bytes[3] === 0)) {
    return null;
  }
  let text = '';
  for (let i = bom ? 2 : 0; i + 1 < bytes.length; i += 2) {
    text += String.fromCharCode((bytes[i] as number) | ((bytes[i + 1] as number) << 8));
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
