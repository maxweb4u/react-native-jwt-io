import { JwtAlgorithmError, JwtKeyError } from '../errors/errors';
import { type Algorithm, type HmacAlgorithm, isHmacAlgorithm } from '../types/algorithm';
import { base64UrlDecode } from '../utils/base64';
import { hexToBytes, isBytes } from '../utils/bytes';
import { describeValue } from '../utils/describe';
import { parseJson } from '../utils/json';
import { utf8Encode } from '../utils/utf8';
import { type JwtKey, keyMaterialOf, type KeyMaterial } from './JwtKey';
import { isKeyDer } from './pem';

/** A bare HMAC secret, or a key from `importPEM` / `importJWK`. */
export type KeyInput = string | Uint8Array | JwtKey;

export interface ResolvedKey {
  readonly algorithm: Algorithm;
  readonly material: KeyMaterial;
  readonly kid: string | undefined;
}

// Lenient on purpose — any case, spaces, three or more dashes: this decides
// what is *not* a secret, so it errs towards "this is a key".
const PEM_ARMOR = /-{3,}[ \t]*BEGIN[ \t]+[A-Z0-9]/i;
const SSH_PUBLIC_KEY = /^\s*(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9-]+@openssh\.com)\s+AAAA/;
const JWK_JSON = /^\s*[[{][\s\S]*"(?:kty|keys)"\s*:/;
const BASE64ISH = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX = /^(?:[0-9a-fA-F]{2})+$/;

/**
 * What kind of key `key` is, if it is one — for refusing key material passed
 * as an HMAC secret, the precondition of RS256-to-HS256 confusion. Checks the
 * whole input (`openssl pkcs12` writes "Bag Attributes" before the armor) and
 * the forms a public key is shown in outside PEM: DER bytes, and DER as
 * base64 or base64url (Keycloak's `public_key`), hex, or Latin-1 text.
 * See memory_bank/domain/keys.md#inputs.
 */
function keyKind(key: string | Uint8Array): string | null {
  const text = typeof key === 'string' ? key : latin1(key);
  if (PEM_ARMOR.test(text)) {
    return "A PEM key was passed as a secret. Import it with importPEM(pem, 'RS256')";
  }
  if (SSH_PUBLIC_KEY.test(text)) {
    return 'An OpenSSH public key was passed as a secret. Convert it (ssh-keygen -e -m PKCS8 -f key.pub) and import it with importPEM';
  }
  if (JWK_JSON.test(text) || isJwkJson(text)) {
    return 'A JWK was passed as a secret. Parse it and import it with importJWK(jwk)';
  }
  for (const der of derCandidates(key, text)) {
    if (isKeyDer(der)) {
      return 'A DER-encoded key was passed as a secret. Wrap it in PEM armor and import it with importPEM';
    }
  }
  return null;
}

/** JSON whose escapes hide "kty" from the pattern above. */
function isJwkJson(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return false;
  }
  try {
    const value = parseJson(trimmed) as Record<string, unknown> | null;
    const first = Array.isArray(value) ? (value[0] as Record<string, unknown> | undefined) : value;
    return first !== null && typeof first === 'object' && ('kty' in first || 'keys' in first);
  } catch {
    return false;
  }
}

/** The byte strings `key` could be DER in: itself, or its text decoded as base64/base64url, hex, or Latin-1. */
function derCandidates(key: string | Uint8Array, text: string): Uint8Array[] {
  const candidates: Uint8Array[] = [];
  if (typeof key !== 'string') {
    candidates.push(key);
  } else {
    const bytes = new Uint8Array(key.length);
    let latin = true;
    for (let i = 0; i < key.length && latin; i++) {
      const unit = key.charCodeAt(i);
      latin = unit < 256;
      bytes[i] = unit;
    }
    if (latin) {
      candidates.push(bytes);
    }
  }
  const compact = text.replace(/\s+/g, '');
  if (HEX.test(compact)) {
    candidates.push(hexToBytes(compact));
  }
  if (BASE64ISH.test(compact)) {
    const decoded = base64UrlDecode(compact.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'));
    if (decoded) {
      candidates.push(decoded);
    }
  }
  return candidates;
}

/** Bytes as Latin-1 text, in chunks so a long input cannot overflow the argument list. */
function latin1(bytes: Uint8Array): string {
  let text = '';
  for (let i = 0; i < bytes.length; i += 4096) {
    text += String.fromCharCode(...bytes.subarray(i, i + 4096));
  }
  return text;
}

const HMAC_MIN_BYTES: Record<HmacAlgorithm, number> = { HS256: 32, HS384: 48, HS512: 64 };

/**
 * One key, one algorithm: a bare secret is HS256 unless `algorithm` names
 * another HMAC; an imported key is whatever it was imported for, and a
 * contradicting `algorithm` is an error, not an override.
 * See memory_bank/adr/ADR-003-one-key-one-algorithm.md.
 */
export function resolveKey(key: KeyInput, algorithm: unknown): ResolvedKey {
  if (typeof key === 'string' || isBytes(key)) {
    const kind = keyKind(key);
    if (kind !== null) {
      throw new JwtKeyError(`${kind} — strings and bytes are HMAC secrets.`);
    }
    const chosen = algorithm ?? 'HS256';
    if (!isHmacAlgorithm(chosen)) {
      throw new JwtAlgorithmError(`A bare secret is an HMAC key; "algorithm" must be HS256, HS384 or HS512, not ${describeValue(chosen)}.`);
    }
    const secret = typeof key === 'string' ? utf8Encode(key) : key.slice();
    return { algorithm: chosen, material: { kind: 'secret', secret }, kid: undefined };
  }
  const material = keyMaterialOf(key);
  if (!material) {
    throw new JwtKeyError('Keys must be a secret string, a Uint8Array, or a key from importPEM, importJWK or createJWKS.');
  }
  if (algorithm !== undefined && algorithm !== key.algorithm) {
    throw new JwtAlgorithmError(`This key is bound to ${key.algorithm}; it cannot be used as ${describeValue(algorithm)}.`);
  }
  return { algorithm: key.algorithm, material, kid: key.kid };
}

/**
 * RFC 7518 §3.2: an HMAC key at least as long as the hash output. Checked
 * after the algorithm is settled, so a wrong algorithm is reported as such.
 */
export function assertSecretStrength(resolved: ResolvedKey, allowShortSecret: boolean | undefined): void {
  if (resolved.material.kind !== 'secret') {
    return;
  }
  const { secret } = resolved.material;
  const algorithm = resolved.algorithm as HmacAlgorithm;
  if (secret.length === 0) {
    throw new JwtKeyError('The HMAC secret is empty.');
  }
  const minimum = HMAC_MIN_BYTES[algorithm];
  if (secret.length < minimum && allowShortSecret !== true) {
    throw new JwtKeyError(
      `${algorithm} needs a secret of at least ${minimum} bytes (RFC 7518 §3.2); this one is ${secret.length}. ` +
        'Use a longer secret, or pass { allowShortSecret: true } only to work with a legacy issuer.',
    );
  }
}
