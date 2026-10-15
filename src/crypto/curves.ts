import { ed25519 } from '@noble/curves/ed25519.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { type EcCurve } from '../keys/JwtKey';

/** Sub-path imports only: Metro bundles per file, and the package root would pull in every curve. */
export const ecdsaCurves = {
  'P-256': p256,
  'P-384': p384,
  'P-521': p521,
  secp256k1,
} as const;

/** Bytes per scalar and per coordinate; a JWS ECDSA signature is twice this (RFC 7518 §3.4). */
export const EC_FIELD_BYTES: Record<EcCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
};

export { ed25519 };

/** The uncompressed point, or null if `bytes` is not a point on the curve. */
export function normalizeEcPublicKey(curve: EcCurve, bytes: Uint8Array): Uint8Array | null {
  try {
    return ecdsaCurves[curve].Point.fromBytes(bytes).toBytes(false);
  } catch {
    return null;
  }
}

export function ecPublicKeyFromPrivate(curve: EcCurve, privateKey: Uint8Array): Uint8Array | null {
  try {
    if (!ecdsaCurves[curve].utils.isValidSecretKey(privateKey)) {
      return null;
    }
    return ecdsaCurves[curve].getPublicKey(privateKey, false);
  } catch {
    return null;
  }
}

/** Strict RFC 8032 decoding (not ZIP-215), matching OpenSSL and therefore Node. */
export function isValidEd25519PublicKey(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) {
    return false;
  }
  try {
    ed25519.Point.fromBytes(bytes, false);
    return true;
  } catch {
    return false;
  }
}

export function ed25519PublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array | null {
  if (privateKey.length !== 32) {
    return null;
  }
  try {
    return ed25519.getPublicKey(privateKey);
  } catch {
    return null;
  }
}
