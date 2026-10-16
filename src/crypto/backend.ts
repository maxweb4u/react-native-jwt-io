import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { JwtKeyError } from '../errors/errors';
import { assertRandomSource, hasRandomSource } from '../host/random';
import { canSign, type KeyMaterial } from '../keys/JwtKey';
import { type Algorithm } from '../types/algorithm';
import { equalBytes } from '../utils/bytes';
import { EC_FIELD_BYTES, ecdsaCurves, ed25519 } from './curves';

/**
 * The only module that calls the crypto packages for signatures. Everything
 * above it works in bytes and algorithm names.
 * See memory_bank/adr/ADR-001-crypto-backend.md.
 */

const HASH = { 256: sha256, 384: sha384, 512: sha512 } as const;

function hashOf(algorithm: Algorithm): (typeof HASH)[keyof typeof HASH] {
  return HASH[Number(algorithm.slice(2, 5)) as keyof typeof HASH];
}

const RSA_PKCS1 = { 256: rsa.PKCS1_SHA256, 384: rsa.PKCS1_SHA384, 512: rsa.PKCS1_SHA512 } as const;

// RFC 7518 §3.5: MGF1 with the same hash, and a salt as long as the hash output.
const RSA_PSS = {
  256: rsa.PSS(sha256, rsa.mgf1(sha256), 32),
  384: rsa.PSS(sha384, rsa.mgf1(sha384), 48),
  512: rsa.PSS(sha512, rsa.mgf1(sha512), 64),
} as const;

function rsaSigner(algorithm: Algorithm) {
  const bits = Number(algorithm.slice(2)) as 256 | 384 | 512;
  return algorithm.startsWith('PS') ? RSA_PSS[bits] : RSA_PKCS1[bits];
}

const RSA_MISMATCH = 'The RSA private key does not match its public key: the signature it made does not verify.';

function modulusBytes(n: bigint): number {
  return Math.ceil(n.toString(16).length / 2);
}

export function signBytes(algorithm: Algorithm, material: KeyMaterial, data: Uint8Array): Uint8Array {
  if (!canSign(material)) {
    throw new JwtKeyError(`A public key cannot sign. Import the private key to sign ${algorithm} tokens.`);
  }
  if (algorithm.startsWith('PS')) {
    assertRandomSource(`${algorithm} signing`);
  }
  let signature: Uint8Array;
  try {
    signature = signWith(algorithm, material, data);
  } catch (error) {
    // The crypto packages throw plain Errors for keys they cannot use. With
    // blinding, micro-rsa-dsa-dh checks the result against e itself and
    // throws for a d that does not belong to n and e — the case below.
    if (material.kind === 'rsa' && (error as Error).message === 'RSA private operation failed') {
      throw new JwtKeyError(RSA_MISMATCH);
    }
    throw new JwtKeyError(`Signing with this ${algorithm} key failed: ${(error as Error).message}`);
  }
  // An RSA JWK may carry d without the primes, so nothing proved at import
  // that d belongs to n and e. One public-key operation — about 1% of the
  // time the signature took — proves it now, instead of issuing a token
  // nobody can verify.
  if (material.kind === 'rsa' && !verifyBytes(algorithm, material, data, signature)) {
    throw new JwtKeyError(RSA_MISMATCH);
  }
  return signature;
}

function signWith(algorithm: Algorithm, material: KeyMaterial, data: Uint8Array): Uint8Array {
  switch (material.kind) {
    case 'secret':
      return hmac(hashOf(algorithm), material.secret, data);
    case 'rsa':
      // With e, micro-rsa-dsa-dh blinds the private operation against timing
      // attacks, which takes random numbers. Without a random source (Hermes
      // alone), RS* signing stays unblinded rather than failing; PS* has
      // already required one. See memory_bank/domain/keys.md#rsa-blinding.
      return rsaSigner(algorithm).sign(
        hasRandomSource() ? { n: material.n, d: material.d as bigint, e: material.e } : { n: material.n, d: material.d as bigint },
        data,
      );
    case 'ec':
      // Compact r‖s, as JWS requires (RFC 7518 §3.4), deterministic per RFC 6979.
      return ecdsaCurves[material.curve].sign(data, material.privateKey as Uint8Array, { prehash: true, lowS: true });
    case 'okp':
      return ed25519.sign(data, material.privateKey as Uint8Array);
  }
}

/** Never throws for a bad signature; malformed signatures are simply invalid. */
export function verifyBytes(algorithm: Algorithm, material: KeyMaterial, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    switch (material.kind) {
      case 'secret':
        return equalBytes(hmac(hashOf(algorithm), material.secret, data), signature);
      case 'rsa':
        if (signature.length !== modulusBytes(material.n)) {
          return false;
        }
        return rsaSigner(algorithm).verify({ n: material.n, e: material.e }, data, signature);
      case 'ec':
        if (signature.length !== 2 * EC_FIELD_BYTES[material.curve]) {
          return false;
        }
        // lowS: false — noble 2.x rejects high-S by default, and OpenSSL (so
        // Node, and most servers) produces high-S signatures half the time.
        return ecdsaCurves[material.curve].verify(signature, data, material.publicKey, {
          prehash: true,
          lowS: false,
          format: 'compact',
        });
      case 'okp':
        if (signature.length !== 64) {
          return false;
        }
        return ed25519.verify(signature, data, material.publicKey, { zip215: false });
    }
  } catch {
    return false;
  }
}
