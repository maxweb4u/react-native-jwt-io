import { ecPublicKeyFromPrivate, ed25519PublicKeyFromPrivate, EC_FIELD_BYTES, isValidEd25519PublicKey, normalizeEcPublicKey } from '../crypto/curves';
import { JwtKeyError } from '../errors/errors';
import { type Algorithm, isAlgorithm } from '../types/algorithm';
import { base64Decode } from '../utils/base64';
import { equalBytes } from '../utils/bytes';
import {
  DerError,
  type DerNode,
  DerTag,
  expectTag,
  readBitStringBytes,
  readNodes,
  readOid,
  readSingle,
  readUnsignedInteger,
} from './der';
import { createKey, type EcCurve, type JwtKey, type KeyMaterial } from './JwtKey';

const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  ed25519: '1.3.101.112',
} as const;

const CURVE_BY_OID: Record<string, EcCurve> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
  '1.3.132.0.10': 'secp256k1',
};

export interface ImportOptions {
  /** Stored on the key and written to the header `kid` when signing. */
  readonly kid?: string;
}

/**
 * Imports a PEM key for exactly one algorithm.
 *
 * Accepted: `PUBLIC KEY` (SPKI), `PRIVATE KEY` (PKCS#8), `RSA PUBLIC KEY` and
 * `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1). Certificates and
 * encrypted keys are refused. See memory_bank/domain/keys.md.
 */
export function importPEM(pem: string, algorithm: Algorithm, options: ImportOptions = {}): JwtKey {
  if (typeof pem !== 'string') {
    throw new JwtKeyError('importPEM expects the PEM text as a string.');
  }
  if (!isAlgorithm(algorithm)) {
    throw new JwtKeyError(`importPEM needs the key's algorithm, such as 'RS256' or 'ES256'; got ${String(algorithm)}.`);
  }
  if (algorithm.startsWith('HS')) {
    throw new JwtKeyError('HMAC secrets are not PEM keys. Pass the secret itself as a string or Uint8Array.');
  }
  const { label, der } = readPem(pem);
  let material: KeyMaterial;
  try {
    material = parseByLabel(label, der);
  } catch (error) {
    if (error instanceof DerError) {
      throw new JwtKeyError(`The ${label} PEM is not a valid key: ${error.message}.`);
    }
    throw error;
  }
  return createKey(material, algorithm, options.kid);
}

function readPem(pem: string): { label: string; der: Uint8Array } {
  const match = /^\s*-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)\r?\n?-----END \1-----\s*$/.exec(pem);
  if (!match) {
    throw new JwtKeyError('The key is not a single PEM block (-----BEGIN …----- / -----END …-----).');
  }
  const label = match[1] as string;
  const body = match[2] as string;
  if (label === 'CERTIFICATE') {
    throw new JwtKeyError('X.509 certificates are not supported. Extract the public key (openssl x509 -pubkey -noout) and import that.');
  }
  if (label === 'ENCRYPTED PRIVATE KEY' || /Proc-Type:/.test(body)) {
    throw new JwtKeyError('Encrypted private keys are not supported. Decrypt the key first.');
  }
  const der = base64Decode(body.replace(/\s+/g, ''));
  if (der === null || der.length === 0) {
    throw new JwtKeyError(`The ${label} PEM body is not valid base64.`);
  }
  return { label, der };
}

function parseByLabel(label: string, der: Uint8Array): KeyMaterial {
  switch (label) {
    case 'PUBLIC KEY':
      return parseSpki(der);
    case 'PRIVATE KEY':
      return parsePkcs8(der);
    case 'RSA PUBLIC KEY':
      return parseRsaPublicKey(der);
    case 'RSA PRIVATE KEY':
      return parseRsaPrivateKey(der);
    case 'EC PRIVATE KEY':
      return parseEcPrivateKey(der, undefined);
    default:
      throw new JwtKeyError(`Unsupported PEM type "${label}".`);
  }
}

function parseSpki(der: Uint8Array): KeyMaterial {
  const [algorithmId, keyBits, extra] = readNodes(readSingle(der, DerTag.Sequence).content);
  if (extra) {
    throw new DerError('trailing data');
  }
  const { oid, parameters } = readAlgorithmIdentifier(algorithmId);
  const keyBytes = readBitStringBytes(keyBits);
  if (oid === OID.rsaEncryption || oid === OID.rsassaPss) {
    return parseRsaPublicKey(keyBytes);
  }
  if (oid === OID.ecPublicKey) {
    const curve = curveOf(parameters);
    const publicKey = normalizeEcPublicKey(curve, keyBytes);
    if (!publicKey) {
      throw new DerError(`the public key is not a point on ${curve}`);
    }
    return { kind: 'ec', curve, publicKey };
  }
  if (oid === OID.ed25519) {
    if (!isValidEd25519PublicKey(keyBytes)) {
      throw new DerError('the Ed25519 public key is invalid');
    }
    return { kind: 'okp', curve: 'Ed25519', publicKey: keyBytes.slice() };
  }
  throw new JwtKeyError(`Unsupported key algorithm (OID ${oid}).`);
}

function parsePkcs8(der: Uint8Array): KeyMaterial {
  const [version, algorithmId, privateKey] = readNodes(readSingle(der, DerTag.Sequence).content);
  const v = readUnsignedInteger(version);
  if (v !== BigInt(0) && v !== BigInt(1)) {
    throw new DerError('unsupported PKCS#8 version');
  }
  const { oid, parameters } = readAlgorithmIdentifier(algorithmId);
  const inner = expectTag(privateKey, DerTag.OctetString).content;
  if (oid === OID.rsaEncryption || oid === OID.rsassaPss) {
    return parseRsaPrivateKey(inner);
  }
  if (oid === OID.ecPublicKey) {
    return parseEcPrivateKey(inner, curveOf(parameters));
  }
  if (oid === OID.ed25519) {
    const seed = readSingle(inner, DerTag.OctetString).content;
    const publicKey = ed25519PublicKeyFromPrivate(seed);
    if (!publicKey) {
      throw new DerError('the Ed25519 private key must be 32 bytes');
    }
    return { kind: 'okp', curve: 'Ed25519', publicKey, privateKey: seed.slice() };
  }
  throw new JwtKeyError(`Unsupported key algorithm (OID ${oid}).`);
}

function parseRsaPublicKey(der: Uint8Array): KeyMaterial {
  const [n, e, extra] = readNodes(readSingle(der, DerTag.Sequence).content);
  if (extra) {
    throw new DerError('trailing data');
  }
  return { kind: 'rsa', n: readUnsignedInteger(n), e: readUnsignedInteger(e) };
}

function parseRsaPrivateKey(der: Uint8Array): KeyMaterial {
  const nodes = readNodes(readSingle(der, DerTag.Sequence).content);
  if (readUnsignedInteger(nodes[0]) !== BigInt(0)) {
    throw new DerError('multi-prime RSA keys are not supported');
  }
  return {
    kind: 'rsa',
    n: readUnsignedInteger(nodes[1]),
    e: readUnsignedInteger(nodes[2]),
    d: readUnsignedInteger(nodes[3]),
  };
}

/** SEC1 ECPrivateKey (RFC 5915). The curve comes from PKCS#8 or from the key's own parameters. */
function parseEcPrivateKey(der: Uint8Array, outerCurve: EcCurve | undefined): KeyMaterial {
  const [version, privateKey, ...optional] = readNodes(readSingle(der, DerTag.Sequence).content);
  if (readUnsignedInteger(version) !== BigInt(1)) {
    throw new DerError('unsupported EC private key version');
  }
  let d = expectTag(privateKey, DerTag.OctetString).content;
  let curve = outerCurve;
  let embeddedPublic: Uint8Array | undefined;
  for (const node of optional) {
    if (node.tag === DerTag.ContextSpecific0) {
      const inner = curveOf(readSingle(node.content, DerTag.Oid));
      if (curve !== undefined && inner !== curve) {
        throw new DerError('the curve parameters disagree');
      }
      curve = inner;
    } else if (node.tag === DerTag.ContextSpecific1) {
      embeddedPublic = readBitStringBytes(readSingle(node.content, DerTag.BitString));
    }
  }
  if (curve === undefined) {
    throw new DerError('the EC private key does not name its curve');
  }
  const size = EC_FIELD_BYTES[curve];
  if (d.length > size) {
    throw new DerError('the EC private key is too long for its curve');
  }
  if (d.length < size) {
    const padded = new Uint8Array(size);
    padded.set(d, size - d.length);
    d = padded;
  }
  const publicKey = ecPublicKeyFromPrivate(curve, d);
  if (!publicKey) {
    throw new DerError(`the private key is not a valid ${curve} scalar`);
  }
  if (embeddedPublic) {
    const normalized = normalizeEcPublicKey(curve, embeddedPublic);
    if (!normalized || !equalBytes(normalized, publicKey)) {
      throw new DerError('the embedded public key does not match the private key');
    }
  }
  return { kind: 'ec', curve, publicKey, privateKey: d.slice() };
}

function readAlgorithmIdentifier(node: DerNode | undefined): {
  oid: string;
  parameters: DerNode | undefined;
} {
  const [oidNode, parameters] = readNodes(expectTag(node, DerTag.Sequence).content);
  return { oid: readOid(oidNode), parameters };
}

function curveOf(parameters: DerNode | undefined): EcCurve {
  const oid = readOid(parameters);
  const curve = CURVE_BY_OID[oid];
  if (!curve) {
    throw new JwtKeyError(`Unsupported elliptic curve (OID ${oid}). Supported: P-256, P-384, P-521, secp256k1.`);
  }
  return curve;
}
