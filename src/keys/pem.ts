import { ecPublicKeyFromPrivate, ed25519PublicKeyFromPrivate, EC_FIELD_BYTES, isValidEd25519PublicKey, normalizeEcPublicKey } from '../crypto/curves';
import { JwtKeyError } from '../errors/errors';
import { type Algorithm, isAlgorithm } from '../types/algorithm';
import { base64Decode } from '../utils/base64';
import { equalBytes } from '../utils/bytes';
import {
  DerError,
  type DerNode,
  DerTag,
  expectNoParameters,
  expectTag,
  readBitStringBytes,
  readNodes,
  readOid,
  readSingle,
  readUnsignedInteger,
} from './der';
import { createKey, type EcCurve, type JwtKey, type KeyMaterial, rsaPrivatePartsMatch } from './JwtKey';

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
  const kid = (options ?? {}).kid;
  if (kid !== undefined && typeof kid !== 'string') {
    throw new JwtKeyError('The "kid" option must be a string.');
  }
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
  let parsed: Parsed;
  try {
    parsed = parseByLabel(label, der);
  } catch (error) {
    if (error instanceof DerError) {
      throw new JwtKeyError(`The ${label} PEM is not a valid key: ${error.message}.`);
    }
    throw error;
  }
  if (parsed.pssOnly && !algorithm.startsWith('PS')) {
    throw new JwtKeyError(`This is an RSASSA-PSS key (OID ${OID.rsassaPss}); it can only be used for PS256, PS384 or PS512.`);
  }
  return createKey(parsed.material, algorithm, kid);
}

/** `pssOnly`: the key's own OID restricts it to RSASSA-PSS (RFC 4055). */
interface Parsed {
  readonly material: KeyMaterial;
  readonly pssOnly?: boolean;
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

function parseByLabel(label: string, der: Uint8Array): Parsed {
  switch (label) {
    case 'PUBLIC KEY':
      return parseSpki(der);
    case 'PRIVATE KEY':
      return parsePkcs8(der);
    case 'RSA PUBLIC KEY':
      return { material: parseRsaPublicKey(der) };
    case 'RSA PRIVATE KEY':
      return { material: parseRsaPrivateKey(der) };
    case 'EC PRIVATE KEY':
      return { material: parseEcPrivateKey(der, undefined) };
    default:
      throw new JwtKeyError(`Unsupported PEM type "${label}".`);
  }
}

function parseSpki(der: Uint8Array): Parsed {
  const [algorithmId, keyBits, extra] = readNodes(readSingle(der, DerTag.Sequence).content);
  if (extra) {
    throw new DerError('trailing data');
  }
  const { oid, parameters } = readAlgorithmIdentifier(algorithmId);
  const keyBytes = readBitStringBytes(keyBits);
  if (oid === OID.rsaEncryption) {
    expectNoParameters(parameters);
    return { material: parseRsaPublicKey(keyBytes) };
  }
  if (oid === OID.rsassaPss) {
    return { material: parseRsaPublicKey(keyBytes), pssOnly: true };
  }
  if (oid === OID.ecPublicKey) {
    const curve = curveOf(parameters);
    const publicKey = normalizeEcPublicKey(curve, keyBytes);
    if (!publicKey) {
      throw new DerError(`the public key is not a point on ${curve}`);
    }
    return { material: { kind: 'ec', curve, publicKey } };
  }
  if (oid === OID.ed25519) {
    // RFC 8410 §3: the parameters are absent for Ed25519.
    if (parameters !== undefined) {
      throw new DerError('unexpected algorithm parameters');
    }
    if (!isValidEd25519PublicKey(keyBytes)) {
      throw new DerError('the Ed25519 public key is invalid');
    }
    return { material: { kind: 'okp', curve: 'Ed25519', publicKey: keyBytes.slice() } };
  }
  throw new JwtKeyError(`Unsupported key algorithm (OID ${oid}).`);
}

/** PKCS#8 / OneAsymmetricKey (RFC 5958): version, algorithm, key, then only [0] attributes and [1] public key. */
function parsePkcs8(der: Uint8Array): Parsed {
  const [version, algorithmId, privateKey, ...optional] = readNodes(readSingle(der, DerTag.Sequence).content);
  const v = readUnsignedInteger(version);
  if (v !== BigInt(0) && v !== BigInt(1)) {
    throw new DerError('unsupported PKCS#8 version');
  }
  let embeddedPublic: Uint8Array | undefined;
  for (const node of optional) {
    if (node.tag === 0x81 && v === BigInt(1)) {
      embeddedPublic = node.content.length > 0 && node.content[0] === 0 ? node.content.subarray(1) : undefined;
    } else if (node.tag !== DerTag.ContextSpecific0) {
      throw new DerError('unexpected data after the private key');
    }
  }
  const { oid, parameters } = readAlgorithmIdentifier(algorithmId);
  const inner = expectTag(privateKey, DerTag.OctetString).content;
  if (oid === OID.rsaEncryption) {
    expectNoParameters(parameters);
    return { material: parseRsaPrivateKey(inner) };
  }
  if (oid === OID.rsassaPss) {
    return { material: parseRsaPrivateKey(inner), pssOnly: true };
  }
  if (oid === OID.ecPublicKey) {
    return { material: parseEcPrivateKey(inner, curveOf(parameters)) };
  }
  if (oid === OID.ed25519) {
    if (parameters !== undefined) {
      throw new DerError('unexpected algorithm parameters');
    }
    const seed = readSingle(inner, DerTag.OctetString).content;
    const publicKey = ed25519PublicKeyFromPrivate(seed);
    if (!publicKey) {
      throw new DerError('the Ed25519 private key must be 32 bytes');
    }
    if (embeddedPublic && !equalBytes(embeddedPublic, publicKey)) {
      throw new DerError('the embedded public key does not match the private key');
    }
    return { material: { kind: 'okp', curve: 'Ed25519', publicKey, privateKey: seed.slice() } };
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

/** RSAPrivateKey (RFC 8017 A.1.2): exactly nine integers, and the primes must produce n, e and d. */
function parseRsaPrivateKey(der: Uint8Array): KeyMaterial {
  const nodes = readNodes(readSingle(der, DerTag.Sequence).content);
  if (readUnsignedInteger(nodes[0]) !== BigInt(0) || nodes.length !== 9) {
    throw new DerError('expected a two-prime RSAPrivateKey');
  }
  const [n, e, d, p, q] = nodes.slice(1, 6).map((node) => readUnsignedInteger(node)) as [bigint, bigint, bigint, bigint, bigint];
  nodes.slice(6).forEach((node) => readUnsignedInteger(node));
  if (!rsaPrivatePartsMatch(n, e, d, p, q)) {
    throw new DerError('the RSA key parts do not belong together');
  }
  return { kind: 'rsa', n, e, d };
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
    } else {
      throw new DerError('unexpected data in the EC private key');
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
  const [oidNode, parameters, extra] = readNodes(expectTag(node, DerTag.Sequence).content);
  if (extra) {
    throw new DerError('trailing data in the algorithm identifier');
  }
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
