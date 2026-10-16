import { ecPublicKeyFromPrivate, ed25519PublicKeyFromPrivate, EC_FIELD_BYTES, isValidEd25519PublicKey, normalizeEcPublicKey } from '../crypto/curves';
import { JwtKeyError, JwtOptionError } from '../errors/errors';
import { type Algorithm, isAlgorithm } from '../types/algorithm';
import { base64Decode } from '../utils/base64';
import { equalBytes } from '../utils/bytes';
import { describeValue } from '../utils/describe';
import { assertKnownOptions } from '../utils/options';
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
  mgf1: '1.2.840.113549.1.1.8',
} as const;

const SHA2_BY_OID: Record<string, 256 | 384 | 512> = {
  '2.16.840.1.101.3.4.2.1': 256,
  '2.16.840.1.101.3.4.2.2': 384,
  '2.16.840.1.101.3.4.2.3': 512,
};

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
  const opts: ImportOptions = options ?? {};
  assertKnownOptions(opts, ['kid']);
  const kid = opts.kid;
  if (kid !== undefined && typeof kid !== 'string') {
    throw new JwtOptionError('kid', 'The "kid" option must be a string.');
  }
  // The algorithm argument first: naming no algorithm is a mistake in the call, whatever the PEM.
  if (!isAlgorithm(algorithm)) {
    throw new JwtOptionError('algorithm', `importPEM needs the key's algorithm, such as 'RS256' or 'ES256'; got ${describeValue(algorithm)}.`);
  }
  if (typeof pem !== 'string') {
    throw new JwtKeyError('importPEM expects the PEM text as a string.');
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
  if (parsed.pssHash !== undefined && algorithm !== `PS${parsed.pssHash}`) {
    throw new JwtKeyError(`This RSASSA-PSS key is restricted to SHA-${parsed.pssHash}; it can only be used for PS${parsed.pssHash}.`);
  }
  return createKey(parsed.material, algorithm, kid);
}

/**
 * `pssOnly`: the key's own OID restricts it to RSASSA-PSS (RFC 4055).
 * `pssHash`: its parameters restrict it further, to one hash.
 */
interface Parsed {
  readonly material: KeyMaterial;
  readonly pssOnly?: boolean;
  readonly pssHash?: 256 | 384 | 512;
}

function readPem(pem: string): { label: string; der: Uint8Array } {
  const match = /^\s*-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)\r?\n?-----END \1-----\s*$/.exec(pem);
  if (!match) {
    throw new JwtKeyError('The key is not a single PEM block (-----BEGIN …----- / -----END …-----).');
  }
  const label = match[1] as string;
  const body = match[2] as string;
  if (body.includes('-----')) {
    throw new JwtKeyError('The key is not a single PEM block (-----BEGIN …----- / -----END …-----).');
  }
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

const DER_LABELS = ['PUBLIC KEY', 'PRIVATE KEY', 'RSA PUBLIC KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'];

/**
 * Whether `der` is a key in one of the formats `importPEM` reads — used to
 * refuse key material passed as an HMAC secret. Never throws. A key of an
 * unsupported algorithm or curve still counts: it is a key either way.
 */
export function isKeyDer(der: Uint8Array): boolean {
  // Cheap gate first: a key is one SEQUENCE spanning the whole input. Random
  // secret bytes pass it about once in 65,000 tries, and then fail to parse.
  if (der[0] !== DerTag.Sequence) {
    return false;
  }
  let children: DerNode[];
  try {
    children = readNodes(readSingle(der, DerTag.Sequence).content);
  } catch {
    return false;
  }
  // An X.509 certificate: tbsCertificate, signatureAlgorithm, signature. It
  // carries a public key, so it is no more a secret than the key is.
  if (children.length === 3 && children[0]?.tag === DerTag.Sequence && children[1]?.tag === DerTag.Sequence && children[2]?.tag === DerTag.BitString) {
    return true;
  }
  for (const label of DER_LABELS) {
    try {
      parseByLabel(label, der);
      return true;
    } catch (error) {
      if (error instanceof JwtKeyError) {
        return true;
      }
    }
  }
  return false;
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
    return { material: parseRsaPublicKey(keyBytes), pssOnly: true, pssHash: pssRestriction(parameters) };
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
  // [0] attributes, then [1] public key (v2 only): each at most once, in that order.
  let embeddedPublic: Uint8Array | undefined;
  let previous = -1;
  for (const node of optional) {
    const index =
      node.tag === DerTag.ContextSpecific0 ? 0 : node.tag === DerTag.ContextSpecific1Primitive && v === BigInt(1) ? 1 : -1;
    if (index <= previous) {
      throw new DerError('unexpected data after the private key');
    }
    previous = index;
    if (index === 1) {
      if (node.content.length < 2 || node.content[0] !== 0) {
        throw new DerError('the embedded public key is not a byte-aligned BIT STRING');
      }
      embeddedPublic = node.content.subarray(1);
    }
  }
  const { oid, parameters } = readAlgorithmIdentifier(algorithmId);
  const inner = expectTag(privateKey, DerTag.OctetString).content;
  if (oid === OID.rsaEncryption) {
    expectNoParameters(parameters);
    return { material: withEmbeddedPublic(parseRsaPrivateKey(inner), embeddedPublic) };
  }
  if (oid === OID.rsassaPss) {
    return {
      material: withEmbeddedPublic(parseRsaPrivateKey(inner), embeddedPublic),
      pssOnly: true,
      pssHash: pssRestriction(parameters),
    };
  }
  if (oid === OID.ecPublicKey) {
    return { material: withEmbeddedPublic(parseEcPrivateKey(inner, curveOf(parameters)), embeddedPublic) };
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
    return { material: withEmbeddedPublic({ kind: 'okp', curve: 'Ed25519', publicKey, privateKey: seed.slice() }, embeddedPublic) };
  }
  throw new JwtKeyError(`Unsupported key algorithm (OID ${oid}).`);
}

/** RFC 5958 §2: a v2 key's own copy of its public key must be that key's public key. */
function withEmbeddedPublic(material: KeyMaterial, embedded: Uint8Array | undefined): KeyMaterial {
  if (embedded === undefined) {
    return material;
  }
  let matches: boolean;
  switch (material.kind) {
    case 'rsa': {
      const embeddedRsa = parseRsaPublicKey(embedded);
      matches = embeddedRsa.n === material.n && embeddedRsa.e === material.e;
      break;
    }
    case 'ec': {
      const normalized = normalizeEcPublicKey(material.curve, embedded);
      matches = normalized !== null && equalBytes(normalized, material.publicKey);
      break;
    }
    case 'okp':
      matches = equalBytes(embedded, material.publicKey);
      break;
    default:
      matches = false;
  }
  if (!matches) {
    throw new DerError('the embedded public key does not match the private key');
  }
  return material;
}

/**
 * RSASSA-PSS-params (RFC 4055 §3.1). Absent parameters leave the key
 * unrestricted. Present ones bind it to one hash: they must name a SHA-2 hash,
 * MGF1 with the same hash, a salt no longer than the hash (RFC 7518 §3.5
 * signs with exactly that), and the standard trailer.
 */
function pssRestriction(parameters: DerNode | undefined): 256 | 384 | 512 | undefined {
  if (parameters === undefined) {
    return undefined;
  }
  let hash: number | undefined;
  let mgfHash: number | undefined;
  let saltLength = BigInt(20);
  let previous = -1;
  for (const node of readNodes(expectTag(parameters, DerTag.Sequence).content)) {
    const index = [DerTag.ContextSpecific0, DerTag.ContextSpecific1, DerTag.ContextSpecific2, DerTag.ContextSpecific3].indexOf(
      node.tag as 0xa0,
    );
    if (index <= previous) {
      throw new DerError('malformed RSASSA-PSS parameters');
    }
    previous = index;
    if (index === 0) {
      hash = sha2Of(readSingle(node.content, DerTag.Sequence));
    } else if (index === 1) {
      const mgf = readAlgorithmIdentifier(readSingle(node.content, DerTag.Sequence));
      if (mgf.oid !== OID.mgf1) {
        throw new DerError('the RSASSA-PSS mask generation function is not MGF1');
      }
      mgfHash = sha2Of(mgf.parameters);
    } else if (index === 2) {
      saltLength = readUnsignedInteger(readSingle(node.content, DerTag.Integer));
    } else if (readUnsignedInteger(readSingle(node.content, DerTag.Integer)) !== BigInt(1)) {
      throw new DerError('unsupported RSASSA-PSS trailer field');
    }
  }
  // The defaults are SHA-1, which JWS does not use.
  if (hash === undefined || mgfHash !== hash) {
    throw new DerError('the RSASSA-PSS parameters do not name one SHA-2 hash for both the digest and MGF1');
  }
  if (saltLength > BigInt(hash / 8)) {
    throw new DerError(`the RSASSA-PSS key requires a salt longer than ${hash / 8} bytes`);
  }
  return hash as 256 | 384 | 512;
}

function sha2Of(node: DerNode | undefined): number {
  const { oid, parameters } = readAlgorithmIdentifier(node);
  expectNoParameters(parameters);
  const bits = SHA2_BY_OID[oid];
  if (bits === undefined) {
    throw new DerError(`unsupported RSASSA-PSS hash (OID ${oid})`);
  }
  return bits;
}

function parseRsaPublicKey(der: Uint8Array): Extract<KeyMaterial, { kind: 'rsa' }> {
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
  let previous = -1;
  for (const node of optional) {
    // [0] parameters, then [1] public key: each at most once, in that order.
    const index = node.tag === DerTag.ContextSpecific0 ? 0 : node.tag === DerTag.ContextSpecific1 ? 1 : -1;
    if (index <= previous) {
      throw new DerError('unexpected data in the EC private key');
    }
    previous = index;
    if (index === 0) {
      const inner = curveOf(readSingle(node.content, DerTag.Oid));
      if (curve !== undefined && inner !== curve) {
        throw new DerError('the curve parameters disagree');
      }
      curve = inner;
    } else {
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
