/**
 * The smallest DER reader that SPKI, PKCS#8, PKCS#1 and SEC1 keys need.
 *
 * This is input parsing, not cryptography: it turns key files into the
 * integers and byte strings the crypto packages take. It is strict on
 * purpose — definite lengths only, no trailing bytes, no lengths past the
 * end — because every byte here comes from outside.
 * See memory_bank/engineering/dependency-policy.md.
 */

export const DerTag = {
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  Oid: 0x06,
  Sequence: 0x30,
  ContextSpecific0: 0xa0,
  ContextSpecific1: 0xa1,
} as const;

export interface DerNode {
  readonly tag: number;
  readonly content: Uint8Array;
}

export class DerError extends Error {}

/** Reads consecutive TLV nodes from `bytes`. */
export function readNodes(bytes: Uint8Array): DerNode[] {
  const nodes: DerNode[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const tag = bytes[offset] as number;
    if ((tag & 0x1f) === 0x1f) {
      throw new DerError('multi-byte tags are not used by key formats');
    }
    let length = bytes[offset + 1];
    if (length === undefined) {
      throw new DerError('truncated length');
    }
    offset += 2;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 4) {
        throw new DerError('indefinite or oversized length');
      }
      length = 0;
      for (let i = 0; i < count; i++) {
        const b = bytes[offset + i];
        if (b === undefined) {
          throw new DerError('truncated length');
        }
        if (i === 0 && b === 0) {
          throw new DerError('non-minimal length');
        }
        length = length * 256 + b;
      }
      if (length < 0x80) {
        throw new DerError('non-minimal length');
      }
      offset += count;
    }
    const end = offset + length;
    if (end > bytes.length) {
      throw new DerError('length runs past the end of the input');
    }
    nodes.push({ tag, content: bytes.subarray(offset, end) });
    offset = end;
  }
  return nodes;
}

/** Exactly one node of the given tag, filling the whole input. */
export function readSingle(bytes: Uint8Array, tag: number): DerNode {
  const nodes = readNodes(bytes);
  if (nodes.length !== 1 || (nodes[0] as DerNode).tag !== tag) {
    throw new DerError('unexpected structure');
  }
  return nodes[0] as DerNode;
}

export function expectTag(node: DerNode | undefined, tag: number): DerNode {
  if (!node || node.tag !== tag) {
    throw new DerError('unexpected structure');
  }
  return node;
}

/** A non-negative INTEGER. Negative values never appear in valid keys. */
export function readUnsignedInteger(node: DerNode | undefined): bigint {
  const { content } = expectTag(node, DerTag.Integer);
  if (content.length === 0 || ((content[0] as number) & 0x80) !== 0) {
    throw new DerError('expected a positive integer');
  }
  if (content.length > 1 && content[0] === 0 && ((content[1] as number) & 0x80) === 0) {
    throw new DerError('non-minimal integer');
  }
  let value = BigInt(0);
  for (const byte of content) {
    value = (value << BigInt(8)) | BigInt(byte);
  }
  return value;
}

export function readOid(node: DerNode | undefined): string {
  const { content } = expectTag(node, DerTag.Oid);
  if (content.length === 0) {
    throw new DerError('empty OID');
  }
  if (((content[content.length - 1] as number) & 0x80) !== 0) {
    throw new DerError('truncated OID');
  }
  const subidentifiers: number[] = [];
  let value = 0;
  for (const byte of content) {
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      subidentifiers.push(value);
      value = 0;
    }
  }
  // X.690 §8.19.4: the first subidentifier packs the first two arcs.
  const first = subidentifiers[0] as number;
  const arc0 = first < 80 ? Math.floor(first / 40) : 2;
  return [arc0, first - arc0 * 40, ...subidentifiers.slice(1)].join('.');
}

/** Absent, or an explicit NULL — the only parameters RSA and Ed25519 keys may carry. */
export function expectNoParameters(node: DerNode | undefined): void {
  if (node !== undefined && (node.tag !== DerTag.Null || node.content.length !== 0)) {
    throw new DerError('unexpected algorithm parameters');
  }
}

/** A BIT STRING with no unused bits, as every key format uses. */
export function readBitStringBytes(node: DerNode | undefined): Uint8Array {
  const { content } = expectTag(node, DerTag.BitString);
  if (content.length === 0 || content[0] !== 0) {
    throw new DerError('expected a byte-aligned BIT STRING');
  }
  return content.subarray(1);
}
