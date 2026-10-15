/**
 * Wycheproof vectors (C2SP): signatures crafted to break signature
 * verification — malleable encodings, out-of-range values, wrong padding,
 * edge-case points. Run through importPEM and the crypto module exactly as a
 * token's signature would be. Fixtures are trimmed copies of
 * C2SP/wycheproof testvectors_v1; see fixtures/wycheproof/README.md.
 *
 * "valid" must verify, "invalid" must not. "acceptable" cases are legal
 * either way and are skipped.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyBytes } from '../crypto/backend';
import { importPEM } from '../index';
import { keyMaterialOf } from '../keys/JwtKey';
import { type Algorithm } from '../types/algorithm';

interface Vector {
  tcId: number;
  msg: string;
  sig: string;
  result: 'valid' | 'invalid' | 'acceptable';
  comment: string;
  key?: string;
}
interface Group {
  publicKeyPem?: string;
  tests: Vector[];
}
interface VectorFile {
  algorithm: Algorithm;
  testGroups: Group[];
}

const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'));
const load = (alg: string): VectorFile =>
  JSON.parse(readFileSync(join(__dirname, 'fixtures', 'wycheproof', `${alg}.json`), 'utf8')) as VectorFile;

describe.each(['HS256', 'RS256', 'PS256', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'])('%s', (alg) => {
  const file = load(alg);

  it('verifies every valid vector and rejects every invalid one', () => {
    const failures: string[] = [];
    let checked = 0;
    for (const group of file.testGroups) {
      const material = group.publicKeyPem
        ? keyMaterialOf(importPEM(group.publicKeyPem, file.algorithm))
        : undefined;
      for (const t of group.tests) {
        if (t.result === 'acceptable') {
          continue;
        }
        const key = material ?? { kind: 'secret' as const, secret: hex(t.key as string) };
        const ok = verifyBytes(file.algorithm, key, hex(t.msg), hex(t.sig));
        checked++;
        if (ok !== (t.result === 'valid')) {
          failures.push(`tcId ${t.tcId} (${t.result}, ${t.comment || 'no comment'}): got ${ok}`);
        }
      }
    }
    expect(failures).toEqual([]);
    expect(checked).toBeGreaterThan(80);
  });
});
