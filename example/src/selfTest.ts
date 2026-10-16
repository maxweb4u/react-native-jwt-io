import {
  type Algorithm,
  decodeUnverified,
  importPEM,
  isExpired,
  JwtError,
  JwtSignatureError,
  sign,
  verify,
} from 'react-native-jwt-io';
import { fixtures } from './fixtures';

export interface Result {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

const now = (): number =>
  (globalThis as { performance?: { now?: () => number } }).performance?.now?.() ?? Date.now();

function timed<T>(f: () => T, runs = 1): { value: T; ms: number } {
  let value = f();
  if (runs > 1) {
    const start = now();
    for (let i = 0; i < runs; i++) {
      value = f();
    }
    return { value, ms: (now() - start) / runs };
  }
  const start = now();
  value = f();
  return { value, ms: now() - start };
}

const ms = (value: number) => `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`;

/** The token with one signature character changed — still canonical base64url. */
function tamper(token: string): string {
  const at = token.length - 10;
  const replacement = token[at] === 'A' ? 'B' : 'A';
  return token.slice(0, at) + replacement + token.slice(at + 1);
}

/** Whatever `run` throws, as the error, or null when it returns. */
function thrown(run: () => unknown): unknown {
  try {
    run();
    return null;
  } catch (error) {
    return error;
  }
}

function check(name: string, run: () => [boolean, string]): Result {
  try {
    const [ok, detail] = run();
    return { name, ok, detail };
  } catch (error) {
    const e = error as Partial<JwtError>;
    return { name, ok: false, detail: `throws ${e.code ?? ''} ${e.message ?? String(error)}` };
  }
}

/**
 * Every algorithm, against tokens signed by Node's crypto (see
 * scripts/make-fixtures.mjs), plus the safety checks a device must also pass.
 * This is SC-9 and SC-13 of memory_bank/features/FT-001-typescript-rewrite.
 */
export function runSelfTest(): Result[] {
  const g = globalThis as { HermesInternal?: unknown; crypto?: { getRandomValues?: unknown } };
  const hasRandom = typeof g.crypto?.getRandomValues === 'function';
  const results: Result[] = [
    {
      // Only Hermes is supported: a pass on JSC or in a remote debugger's V8
      // would say nothing about the engine apps ship with.
      name: 'Engine',
      ok: Boolean(g.HermesInternal),
      detail: `${g.HermesInternal ? 'Hermes' : 'not Hermes'}, getRandomValues ${hasRandom ? 'present' : 'absent'}`,
    },
  ];

  results.push(
    check('HS256', () => {
      const node = verify(fixtures.hs256NodeToken, fixtures.secret).payload.sub;
      const s = timed(() => sign({ sub: 'app' }, fixtures.secret), 20);
      const v = timed(() => verify(s.value, fixtures.secret), 20);
      return [node === 'node-HS256', `verify ${ms(v.ms)}, sign ${ms(s.ms)}`];
    }),
  );

  for (const c of fixtures.cases) {
    const alg = c.alg as Algorithm;
    results.push(
      check(alg, () => {
        const publicKey = importPEM(c.publicPem, alg);
        const privateKey = importPEM(c.privatePem, alg);
        const verified = timed(() => verify(c.nodeToken, publicKey), 3);
        const fromNode = verified.value.payload.sub === `node-${alg}`;
        if (alg.startsWith('PS') && !hasRandom) {
          // PS* signing needs a random salt; without a source it must say so.
          try {
            sign({}, privateKey);
            return [false, 'signed without a random source'];
          } catch (error) {
            const ok = (error as JwtError).code === 'ERR_JWT_HOST_REQUIREMENT';
            return [fromNode && ok, `verify ${ms(verified.ms)}; sign needs getRandomValues (as designed)`];
          }
        }
        const signed = timed(() => sign({ sub: 'app' }, privateKey));
        const roundTrip = verify(signed.value, publicKey).payload.sub === 'app';
        return [fromNode && roundTrip, `verify ${ms(verified.ms)}, sign ${ms(signed.ms)}`];
      }),
    );
  }

  results.push(
    check('Same bytes as Node', () => {
      // HS256, RS256 (PKCS#1 v1.5) and EdDSA are deterministic: a token signed
      // here must equal Node's byte for byte.
      const rsa = fixtures.cases.find((c) => c.alg === 'RS256')!;
      const ed = fixtures.cases.find((c) => c.alg === 'EdDSA')!;
      const options = { now: new Date(fixtures.reference.iat * 1000) };
      const ours = {
        HS256: sign({ sub: 'reference' }, fixtures.secret, options),
        RS256: sign({ sub: 'reference' }, importPEM(rsa.privatePem, 'RS256'), options),
        EdDSA: sign({ sub: 'reference' }, importPEM(ed.privatePem, 'EdDSA'), options),
      };
      const differ = (Object.keys(ours) as (keyof typeof ours)[]).filter((alg) => ours[alg] !== fixtures.reference.tokens[alg]);
      return [differ.length === 0, differ.length === 0 ? 'HS256, RS256, EdDSA identical' : `differ: ${differ.join(', ')}`];
    }),
    check('Tampered signatures refused', () => {
      // A verifier that always said yes would pass every check above but this one.
      const failures: string[] = [];
      // `name` too: a release build minifies class names, and the library
      // must not take error names from them.
      const named = (error: unknown) =>
        error instanceof JwtSignatureError && error instanceof JwtError && error.name === 'JwtSignatureError';
      const hs = thrown(() => verify(tamper(fixtures.hs256NodeToken), fixtures.secret));
      if (!named(hs)) {
        failures.push('HS256');
      }
      for (const c of fixtures.cases) {
        const error = thrown(() => verify(tamper(c.nodeToken), importPEM(c.publicPem, c.alg as Algorithm)));
        if (!named(error)) {
          failures.push(c.alg);
        }
      }
      return [failures.length === 0, failures.length === 0 ? `all ${fixtures.cases.length + 1}; instanceof and name intact` : `accepted: ${failures.join(', ')}`];
    }),
    check('Unverified read', () => {
      const { header } = decodeUnverified(fixtures.hs256NodeToken);
      return [header.alg === 'HS256' && !isExpired(fixtures.hs256NodeToken), 'decodeUnverified, isExpired'];
    }),
    check('alg "none" refused', () => {
      try {
        verify('eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.', fixtures.secret);
        return [false, 'accepted'];
      } catch (error) {
        return [(error as JwtError).code === 'ERR_JWT_ALGORITHM', (error as JwtError).code];
      }
    }),
    check('Public key as a secret refused', () => {
      const publicPem = fixtures.cases[0]!.publicPem;
      // As a string, and as bytes after a preamble such as openssl pkcs12 writes.
      const preamble = `Bag Attributes\n    friendlyName: server\n    localKeyID: 01 02 03 04\n${publicPem}`;
      const bytes = Uint8Array.from(preamble, (char) => char.charCodeAt(0));
      // And as the bare base64 body, as Keycloak shows a realm's public key.
      const body = publicPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
      const codes = [publicPem, bytes, body].map((key) => (thrown(() => verify(fixtures.hs256NodeToken, key)) as JwtError | null)?.code);
      return [codes.every((c) => c === 'ERR_JWT_KEY_INVALID'), codes.join(', ')];
    }),
  );
  return results;
}
