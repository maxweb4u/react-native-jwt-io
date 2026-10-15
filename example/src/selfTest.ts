import {
  type Algorithm,
  decodeUnverified,
  importPEM,
  isExpired,
  type JwtError,
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
      name: 'Engine',
      ok: true,
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
    check('PEM as a string refused', () => {
      try {
        verify(fixtures.hs256NodeToken, fixtures.cases[0]!.publicPem);
        return [false, 'accepted'];
      } catch (error) {
        return [(error as JwtError).code === 'ERR_JWT_KEY_INVALID', (error as JwtError).code];
      }
    }),
  );
  return results;
}
