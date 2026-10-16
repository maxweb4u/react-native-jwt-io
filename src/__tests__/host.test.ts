/**
 * SC-15, SC-17 and the PS* random-source check: failures that must read as a
 * sentence, not as a stack trace from inside a dependency.
 */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import jwt, { decode, encode, importPEM, JwtError, JwtMigrationError, sign } from '../index';
import { nodeKeyPair, pem } from './helpers/node';

describe('host requirements (SC-17)', () => {
  // Removes a global for one isolated import of the whole library, the way
  // react-native-matrix's hostSupport test removes crypto.
  function importWithout(object: object, name: string): unknown {
    const descriptor = Object.getOwnPropertyDescriptor(object, name) as PropertyDescriptor;
    delete (object as Record<string, unknown>)[name];
    try {
      let thrown: unknown;
      jest.isolateModules(() => {
        try {
          require('../index');
        } catch (error) {
          thrown = error;
        }
      });
      return thrown;
    } finally {
      Object.defineProperty(object, name, descriptor);
    }
  }

  it('names Object.hasOwn before noble fails on it', () => {
    const error = importWithout(Object, 'hasOwn') as { code: string; feature: string; message: string };
    expect(error.code).toBe('ERR_JWT_HOST_REQUIREMENT');
    expect(error.feature).toBe('Object.hasOwn');
    expect(error.message).toMatch(/polyfill/);
    expect(error.message).toMatch(/0\.74/);
  });

  it('names TextEncoder, which noble calls while it loads (Hermes before React Native 0.74)', () => {
    const error = importWithout(globalThis, 'TextEncoder') as { code: string; feature: string; message: string };
    expect(error).toEqual(expect.objectContaining({ code: 'ERR_JWT_HOST_REQUIREMENT', feature: 'TextEncoder' }));
    expect(error.message).toMatch(/0\.74/);
  });

  it('the TextEncoder check is needed: without it, noble fails while loading', () => {
    // Guards the reason for the check — if a noble update stops calling
    // TextEncoder at load, the requirement (and the React Native floor) can drop.
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder') as PropertyDescriptor;
    delete (globalThis as Record<string, unknown>).TextEncoder;
    try {
      let thrown: unknown;
      jest.isolateModules(() => {
        try {
          require('@noble/curves/ed25519.js');
        } catch (error) {
          thrown = error;
        }
      });
      expect(String(thrown)).toMatch(/TextEncoder/);
    } finally {
      Object.defineProperty(globalThis, 'TextEncoder', descriptor);
    }
  });

  it('names a Babel setup that rewrites ** into Math.pow (React Native 0.70)', () => {
    // Compiles hostCheck.ts the way React Native 0.70's preset did — with **
    // lowered to Math.pow — and runs it. The check must fail on its own **,
    // before noble's Ed25519 code would.
    // @babel/core 8 is ESM-only, so it runs in its own Node process.
    const compile = `
      import { transformFileSync } from '@babel/core';
      const result = transformFileSync(process.argv[1], {
        babelrc: false,
        configFile: false,
        presets: [['@babel/preset-env', { targets: { chrome: '50' }, modules: 'commonjs' }], '@babel/preset-typescript'],
      });
      process.stdout.write(result.code);`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', compile, join(__dirname, '../host/hostCheck.ts')], {
      cwd: join(__dirname, '../..'),
      encoding: 'utf8',
    });
    const compiled = child.stdout;
    expect(compiled).toMatch(/Math\.pow/);
    const module = { exports: {} };
    const run = new Function('require', 'module', 'exports', compiled);
    const errors = jest.requireActual('../errors/errors');
    expect(() => run(() => errors, module, module.exports)).toThrow(
      expect.objectContaining({ code: 'ERR_JWT_HOST_REQUIREMENT', feature: 'BigInt exponentiation (**)' }),
    );
  });

  it('names BigInt', () => {
    const error = importWithout(globalThis, 'BigInt') as { code: string; feature: string };
    expect(error).toEqual(expect.objectContaining({ code: 'ERR_JWT_HOST_REQUIREMENT', feature: 'BigInt' }));
  });

  it('asks for crypto.getRandomValues only for PS* signing', () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto') as PropertyDescriptor;
    const rsa = nodeKeyPair('rsa');
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
      expect(() => sign({}, importPEM(pem(rsa.privateKey), 'PS256'))).toThrow(/react-native-get-random-values/);
      expect(sign({}, importPEM(pem(rsa.privateKey), 'RS256'))).toMatch(/^ey/);
    } finally {
      Object.defineProperty(globalThis, 'crypto', descriptor);
    }
  });
});

describe('1.x tombstones (SC-15)', () => {
  it.each(['encode', 'decode', 'verify'] as const)('jwt.%s throws a migration error naming the replacement', (name) => {
    expect(() => (jwt[name] as () => unknown)()).toThrow(JwtMigrationError);
    expect(() => (jwt[name] as () => unknown)()).toThrow(/2\.0/);
  });

  it.each([
    ['encode', encode, /sign\(payload, key, options\)/],
    ['decode', decode, /verify\(token, key\)/],
  ] as const)('the named %s throws the same migration error (for require and Node ESM)', (_name, fn, replacement) => {
    expect(() => fn({ id: 1 }, 'secret')).toThrow(JwtMigrationError);
    expect(() => fn({ id: 1 }, 'secret')).toThrow(replacement);
    expect(jwt.encode).toBe(encode);
    expect(jwt.decode).toBe(decode);
  });

  it('errors are JwtError subclasses with instanceof intact', () => {
    expect(() => jwt.encode()).toThrow(JwtError);
    expect(() => jwt.encode()).toThrow(expect.objectContaining({ name: 'JwtMigrationError' }));
  });
});
