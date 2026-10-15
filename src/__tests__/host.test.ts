/**
 * SC-15, SC-17 and the PS* random-source check: failures that must read as a
 * sentence, not as a stack trace from inside a dependency.
 */
import jwt, { importPEM, JwtError, JwtMigrationError, sign } from '../index';
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

  it('errors are JwtError subclasses with instanceof intact', () => {
    try {
      jwt.encode();
    } catch (error) {
      expect(error).toBeInstanceOf(JwtError);
      expect((error as JwtError).name).toBe('JwtMigrationError');
    }
  });
});
