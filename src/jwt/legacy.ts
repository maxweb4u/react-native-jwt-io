import { JwtMigrationError } from '../errors/errors';

const GUIDE = 'See "Migrating from 1.x" in the react-native-jwt-io README.';

function removed(name: string, replacement: string): () => never {
  return () => {
    throw new JwtMigrationError(`jwt.${name}() was removed in 2.0. ${replacement} ${GUIDE}`);
  };
}

/**
 * The 1.x default export, kept until 3.0 so that upgraded code fails with a
 * sentence instead of `Cannot read property 'encode' of undefined`.
 * See memory_bank/adr/ADR-004-break-from-v1-api.md.
 *
 * @deprecated Use the named exports: `sign`, `verify`, `decodeUnverified`.
 */
export const legacyDefaultExport = Object.freeze({
  encode: removed('encode', 'Use sign(payload, key, options).'),
  decode: removed(
    'decode',
    'Use verify(token, key) — it checks the signature and returns { header, payload }. decodeUnverified(token) reads without checking.',
  ),
  verify: removed('verify', 'Use the named export verify(token, key), which returns { header, payload } or throws.'),
});
