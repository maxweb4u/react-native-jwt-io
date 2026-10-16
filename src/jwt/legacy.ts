import { JwtMigrationError } from '../errors/errors';

const GUIDE = 'See "Migrating from 1.x" in the react-native-jwt-io README.';

function removed(name: string, replacement: string): (...args: unknown[]) => never {
  return () => {
    throw new JwtMigrationError(`jwt.${name}() was removed in 2.0. ${replacement} ${GUIDE}`);
  };
}

/**
 * Removed in 2.0. Throws `JwtMigrationError`.
 *
 * Exported by name as well as on the default export: `require()` and a Node
 * ESM default import both see the module's named exports, not its default,
 * and 1.x code written as `jwt.encode(...)` must still fail with a sentence.
 * See memory_bank/adr/ADR-006-named-1x-tombstones.md.
 *
 * @deprecated Use `sign(payload, key, options)`. Removed in 3.0.
 */
export const encode = removed('encode', 'Use sign(payload, key, options).');

/**
 * Removed in 2.0. Throws `JwtMigrationError` — it never decodes, so 1.x code
 * that relied on it to verify cannot silently stop verifying.
 *
 * @deprecated Use `verify(token, key)`, or `decodeUnverified(token)` to read without checking. Removed in 3.0.
 */
export const decode = removed(
  'decode',
  'Use verify(token, key) — it checks the signature and returns { header, payload }. decodeUnverified(token) reads without checking.',
);

/**
 * The 1.x default export, kept until 3.0 so that upgraded code fails with a
 * sentence instead of `Cannot read property 'encode' of undefined`.
 *
 * @deprecated Use the named exports: `sign`, `verify`, `decodeUnverified`.
 */
export const legacyDefaultExport = Object.freeze({
  encode,
  decode,
  verify: removed('verify', 'Use the named export verify(token, key), which returns { header, payload } or throws.'),
});
