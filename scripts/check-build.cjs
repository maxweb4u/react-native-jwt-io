#!/usr/bin/env node
/**
 * Smoke test of the built package, run by `prepack`.
 *
 * Loads lib/commonjs through the package's own `exports` map, the way a Node
 * consumer would. This is the check that the CommonJS build can `require()`
 * the ESM-only crypto dependencies (Node >= 20.19), which neither the type
 * checker nor Jest (which transforms them) can see.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const jwt = require(require.resolve('react-native-jwt-io', { paths: [root] }));

const secret = 'a-secret-that-is-at-least-32-bytes-long!';
const token = jwt.sign({ sub: 'build-check' }, secret, { expiresIn: '5m' });
assert.equal(jwt.verify(token, secret).payload.sub, 'build-check');
assert.equal(jwt.decodeUnverified(token).header.alg, 'HS256');
assert.throws(() => jwt.default.encode({}, secret), { code: 'ERR_JWT_MIGRATION' });
// 1.x code written as `const jwt = require(...); jwt.encode(...)` sees the
// named exports, not the default: the tombstones must be there too.
assert.throws(() => jwt.encode({}, secret), { code: 'ERR_JWT_MIGRATION' });
assert.throws(() => jwt.decode('t', secret), { code: 'ERR_JWT_MIGRATION' });
assert.throws(() => jwt.verify(token, secret, { algorithm: 'HS512' }), { code: 'ERR_JWT_ALGORITHM' });

// A Node ESM default import of the CommonJS build is `module.exports`.
const esm = spawnSync(
  process.execPath,
  [
    '--input-type=module',
    '-e',
    `import jwt from 'react-native-jwt-io';
     try { jwt.encode({}, 's'); process.exit(2); } catch (e) { process.exit(e.code === 'ERR_JWT_MIGRATION' ? 0 : 3); }`,
  ],
  { cwd: root, encoding: 'utf8' },
);
assert.equal(esm.status, 0, `Node ESM default import: ${esm.stderr || `exit ${esm.status}`}`);

// lib/module is for bundlers (its imports are extensionless, so Node cannot
// load it) and lib/typescript for the type checker: check they were built,
// and that the host check is still the first thing the ES build imports.
const esmIndex = fs.readFileSync(path.join(root, 'lib/module/index.js'), 'utf8');
assert.match(esmIndex.split('\n').find((line) => line.startsWith('import')) ?? '', /^import '\.\/host\/hostCheck';/);
const declarations = fs.readFileSync(path.join(root, 'lib/typescript/index.d.ts'), 'utf8');
for (const name of ['sign', 'verify', 'decodeUnverified', 'importPEM', 'importJWK', 'createJWKS']) {
  assert.match(declarations, new RegExp(`\\b${name}\\b`), `lib/typescript/index.d.ts does not export ${name}`);
}

console.log(`check-build: lib/commonjs loads, round-trips and keeps the 1.x tombstones (require, ESM); lib/module and lib/typescript are complete; Node ${process.version}`);
