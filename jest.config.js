/**
 * One project: unit, interop and hostile-input suites all run in Node with no
 * network. Node's `crypto` is the interop oracle.
 *
 * See memory_bank/engineering/testing-policy.md
 */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  // The crypto dependencies are ESM-only and must be transformed to run under
  // Jest's CommonJS module system.
  transformIgnorePatterns: ['/node_modules/(?!(?:@noble|micro-rsa-dsa-dh)/)'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/__tests__/**', '!src/index.ts', '!src/types/**'],
  // A floor just under the measured value, not a goal: it exists to make an
  // unexplained fall visible. Measured at 93.97 / 91.56 / 100 / 93.86 on
  // 2026-10-15 (memory_bank/engineering/testing-policy.md).
  coverageThreshold: {
    global: { statements: 93, branches: 90, functions: 100, lines: 93 },
  },
};
