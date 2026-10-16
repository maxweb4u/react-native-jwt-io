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
  // unexplained fall visible. Measured at 96.49 / 95.03 / 100 / 96.41 on
  // 2026-10-16, ±0.1 between runs because test keys are generated per run
  // (memory_bank/engineering/testing-policy.md).
  coverageThreshold: {
    global: { statements: 96, branches: 94, functions: 100, lines: 96 },
  },
};
