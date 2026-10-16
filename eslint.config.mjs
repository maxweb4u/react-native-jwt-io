import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['lib/**', 'coverage/**', 'example/**', 'node_modules/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // A `const` value object paired with a type of the same name is the
      // project's enum pattern (memory_bank/engineering/typescript.md).
      'no-redeclare': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      'no-console': 'error',
      eqeqeq: ['error', 'always'],
      'prefer-const': 'error',
      'no-param-reassign': 'error',
    },
  },
  {
    // Published code runs on Hermes. These globals are absent there or behave
    // differently (Latin-1 strings, not bytes); the library carries its own.
    files: ['src/**/*.ts'],
    ignores: ['src/**/__tests__/**'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'Buffer', message: 'Hermes has no Buffer. Use Uint8Array and src/utils.' },
        { name: 'process', message: 'Not available in React Native.' },
        { name: 'atob', message: 'Latin-1 only, and absent before React Native 0.74. Use src/utils/base64url.' },
        { name: 'btoa', message: 'Latin-1 only, and absent before React Native 0.74. Use src/utils/base64url.' },
        { name: 'TextDecoder', message: 'Absent in Hermes. Use src/utils/utf8.' },
        { name: 'TextEncoder', message: 'Absent in older Hermes. Use src/utils/utf8.' },
      ],
      'no-restricted-imports': [
        'error',
        {
          paths: ['crypto', 'buffer', 'util'].map((name) => ({ name, message: 'Node built-ins are test-only.' })),
          patterns: [{ group: ['node:*'], message: 'Node built-ins are test-only.' }],
        },
      ],
    },
  },
  {
    // jest.isolateModules needs a synchronous require to re-import the library.
    files: ['src/**/__tests__/**/*.ts'],
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    files: ['*.js', '*.mjs', 'scripts/**/*.{js,cjs,mjs}'],
    languageOptions: {
      globals: {
        module: 'writable',
        require: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
        console: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
      'no-console': 'off',
    },
  },
);
