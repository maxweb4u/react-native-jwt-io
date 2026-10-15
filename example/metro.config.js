const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

// The app consumes the library from source in the repository above it: Metro
// watches the root and resolves `react-native-jwt-io` to it. The package's
// `react-native` export condition then points at `src/index.ts`, so edits to
// the library show up on reload with no build step. The crypto dependencies
// (@noble/*, micro-rsa-dsa-dh) resolve from the root's node_modules, as they
// would from a consumer's.
const root = path.resolve(__dirname, '..');

/**
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root],
  resolver: {
    extraNodeModules: {
      'react-native-jwt-io': root,
      // Babel rewrites the library's source to import helpers from
      // @babel/runtime, which only this app installs. Resolution starts next
      // to the library's files, finds the root's node_modules without it, and
      // falls back to this mapping.
      '@babel/runtime': path.resolve(__dirname, 'node_modules/@babel/runtime'),
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
