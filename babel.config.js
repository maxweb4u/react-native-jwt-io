// Used by Jest only. Metro consumers compile `src/` with their own React
// Native preset; the published `lib/` is built by `tsc`.
module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' } }],
    '@babel/preset-typescript',
  ],
};
