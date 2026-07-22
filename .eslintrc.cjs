module.exports = {
  root: true,
  extends: ['eslint:recommended', 'prettier'],
  plugins: ['@typescript-eslint', 'import'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  ignorePatterns: ['build', 'dist', 'node_modules', 'storybook-static'],
  rules: {
    'no-trailing-spaces': 'error',
    'no-console': 'off',
  },
  overrides: [
    {
      files: ['*.ts', '*.tsx'],
      extends: ['plugin:@typescript-eslint/recommended'],
      rules: {
        // `^_` marks a deliberately unused binding. It already covered arguments
        // (e.g. `_userId` on a handler that keeps the shared signature);
        // varsIgnorePattern extends the same convention to the omit-by-
        // destructuring idiom (`const { a: _omit, ...rest } = obj`).
        '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      },
    },
    {
      files: ['*.tsx'],
      extends: ['plugin:react/recommended', 'plugin:react-hooks/recommended'],
      settings: {
        react: {
          version: 'detect',
        },
      },
      rules: {
        'react/react-in-jsx-scope': 'off',
      },
    },
  ],
};
