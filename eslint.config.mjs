import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['build/', 'dist/', 'node_modules/', 'storybook-static/', 'src/ui/api/generated/'],
  },
  {
    files: ['**/*.{js,jsx,mjs,cjs,ts,tsx}'],
  },
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    extends: [tseslint.configs.recommended],
    rules: {
      // `^_` marks a deliberately unused binding. It already covered arguments
      // (e.g. `_userId` on a handler that keeps the shared signature);
      // varsIgnorePattern extends the same convention to the omit-by-
      // destructuring idiom (`const { a: _omit, ...rest } = obj`).
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['**/*.tsx'],
    extends: [react.configs.flat.recommended, react.configs.flat['jsx-runtime'], reactHooks.configs.flat['recommended-latest']],
    settings: {
      react: {
        // Pinned rather than 'detect': detection calls context.getFilename(), which
        // ESLint 10 removed, and eslint-plugin-react has not caught up.
        version: '19.1.2',
      },
    },
    rules: {
      'react-hooks/set-state-in-effect': 'off',
    },
  },
  prettier,
  {
    rules: {
      'no-trailing-spaces': 'error',
      'no-console': 'off',
    },
  },
  {
    files: ['.storybook/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  }
);
