// @ts-check

// This file came from https://typescript-eslint.io/getting-started/ and updates the configuration file from the deprecated eslintrc.js file format

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // These rules are set to warn solely to silence the linter, since the code came from autogeneration.
    // It could be possible that autogeneration nolonger breaks these rules at some point.
    "rules": {
      '@typescript-eslint/no-var-requires': 'warn',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': 'warn',
      '@typescript-eslint/no-namespace': 'warn',
      '@typescript-eslint/no-this-alias': 'warn',
      'no-undef': 'warn'
    }
  },
);