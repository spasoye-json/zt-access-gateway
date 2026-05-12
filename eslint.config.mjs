// @ts-check
import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['eslint.config.mjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      sourceType: 'commonjs',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'error', // D-14 (Phase 16): promoted after cleanup; correctness rule
      '@typescript-eslint/no-unsafe-argument': 'warn',
      // Standard typescript-eslint convention: prefix intentionally-unused arguments
      // with `_` to opt them out of no-unused-vars. Phase 16 plan 16-05 Task 2.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      "prettier/prettier": ["error", { endOfLine: "auto" }],
    },
  },
  {
    // D-04 escape valve (Phase 16) — relax type-safety rules in test scope only.
    //
    // Test specs heavily mock Express req/res with `as any` and `jest.fn() as unknown
    // as ...` patterns; clearing the ~900 resulting `no-unsafe-*` hits is a high-
    // volume / low-correctness-value mock-typing exercise. Per CONTEXT.md D-04 and
    // RESEARCH §"D-04 Cutoff Recommendation" + §"D-15 `--max-warnings 0`
    // Reachability" option (a), test-scope cleanup is parked in backlog phase
    // 999.x. Production code (src/**/*.ts excluding __tests__) keeps these rules
    // at ERROR — see preceding `tseslint.configs.recommendedTypeChecked`.
    files: ['**/__tests__/**/*.ts', 'test/**/*.ts', 'tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      // `unbound-method` flips frequently on `jest.toHaveBeenCalledWith(svc.method)`
      // mocking pattern. Same backlog 999.x parking applies.
      '@typescript-eslint/unbound-method': 'off',
      // Phase 16 plan 16-08 extension: additional test-scope-idiomatic rules.
      // - `await-thenable`: `await mockedService.onModuleInit()` against jest-mocked
      //   instances flips when TS sees the mock typing, not the real Promise return.
      // - `require-await`: `async () => { synchronous; }` is idiomatic for
      //   `mockImplementation(async () => ...)` shape matching.
      // - `no-require-imports`: dynamic `require()` is used in tests for reading
      //   source files (parity-test introspection) and for jest.mock setup.
      // - `no-base-to-string` + `restrict-template-expressions`: tests format
      //   error-message strings with `${err instanceof Error ? err.message : String(err)}`
      //   which is the same idiom we use in production but eslint-flags `String(unknown)`.
      //   In test scope the value is always already-typed by the assertion under test.
      '@typescript-eslint/await-thenable': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-base-to-string': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',
    },
  },
);
