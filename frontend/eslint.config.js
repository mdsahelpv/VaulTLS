import js from '@eslint/js'
import vue from 'eslint-plugin-vue'
import ts from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'

export default [
  {
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      env: { browser: true, node: true, es6: true },
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: 'module',
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      ...ts.configs.recommended.rules,
    },
  },
  ...vue.configs['flat/recommended'],
  {
    files: ['**/*.{ts,tsx,vue}'],
    plugins: {
      '@typescript-eslint': ts,
    },
  },
  {
    ignores: ['*.config.*', '**/*.min.js', 'node_modules/', 'dist/', '**/*.d.ts', 'public/', '.git/', 'playwright-report/', 'test-results/'],
  }
]
