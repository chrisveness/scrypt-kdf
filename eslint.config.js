import eslintjs from '@eslint/js';
import globals  from 'globals';

export default [
    eslintjs.configs.recommended,
    { ignores: [ 'tmp/' ] }, // github.com/eslint/eslint/discussions/18304
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
                Deno: 'readonly',
            },
        },
        rules: {
            'array-bracket-spacing':   [ 'error', 'always' ],
            'comma-dangle':            [ 'error', 'always-multiline' ],
            'comma-spacing':           [ 'error' ],
            'curly':                   [ 'error', 'multi-line' ],
            'indent':                  [ 'error', 4, { 'SwitchCase': 1 } ],
            'key-spacing':             [ 'error', { 'align': 'value' } ],
            'keyword-spacing':         [ 'error' ],
            'no-case-declarations':    'warn',
            'no-console':              [ 'warn', { 'allow': [ 'error', 'info', 'debug' ] } ],
            'no-irregular-whitespace': 'warn',
            'no-redeclare':            'warn',
            'no-shadow':               'warn',
            'no-unused-vars':          'warn',
            'no-var':                  'error',
            'object-curly-spacing':    [ 'error', 'always' ],
            'prefer-const':            'error',
            'quotes':                  [ 'error', 'single', 'avoid-escape' ],
            'require-await':           'error',
            'semi':                    [ 'error', 'always' ],
            'space-before-blocks':     [ 'error', 'always' ],
            'space-in-parens':         [ 'error' ],
            'strict':                  [ 'error', 'global' ],
        },
    },
];
