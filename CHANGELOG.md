# Changelog

## Unreleased

### Changed

- Increase pickParams() timing loop

## [3.0.0] - 2024-10-18

### Changed

- BREAKING: Convert to ESM
- Run in Node.js & Deno
- Strings accepted for passphrase & key arguments
- Use Web Crypto API in place of node:crypto (except OpenSSL scrypt, timingSafeEqual)
- Indicate received type when parameter type checks fail
- Use GitHub Actions CI in place of Travis CI

## [2.0.1] - 2019-05-03

### Changed

- Node.js 'engines' changed to >=8.5.0 to facilitate polyfill usage in yarn

## [2.0.0] - 2019-02-15

### Changed
- [BREAKING] Return & accept key as Buffer rather than as base-64 string

## [1.1.0] - 2018-12-20

### Added
- Add TypeScript declaration file

### Changed
- Accept passphrase as TypedArray or Buffer

## [1.0.1] - 2018-10-11

### Changed
- Throw if crypto.scrypt not available (i.e. Node.js < 10.5)
- Add extra range checks on r, p params

## [1.0.0] - 2018-07-02
- Initial release
