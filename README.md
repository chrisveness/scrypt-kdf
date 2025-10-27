Scrypt Key Derivation Function
==============================

![Node.js CI](https://github.com/chrisveness/scrypt-kdf/actions/workflows/node.js.yml/badge.svg)

Scrypt is a *password-based [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function)*, useful for storing password hashes for verifying interactive logins.

Passwords should never, of course, be stored as plaintext, but even salted hashed passwords can be susceptible to brute-force attack using custom hardware. Key derivation functions can be tuned to be computationally expensive to calculate, in order to protect against attack.

Scrypt is a ‘memory-hard’ algorithm, meaning that it will produce keys (hashes) which are strongly resistant to attack using GPUs and other custom hardware, which may be computationally powerful but have limited memory. It is designed to be stronger than earlier KDFs [bcrypt](PBKDF2) and  [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2).

It was originally developed by Colin Percival as part of the [Tarsnap](http://www.tarsnap.com/scrypt.html) file encryption utility. It is fully described in Percival’s paper [Stronger Key Derivation via Sequential Memory-Hard Functions](http://www.tarsnap.com/scrypt/scrypt.pdf), and is specified in [RFC 7841](https://tools.ietf.org/html/rfc7914).

`scrypt-kdf` is a zero-dependency JavaScript implementation of the [Node.js crypto](https://nodejs.org/api/crypto.html#crypto_crypto_scrypt_password_salt_keylen_options_callback) wrapper around the [OpenSSL EVP_KDF-SCRYPT](https://docs.openssl.org/master/man7/EVP_KDF-SCRYPT) function; it returns the KDF as a key incorporating[<sup>*</sup>](#key-format) the scrypt parameters and salt, enabling it to be stored in a form which can readily be used for verification.

- the `kdf(passphrase, params)` function returns a key (together with scrypt parameters and salt in Colin Percival’s [standard file header format](#key-format):), which can be stored for later verification
- the `verify(key, passphrase)` function verifies that the stored key was derived from the supplied password.


Example usage
-------------

`scrypt-kdf` is available from [npm](https://www.npmjs.com/package/scrypt-kdf):

    $ npm install scrypt-kdf

### hashing

    import Scrypt from 'scrypt-kdf');

    const key = await Scrypt.kdf('my secret pw', { logN: 15 }); // key is Uint8Array

    // key can be used as Uint8Array, or converted to (base64) String or (Node.js) Buffer
    const keyStr = key.toBase64();
    const keyBuf = Buffer.from(key);

    // the passphrase can also be supplied as a Uint8Array (including a Node.js Buffer)
    const key = await Scrypt.kdf(new TextEncoder().encode('my secret pw'), { logN: 15 }); // Uint8Array
    const key = await Scrypt.kdf(Buffer.from('my secret pw'), { logN: 15 });              // Node.js Buffer

    // (note: Uint8Array.toBase64() is not available on Node.js < v24.8.1 or Deno < v2.5.0,
    // so use btoa(new TextDecoder('utf8').decode(key)) on older versions)

### verifying

    import Scrypt from 'scrypt-kdf');

    const user = await users.findOne({ email: req.body.email });      // for example
    const ok = await Scrypt.verify(user.password, req.body.password); // user.password is a base64 string

    // key may be either (base64) string or Uint8Array, and passphrase may be either string or Uint8Array

### in Deno:

    import Scrypt from 'npm:scrypt-kdf@^4';

API
---

### – hash

`Scrypt.kdf(passphrase, params)` – derive key from given passphrase (async).

- `passphrase` is a user-supplied password string/Uint8Array to be hashed and stored.
- `params` is an object with properties `logN`, `r`, `p`.
  - `logN` is a CPU/memory cost parameter: an integer *work factor* which determines the cost of the key derivation function, and hence the security of the stored key; for sub-100ms interactive logins, a [value of 15 is recommended](https://blog.filippo.io/the-scrypt-parameters/) for current (2017) hardware (increased from the original 2009 recommendation of 14)
  - `r` (optional) is a block size parameter, an integer conventionally fixed at 8.
  - `p` (optional) is a parallelization parameter, an integer conventionally fixed at 1.
- returns: (promised) key as a Uint8Array which can be stored in any preferred format.

### – verify

`Scrypt.verify(key, passphrase)` – confirm key was derived from passphrase (async).

- `key` is a Uint8Array obtained from `Scrypt.kdf()` (or corresponding base64 string / Node.js Buffer).
- `passphrase` is the password string/Uint8Array/Buffer used to derive the stored `key`.
- returns: (promised) `true` for successful verification, `false` otherwise.

### – view parameters

`Scrypt.viewParams(key)` – return the `logN`, `r`, `p` parameters used to derive `key`.

- `key` is a Uint8Array (or base64 string or Node.js Buffer) obtained from `Scrypt.kdf()`.
- returns `{ logN, r, p }` object.

### – pick parameters

`Scrypt.pickParams(maxtime, maxmem, maxmemfrac)` – return scrypt parameters for given operational parameters.

Percival’s calculation for optimal parameters can be used to verify Valsorda’s / Percival’s [recommendation of 15](https://words.filippo.io/the-scrypt-parameters) for logN; though in empirical tests (in 2024) it appears to underestimate logN by one or two – timing tests are the most reliable way to validate optimal parameters.

- `maxtime` is the maximum time in seconds scrypt will spend computing the derived encryption key from the password (0.1 seconds is recommended for interactive logins).
- `maxmem` (optional) is the maximum RAM scrypt will use when computing the derived encryption key, in bytes (default maximum available physical memory).
- `maxmemfrac` (optional) is the maximum fraction of available RAM scrypt will use for computing the derived encryption key (default 0.5); if not within the range 0 < maxmemfrac <= 0.5, this will be set to 0.5.
- returns `{ logN, r, p }` object.

Note that results are dependent on the computer the calculation is run on; calculated parameters may vary depending on computer specs & current loading.


Key format
----------

The key is returned as a 96-byte Uint8Array for maximum flexibility, in Colin Percival’s [standard file header format](https://github.com/Tarsnap/scrypt/blob/master/FORMAT):

| offset | length | value
| -----: | -----: | :----
|      0 |      6 | ‘scrypt’
|      6 |      1 | version [0]
|      7 |      1 | log2(N) (1..63)
|      8 |      4 | r (big-endian integer; r·p < 2³⁰)
|     12 |      4 | p (big-endian integer; r·p < 2³⁰)
|     16 |     32 | (random) salt
|     48 |     16 | checksum: first 16 bytes of SHA256(bytes 0–47)
|     64 |     32 | HMAC-SHA256(bytes 0–63), with scrypt(password, salt, 64, { N, r, p }) as key

If converted to base-64 (for trouble-free storage or transmission), the key will be a 128-character string, which will always begin with *c2NyeXB0*, as this is ‘scrypt’ encoded as base-64.
