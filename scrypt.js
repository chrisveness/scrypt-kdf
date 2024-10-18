/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Scrypt password-based key derivation function.    © 2018-2024 Chris Veness / Movable Type Ltd  */
/*                                                                                   MIT Licence  */
/*                                                                                                */
/* The function derives one or more secret keys from a secret string. It is based on memory-hard  */
/* functions, which offer added protection against attacks using custom hardware.                 */
/*                                                                                                */
/* www.tarsnap.com/scrypt.html, tools.ietf.org/html/rfc7914                                       */
/*                                                                                                */
/* This implementation is a zero-dependency wrapper providing access to the OpenSSL scrypt        */
/* function, returning a derived key with scrypt parameters and salt in Colin Percival's standard */
/* file header format, and a function for verifying that key against the original password.       */
/*                                                                                                */
/* Runs on Node.js v18.0.0+ or Deno v2.0.1+.                                                     */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import nodeCrypto      from 'node:crypto'; // for OpenSSL scrypt, timingSafeEqual
import { Buffer }      from 'node:buffer'; // key is returned as Buffer (for better or for worse)
import os              from 'node:os';     // for total amoung to system memory
import { TextEncoder } from 'node:util';   // TextEncoder should be a global in Node.js, but it's not
import { promisify }   from 'node:util';

const opensslScrypt = promisify(nodeCrypto.scrypt); // OpenSSL scrypt; docs.openssl.org/1.1.1/man7/scrypt/
const opensslScryptSync = nodeCrypto.scryptSync;


class Scrypt {

    /**
     * Produce derived key using scrypt as a key derivation function.
     *
     * @param   {string|Uint8Array|Buffer} passphrase - Secret value such as a password from which key is to be derived.
     * @param   {Object}   params - Scrypt parameters.
     * @param   {number}   params.logN - CPU/memory cost parameter.
     * @param   {number=8} params.r - Block size parameter.
     * @param   {number=1} params.p - Parallelization parameter.
     * @returns {Promise<Buffer>} Derived key.
     *
     * @example
     *   const key = (await Scrypt.kdf('my secret password', { logN: 15 })).toString('base64');
     */
    static async kdf(passphrase, params) {
        if (typeof passphrase!='string' && !ArrayBuffer.isView(passphrase)) throw new TypeError(`passphrase must be a string, TypedArray, or Buffer (received ${typeOf(passphrase)})`);
        if (params === undefined) throw new TypeError('params must be supplied');
        if (typeof params != 'object' || params == null) throw new TypeError(`params must be an object (received ${typeOf(params)})`);

        const paramDefaults = { logN: undefined, r: 8, p: 1 };
        params = Object.assign({}, paramDefaults, params);

        // range-check logN, r, p
        const logN = Math.round(params.logN);
        const r = Math.round(params.r);
        const p = Math.round(params.p);
        if (isNaN(logN) || logN != params.logN) throw new RangeError(`parameter logN must be an integer; received ${params.logN}`);
        if (logN < 1 || logN > 30) throw new RangeError(`parameter logN must be between 1 and 30; received ${params.logN}`);
        if (isNaN(r) || r != params.r || r <= 0) throw new RangeError(`parameter r must be a positive integer; received ${params.r}`);
        if (isNaN(p) || p != params.p || p <= 0) throw new RangeError(`parameter p must be a positive integer; received ${params.p}`);
        if (p > (2**30-1)/r) throw new RangeError('parameters p*r must be <= 2^30-1');

        // the derived key is 96 bytes: use an ArrayBuffer to view it in different formats
        const keyBuff = new ArrayBuffer(96);

        // a structured view of the derived key
        const struct = {
            scrypt: new Uint8Array(keyBuff,  0,  6),
            params: {
                v:    new DataView(keyBuff,    6,  1),
                logN: new DataView(keyBuff,    7,  1),
                r:    new DataView(keyBuff,    8,  4),
                p:    new DataView(keyBuff,   12,  4),
            },
            salt:     new Uint8Array(keyBuff, 16, 32),
            checksum: new Uint8Array(keyBuff, 48, 16),
            hmachash: new Uint8Array(keyBuff, 64, 32),
        };

        // set params
        struct.scrypt.set(new TextEncoder().encode('scrypt')); // convert string to Uint8Array
        struct.params.logN.setUint8(0, logN);
        struct.params.r.setUint32(0, r, false); // big-endian
        struct.params.p.setUint32(0, p, false); // big-endian

        // set salt
        struct.salt.set(crypto.getRandomValues(new Uint8Array(32)));

        // set checksum of params & salt
        const prefix48 = new Uint8Array(keyBuff,  0, 48); // view onto struct.scrypt, struct.params, struct.salt
        const prefix48hash = await crypto.subtle.digest('SHA-256', prefix48); // digest() returns ArrayBuffer...
        struct.checksum.set(new Uint8Array(prefix48hash.slice(0, 16))); // note TypedArray.set() requires TypedArray arg, not ArrayBuffer

        // set HMAC hash from scrypt-derived key
        try {
            params = {
                N:      2**logN,
                r:      r,
                p:      p,
                maxmem: 2**31-1, // 2GB is maximum maxmem allowed
            };
            // apply scrypt kdf to salt to derive hmac key
            const hmacKey = await opensslScrypt(passphrase, struct.salt, 64, params);

            // get hmachash of params, salt, & checksum, using 1st 32 bytes of scrypt hash as key
            const prefix64 = new Uint8Array(keyBuff, 0, 64);
            const algorithm = { name: 'HMAC', hash: 'SHA-256' };
            const cryptoKey = await crypto.subtle.importKey('raw', hmacKey.slice(32), algorithm, false, [ 'sign' ]);
            const hmacHash = await crypto.subtle.sign(algorithm.name, cryptoKey, prefix64); // sign() returns ArrayBuffer...
            struct.hmachash.set(new Uint8Array(hmacHash)); // note TypedArray.set() requires TypedArray arg, not ArrayBuffer

            return Buffer.from(keyBuff); // return ArrayBuffer as Buffer/Uint8Array
        } catch (e) {
            throw new Error(e.message); // e.g. memory limit exceeded; localise error to this function
        }
    }


    /**
     * Check whether key was generated from passphrase.
     *
     * @param   {string|Uint8Array|Buffer} key - Derived key obtained from Scrypt.kdf().
     * @param   {string|Uint8Array|Buffer} passphrase - Passphrase originally used to generate key.
     * @returns {Promise<boolean>} True if key was generated from passphrase.
     *
     * @example
     *   const key = (await Scrypt.kdf('my secret password', { logN: 15 })).toString('base64');
     *   const ok = await Scrypt.verify(Buffer.from(key, 'base64'), 'my secret password');
     */
    static async verify(key, passphrase) {
        const keyArr = typeof key == 'string' ? new Uint8Array([ ...atob(key) ].map(ch => ch.charCodeAt(0))) : key;
        if (!(keyArr instanceof Uint8Array)) throw new TypeError(`key must be a Uint8Array/Buffer (received ${typeOf(keyArr)})`);
        if (keyArr.length != 96) throw new RangeError('invalid key');
        if (typeof passphrase!='string' && !ArrayBuffer.isView(passphrase)) throw new TypeError(`passphrase must be a string, TypedArray, or Buffer (received ${typeOf(passphrase)})`);

        // use the underlying ArrayBuffer to view key in different formats
        const keyBuff = keyArr.buffer.slice(keyArr.byteOffset, keyArr.byteOffset + keyArr.byteLength);

        // a structured view of the derived key
        const struct = {
            scrypt: new Uint8Array(keyBuff,  0,  6),
            params: {
                v:    new DataView(keyBuff,    6,  1),
                logN: new DataView(keyBuff,    7,  1),
                r:    new DataView(keyBuff,    8,  4),
                p:    new DataView(keyBuff,   12,  4),
            },
            salt:     new Uint8Array(keyBuff, 16, 32),
            checksum: new Uint8Array(keyBuff, 48, 16),
            hmachash: new Uint8Array(keyBuff, 64, 32),
        };

        // verify checksum of params & salt

        const prefix48 = new Uint8Array(keyBuff,  0, 48); // view onto struct.scrypt, struct.params, struct.salt
        const checksumRecalcd = await crypto.subtle.digest('SHA-256', prefix48);

        if (!nodeCrypto.timingSafeEqual(struct.checksum, checksumRecalcd.slice(0, 16))) return false;

        // rehash scrypt-derived key
        try {
            const params = {
                N:      2**struct.params.logN.getUint8(0),
                r:      struct.params.r.getUint32(0, false), // big-endian
                p:      struct.params.p.getUint32(0, false), // big-endian
                maxmem: 2**31-1, // 2GB is maximum allowed
            };

            // apply scrypt kdf to salt to derive hmac key
            const hmacKey = await opensslScrypt(passphrase, struct.salt, 64, params);

            // get hmachash of params, salt, & checksum, using 1st 32 bytes of scrypt hash as key
            const prefix64 = new Uint8Array(keyBuff, 0, 64);
            const algorithm = { name: 'HMAC', hash: 'SHA-256' };
            const cryptoKey = await crypto.subtle.importKey('raw', hmacKey.slice(32), algorithm, false, [ 'sign' ]);
            const hmacHash = await crypto.subtle.sign(algorithm.name, cryptoKey, prefix64);

            // verify hash
            return nodeCrypto.timingSafeEqual(hmacHash, struct.hmachash);
        } catch (e) {
            throw new Error(e.message); // localise error to this function [can't happen?]
        }
    }


    /**
     * View scrypt parameters which were used to derive key.
     *
     * @param   {string|Uint8Array|Buffer} key - Derived base64 key obtained from Scrypt.kdf().
     * @returns {Object} Scrypt parameters logN, r, p.
     *
     * @example
     *   const key = await Scrypt.kdf('my secret password', { logN: 15 } );
     *   const params = Scrypt.viewParams(key); // => { logN: 15, r: 8, p: 1 }
     */
    static viewParams(key) {
        const keyArr = typeof key == 'string' ? new Uint8Array([ ...atob(key) ].map(ch => ch.charCodeAt(0))) : key;
        if (!(keyArr instanceof Uint8Array)) throw new TypeError(`key must be a Uint8Array/Buffer (received ${typeOf(keyArr)})`);
        if (keyArr.length != 96) throw new RangeError('invalid key');

        // use the underlying ArrayBuffer to view key in structured format
        const keyBuff = keyArr.buffer.slice(keyArr.byteOffset, keyArr.byteOffset + keyArr.byteLength);

        // a structured view of the derived key
        const struct = {
            scrypt: new Uint8Array(keyBuff,  0,  6),
            params: {
                v:    new DataView(keyBuff,    6,  1),
                logN: new DataView(keyBuff,    7,  1),
                r:    new DataView(keyBuff,    8,  4),
                p:    new DataView(keyBuff,   12,  4),
            },
            salt:     new Uint8Array(keyBuff, 16, 32),
            checksum: new Uint8Array(keyBuff, 48, 16),
            hmachash: new Uint8Array(keyBuff, 64, 32),
        };

        const params = {
            logN: struct.params.logN.getUint8(0),
            r:    struct.params.r.getUint32(0, false), // big-endian
            p:    struct.params.p.getUint32(0, false), // big-endian
        };

        return params;
    }


    /**
     * Calculate scrypt parameters from maxtime, maxmem, maxmemfrac values.
     *
     * Adapted from Colin Percival's code: see github.com/Tarsnap/scrypt/tree/master/lib.
     *
     * Returned parameters may vary depending on computer specs & current loading.
     *
     * @param   {number}          maxtime - Maximum time in seconds scrypt will spend computing the derived key.
     * @param   {number=availMem} maxmem - Maximum bytes of RAM used when computing the derived encryption key.
     * @param   {number=0.5}      maxmemfrac - Fraction of the available RAM used when computing the derived key.
     * @returns {Object} Scrypt parameters logN, r, p.
     *
     * @example
     *   const params = Scrypt.pickParams(0.1); // => e.g. { logN: 15, r: 8, p: 1 }
     */
    static pickParams(maxtime, maxmem=os.totalmem(), maxmemfrac=0.5) {
        if (maxmem==0 || maxmem==null) maxmem = os.totalmem();
        if (maxmemfrac==0 || maxmemfrac>0.5) maxmemfrac = 0.5;

        // memory limit is memfrac · physical memory, no more than maxmem and no less than 1MiB
        const physicalMemory = os.totalmem();
        const memlimit = Math.max(Math.min(physicalMemory*maxmemfrac, maxmem), 1024*1024);

        // Colin Percival measures how many scrypts can be done in one clock tick using C/POSIX
        // clock_getres() / CLOCKS_PER_SEC (usually just one?); we will use performance.now() to get
        // a DOMHighResTimeStamp. (Following meltdown/spectre timing attacks Chrome reduced the high
        // res timestamp resolution to 100µs, so we'll be conservative and do a 1ms run - typically
        // 1..10 minimal scrypts).
        let i = 0;
        const start = performance.now();
        while (performance.now()-start < 1) {
            opensslScryptSync('', '', 64, { N: 128, r: 1, p: 1 });
            i += 512; // we invoked the salsa20/8 core 512 times
        }
        const duration = (performance.now()-start) / 1000; // in seconds
        const opps = i / duration;

        // allow a minimum of 2^15 salsa20/8 cores
        const opslimit = Math.max(opps * maxtime, 2**15);

        const r = 8; // "fix r = 8 for now"

        // memory limit requires that 128·N·r <= memlimit
        // CPU limit requires that 4·N·r·p <= opslimit
        // if opslimit < memlimit/32, opslimit imposes the stronger limit on N

        let p = null;
        let logN = 0;
        if (opslimit < memlimit/32) {
            // set p = 1 & choose N based on CPU limit
            p = 1;
            const maxN = opslimit / (r*4);
            while (1<<logN <= maxN/2 && logN < 63) logN++;
        } else {
            // set N based on the memory limit
            const maxN = memlimit / (r * 128);
            while (1<<logN <= maxN/2 && logN < 63) logN++;
            // choose p based on the CPU limit
            const maxrp = Math.min((opslimit / 4) / (1<<logN), 0x3fffffff);
            p = Math.round(maxrp / r);
        }

        return { logN, r, p };
    }

}

/**
 * Return more useful type description than 'typeof': javascriptweblog.wordpress.com/2011/08/08/
 */
function typeOf(obj) {
    return ({}).toString.call(obj).match(/\s([a-zA-Z]+)/)[1].toLowerCase();
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default Scrypt;
