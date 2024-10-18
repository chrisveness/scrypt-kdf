/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Tests for scrypt key derivation function using Node.js.                                        */
/*                                                   © 2018-2024 Chris Veness / Movable Type Ltd  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import { test, describe } from 'node:test';
import assert             from 'node:assert/strict';

import { Buffer } from 'node:buffer';

import Scrypt from '../scrypt.js';

const password = 'my secret password';
const key0salt = 'c2NyeXB0AAwAAAAIAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA08wOZXFAec6Si7mP1SzrmK6Pvpx2zfUEXXAuM68S4DAnUER44bh+BxsnxMC75Jgs';


describe('Hash & verify (base64)', function() {

    test('with just logN param, args as Buffer', async function() {
        const keyBuff = await Scrypt.kdf(password, { logN: 12 });
        assert.deepEqual(Scrypt.viewParams(keyBuff), { logN: 12, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(keyBuff, password), true);
    });

    test('with logN, r, p params, args as Buffer', async function() {
        const keyBuff = await Scrypt.kdf(password, { logN: 12, r: 9, p: 2 });
        assert.deepEqual(Scrypt.viewParams(keyBuff), { logN: 12, r: 9, p: 2 });
        assert.equal(await Scrypt.verify(keyBuff, password), true);
    });

    test('with args as strings', async function() {
        const keyStr = (await Scrypt.kdf(password, { logN: '12', r: '8', p: '1' })).toString('base64');
        assert.deepEqual(Scrypt.viewParams(keyStr), { logN: 12, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(keyStr, password), true);
    });

    test('fails to verify with bad passphrase', async function() {
        const keyStr = (await Scrypt.kdf(password, { logN: 12 })).toString('base64');
        assert.equal(await Scrypt.verify(keyStr, 'wrong password'), false);
    });
});

describe('Verify previous key (base64)', function() {
    test('verifies null-salt key', async function() {
        assert.equal(await Scrypt.verify(Buffer.from(key0salt, 'base64'), password), true);
    });

    test('fails to verify null-salt key with bad passphrase', async function() {
        assert.equal(await Scrypt.verify(Buffer.from(key0salt, 'base64'), 'wrong password'), false);
    });
});

describe('Args as String/Uint8Array/Buffer', function() {

    test('String', async function() {
        const pwStr = String.fromCharCode(...[ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const keyStr = (await Scrypt.kdf(pwStr, { logN: 12 })).toString('base64');
        assert.deepEqual(Scrypt.viewParams(keyStr), { logN: 12, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(keyStr, pwStr), true);
    });

    test('Uint8Array', async function() {
        const pwArr = new Uint8Array([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const keyArr = new Uint8Array(await Scrypt.kdf(pwArr, { logN: 12 }));
        assert.deepEqual(Scrypt.viewParams(keyArr), { logN: 12, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(keyArr, pwArr), true);
    });

    test('Buffer', async function() {
        const pwBuff = Buffer.from([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const keyBuff = await Scrypt.kdf(pwBuff, { logN: 12 });
        assert.deepEqual(Scrypt.viewParams(keyBuff), { logN: 12, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(keyBuff, pwBuff), true);
    });
});

describe('Pick params', function() {
    test('Picks params for 100ms', function() {
        const params = Scrypt.pickParams(0.1, 1024*1024*1024, 0.5);
        assert.deepEqual(Object.keys(params), [ 'logN', 'r', 'p' ]);
        assert(params.logN >= 8 && params.logN <= 20);
        assert.equal(params.r, 8);
        assert.equal(params.p, 1);
    });

    test('Picks params with default maxmem/maxmemfrac', function() {
        const params = Scrypt.pickParams(0.1);
        assert.deepEqual(Object.keys(params), [ 'logN', 'r', 'p' ]);
        assert(params.logN >= 8 && params.logN <= 20);
        assert.equal(params.r, 8);
        assert.equal(params.p, 1);
    });

    test('Picks params with 0 maxmem', function() {
        const params = Scrypt.pickParams(0.1, 0);
        assert(params.logN >= 8 && params.logN <= 20);
    });

    test('Picks params with 0 maxmemfrac', function() {
        const params = Scrypt.pickParams(0.1, 0, 0);
        assert(params.logN >= 8 && params.logN <= 20);
    });

    test('Picks params setting N based on memory limit', function() {
        const params = Scrypt.pickParams(1, 1024, 0.1);
        assert(params.logN >= 8 && params.logN <= 20);
        assert(params.p > 1);
    });
});

describe('Kdf errors', function() {
    test('rejects on numeric passphrase', function() {
        assert.rejects(async () => await Scrypt.kdf(99), new TypeError('passphrase must be a string, TypedArray, or Buffer (received number)'));
    });

    test('rejects on no params', function() {
        assert.rejects(async () => await Scrypt.kdf(password), new TypeError('params must be supplied'));
    });

    test('rejects on bad params', function() {
        assert.rejects(async () => await Scrypt.kdf(password, null), new TypeError('params must be an object (received null)'));
    });

    test('rejects on bad params', function() {
        assert.rejects(async () => await Scrypt.kdf(password, false), new TypeError('params must be an object (received boolean)'));
    });

    test('rejects on bad params', function() {
        assert.rejects(async () => await Scrypt.kdf(password, 99), new TypeError('params must be an object (received number)'));
    });

    test('rejects on bad params', function() {
        assert.rejects(async () => await Scrypt.kdf(password, 'bad params'), new TypeError('params must be an object (received string)'));
    });

    test('rejects on bad logN', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 'bad' }), new RangeError('parameter logN must be an integer; received bad'));
    });

    test('rejects on zero logN', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 0 }), new RangeError('parameter logN must be between 1 and 30; received 0'));
    });

    test('rejects on non-integer logN', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12.12 }), new RangeError('parameter logN must be an integer; received 12.12'));
    });

    test('rejects on non-integer r', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  r: 8.8 }), new RangeError('parameter r must be a positive integer; received 8.8'));
    });

    test('rejects on non-integer p', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  p: 1.1 }), new RangeError('parameter p must be a positive integer; received 1.1'));
    });

    test('rejects on 0 r', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  r: 0 }), new RangeError('parameter r must be a positive integer; received 0'));
    });

    test('rejects on 0 p', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  p: 0 }), new RangeError('parameter p must be a positive integer; received 0'));
    });

    test('rejects on out-of-range r', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  r: 2**30 }), new RangeError('parameters p*r must be <= 2^30-1'));
    });

    test('rejects on out-of-range p', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12,  p: 2**30 }), new RangeError('parameters p*r must be <= 2^30-1'));
    });

    test('rejects on EVP PBE memory limit exceeded', function() {
        assert.rejects(async () => await Scrypt.kdf(password, { logN: 12, r: 2 ** 20 }), new Error('Invalid scrypt params: error:030000AC:digital envelope routines::memory limit exceeded'));
    });
});

describe('Verify errors', function() {
    test('rejects on bad passphrase type', function() {
        assert.rejects(async () => await Scrypt.verify(await Scrypt.kdf(password, { logN: 12 }), null), new TypeError('passphrase must be a string, TypedArray, or Buffer (received null)'));
    });

    test('rejects on bad key type', function() {
        assert.rejects(async () => await Scrypt.verify(null, 'passwd'), new TypeError('key must be a Uint8Array/Buffer (received null)'));
    });

    test('rejects on bad key', function() {
        assert.rejects(async () => await Scrypt.verify(Buffer.from('key', 'base64'), 'passwd'), new RangeError('invalid key'));
    });

    test('fails to verify on checksum failure', async function() {
        const key = await Scrypt.kdf(password, { logN: 12 });
        key[7] = 11; // patch logN to new value
        assert.deepEqual(Scrypt.viewParams(key), { logN: 11, r: 8, p: 1 });
        assert.equal(await Scrypt.verify(key, password), false);
    });
});

describe('ViewParams errors', function() { // note Scrypt.viewParams is not async
    test('throws on null key', function() {
        assert.throws(() => Scrypt.viewParams(null), new TypeError('key must be a Uint8Array/Buffer (received null)'));
    });

    test('throws on numeric key', function() {
        assert.throws(() => Scrypt.viewParams(99), new TypeError('key must be a Uint8Array/Buffer (received number)'));
    });

    test('throws on invalid key', function() {
        assert.throws(() => Scrypt.viewParams(Buffer.from('bad key', 'base64')), new RangeError('invalid key'));
    });
});
