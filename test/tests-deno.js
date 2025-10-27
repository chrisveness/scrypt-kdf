/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Tests for scrypt key derivation function using Deno.                                           */
/*                                                   © 2024-2025 Chris Veness / Movable Type Ltd  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import { assert, assertEquals, assertThrows, assertRejects } from 'jsr:@std/assert';

import { Buffer } from 'node:buffer';

import Scrypt from '../scrypt.js';

const password = 'my secret password';
const key0salt = 'c2NyeXB0AAwAAAAIAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA08wOZXFAec6Si7mP1SzrmK6Pvpx2zfUEXXAuM68S4DAnUER44bh+BxsnxMC75Jgs';


Deno.test('Hash & verify (base64)', async function(t) {

    await t.step('with just logN param, with verify key as Uint8Array', async function() {
        const key = await Scrypt.kdf(password, { logN: 12 });
        assertEquals(Scrypt.viewParams(key), { logN: 12, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(key, password), true);
    });

    await t.step('with logN, r, p params, with verify key as Uint8Array', async function() {
        const key = await Scrypt.kdf(password, { logN: 12, r: 9, p: 2 });
        assertEquals(Scrypt.viewParams(key), { logN: 12, r: 9, p: 2 });
        assertEquals(await Scrypt.verify(key, password), true);
    });

    await t.step('with kdf params & verify key as strings', async function() {
        const key = await Scrypt.kdf(password, { logN: '12', r: '8', p: '1' });
        assertEquals(Scrypt.viewParams(key.toBase64()), { logN: 12, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(key.toBase64(), password), true);
    });

    await t.step('fails to verify with bad passphrase', async function() {
        const key = await Scrypt.kdf(password, { logN: '12', r: '8', p: '1' });
        assertEquals(await Scrypt.verify(key.toBase64(), 'wrong password'), false);
    });
});

Deno.test('Verify previous key (base64)', async function(t) {
    await t.step('verifies null-salt key', async function() {
        assertEquals(await Scrypt.verify(Buffer.from(key0salt, 'base64'), password), true);
    });

    await t.step('fails to verify null-salt key with bad passphrase', async function() {
        assertEquals(await Scrypt.verify(Buffer.from(key0salt, 'base64'), 'wrong password'), false);
    });
});

Deno.test('Args as String/Uint8Array/Buffer', async function(t) {

    await t.step('String', async function() {
        const pwStr = String.fromCharCode(...[ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const key = await Scrypt.kdf(pwStr, { logN: 12 });
        assertEquals(Scrypt.viewParams(key.toBase64()), { logN: 12, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(key.toBase64(), pwStr), true);
    });

    await t.step('Uint8Array', async function() {
        const pwArr = new Uint8Array([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const keyArr = new Uint8Array(await Scrypt.kdf(pwArr, { logN: 12 }));
        assertEquals(Scrypt.viewParams(keyArr), { logN: 12, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(keyArr, pwArr), true);
    });

    await t.step('Node.js Buffer', async function() {
        const pwBuff = Buffer.from([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
        const key = await Scrypt.kdf(pwBuff, { logN: 12 });
        assertEquals(Scrypt.viewParams(key), { logN: 12, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(key, pwBuff), true);
    });
});

Deno.test('Pick params', async function(t) {
    await t.step('Picks params for 100ms', function() {
        const params = Scrypt.pickParams(0.1, 1024*1024*1024, 0.5);
        assertEquals(Object.keys(params), [ 'logN', 'r', 'p' ]);
        assert(params.logN >= 8 && params.logN <= 20);
        assertEquals(params.r, 8);
        assertEquals(params.p, 1);
    });

    await t.step('Picks params with default maxmem/maxmemfrac', function() {
        const params = Scrypt.pickParams(0.1);
        assertEquals(Object.keys(params), [ 'logN', 'r', 'p' ]);
        assert(params.logN >= 8 && params.logN <= 20);
        assertEquals(params.r, 8);
        assertEquals(params.p, 1);
    });

    await t.step('Picks params with 0 maxmem', function() {
        const params = Scrypt.pickParams(0.1, 0);
        assert(params.logN >= 8 && params.logN <= 20);
    });

    await t.step('Picks params with 0 maxmemfrac', function() {
        const params = Scrypt.pickParams(0.1, 0, 0);
        assert(params.logN >= 8 && params.logN <= 20);
    });

    await t.step('Picks params setting N based on memory limit', function() {
        const params = Scrypt.pickParams(1, 1024, 0.1);
        assert(params.logN >= 8 && params.logN <= 20);
        assert(params.p > 1);
    });
});

Deno.test('Kdf errors', async function(t) {
    await t.step('rejects on numeric passphrase', function() {
        assertRejects(async () => await Scrypt.kdf(99));
    });

    await t.step('rejects on no params', function() {
        assertRejects(async () => await Scrypt.kdf(password));
    });

    await t.step('rejects on bad params', function() {
        assertRejects(async () => await Scrypt.kdf(password, null));
    });

    await t.step('rejects on bad params', function() {
        assertRejects(async () => await Scrypt.kdf(password, false));
    });

    await t.step('rejects on bad params', function() {
        assertRejects(async () => await Scrypt.kdf(password, 99));
    });

    await t.step('rejects on bad params', function() {
        assertRejects(async () => await Scrypt.kdf(password, 'bad params'));
    });

    await t.step('rejects on bad logN', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 'bad' }));
    });

    await t.step('rejects on zero logN', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 0 }));
    });

    await t.step('rejects on non-integer logN', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12.12 }));
    });

    await t.step('rejects on non-integer r', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, r: 8.8 }));
    });

    await t.step('rejects on non-integer p', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, p: 1.1 }));
    });

    await t.step('rejects on 0 r', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, r: 0 }));
    });

    await t.step('rejects on 0 p', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, p: 0 }));
    });

    await t.step('rejects on out-of-range r', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, r: 2**30 }));
    });

    await t.step('rejects on out-of-range p', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, p: 2**30 }));
    });

    await t.step('rejects on EVP PBE memory limit exceeded', function() {
        assertRejects(async () => await Scrypt.kdf(password, { logN: 12, r: 2 ** 20 }));
    });
});

Deno.test('Verify errors', async function(t) {
    await t.step('rejects on bad passphrase type', function() {
        assertRejects(async () => await Scrypt.verify(await Scrypt.kdf(password, { logN: 12 }), null));
    });

    await t.step('rejects on bad key type', function() {
        assertRejects(async () => await Scrypt.verify(null, 'passwd'));
    });

    await t.step('rejects on bad key', function() {
        assertRejects(async () => await Scrypt.verify(Buffer.from('key', 'base64'), 'passwd'));
    });

    await t.step('fails to verify on checksum failure', async function() {
        const key = await Scrypt.kdf(password, { logN: 12 });
        key[7] = 11; // patch logN to new value
        assertEquals(Scrypt.viewParams(key), { logN: 11, r: 8, p: 1 });
        assertEquals(await Scrypt.verify(key, password), false);
    });
});

Deno.test('ViewParams errors', async function(t) { // note Scrypt.viewParams is not async
    await t.step('throws on null key', function() {
        assertThrows(() => Scrypt.viewParams(null));
    });

    await t.step('throws on numeric key', function() {
        assertThrows(() => Scrypt.viewParams(99));
    });

    await t.step('throws on invalid key', function() {
        assertThrows(() => Scrypt.viewParams(Buffer.from('bad key', 'base64')));
    });
});
