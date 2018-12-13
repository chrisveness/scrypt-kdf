/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Tests for scrypt key derivation function.                                   (c) C.Veness 2018  */
/*                                                                                   MIT Licence  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

const expect = require('chai').expect; // BDD/TDD assertion library

const Scrypt = require('../scrypt.js');

const password = 'my secret password';
const key0salt = 'c2NyeXB0AAwAAAAIAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA08wOZXFAec6Si7mP1SzrmK6Pvpx2zfUEXXAuM68S4DAnUER44bh+BxsnxMC75Jgs';


describe('Scrypt tests', function() {

    describe('Hash & verify', function() {
        it('with just logN param', async function() {
            const key = await Scrypt.kdf(password, { logN: 12 });
            expect(Scrypt.viewParams(key)).to.deep.equal({ logN: 12, r: 8, p: 1 });
            expect(await Scrypt.verify(key, password)).to.be.true;
        });

        it('with logN, r, p params', async function() {
            const key = await Scrypt.kdf(password, { logN: 12, r: 9, p: 2 });
            expect(Scrypt.viewParams(key)).to.deep.equal({ logN: 12, r: 9, p: 2 });
            expect(await Scrypt.verify(key, password)).to.be.true;
        });

        it('with params as strings', async function() {
            const key = await Scrypt.kdf(password, { logN: '12', r: '8', p: '1' });
            expect(Scrypt.viewParams(key)).to.deep.equal({ logN: 12, r: 8, p: 1 });
            expect(await Scrypt.verify(key, password)).to.be.true;
        });

        it('fails to verify with bad passphrase', async function() {
            const key = await Scrypt.kdf(password, { logN: 12 });
            expect(await Scrypt.verify(key, 'wrong password')).to.be.false;
        });
    });

    describe('Verify previous key', function() {
        it('verifies null-salt key', async function() {
            expect(await Scrypt.verify(key0salt, password)).to.be.true;
        });

        it('fails to verify null-salt key with bad passphrase', async function() {
            expect(await Scrypt.verify(key0salt, 'wrong password')).to.be.false;
        });
    });

    describe('TypedArray/Buffer passphrase', function() {
        it('Uint8Array', async function() {
            const pwTypedArray = new Uint8Array([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
            const key = await Scrypt.kdf(pwTypedArray, { logN: 12 });
            expect(Scrypt.viewParams(key)).to.deep.equal({ logN: 12, r: 8, p: 1 });
            expect(await Scrypt.verify(key, pwTypedArray)).to.be.true;
        });

        it('Buffer', async function() {
            const pwBuffer = Buffer.from([ 99, 98, 97, 96, 95, 94, 94, 92, 91 ]);
            const key = await Scrypt.kdf(pwBuffer, { logN: 12 });
            expect(Scrypt.viewParams(key)).to.deep.equal({ logN: 12, r: 8, p: 1 });
            expect(await Scrypt.verify(key, pwBuffer)).to.be.true;
        });
    });

    describe('Pick params', function() {
        it('Picks params for 100ms', async function() {
            const params = await Scrypt.pickParams(0.1, 1024*1024*1024, 0.5);
            expect(params).to.have.all.keys('logN', 'r', 'p');
            expect(params.logN).to.be.within(8, 20);
            expect(params.r).to.equal(8);
            expect(params.p).to.equal(1);
        });

        it('Picks params with default maxmem/maxmemfrac', async function() {
            const params = await Scrypt.pickParams(0.1);
            expect(params).to.have.all.keys('logN', 'r', 'p');
            expect(params.logN).to.be.within(8, 20);
            expect(params.r).to.equal(8);
            expect(params.p).to.equal(1);
        });

        it('Picks params with 0 maxmem', async function() {
            const params = await Scrypt.pickParams(0.1, 0);
            expect(params.logN).to.be.within(8, 20);
        });

        it('Picks params with 0 maxmemfrac', async function() {
            const params = await Scrypt.pickParams(0.1, 0, 0);
            expect(params.logN).to.be.within(8, 20);
        });

        it('Picks params setting N based on memory limit', async function() {
            const params = await Scrypt.pickParams(1, 1024, 0.1);
            expect(params.logN).to.be.within(8, 20);
            expect(params.p).to.be.above(1);
        });
    });

    describe('Error checking', function() {

        describe('kdf errors', function() {
            it('throws on numeric passphrase', () => Scrypt.kdf(99)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Passphrase must be a string, TypedArray, or Buffer')));
            it('throws on no params', () => Scrypt.kdf(password)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Params must be an object')));
            it('throws on bad params', () => Scrypt.kdf(password, null)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Params must be an object')));
            it('throws on bad params', () => Scrypt.kdf(password, false)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Params must be an object')));
            it('throws on bad params', () => Scrypt.kdf(password, 99)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Params must be an object')));
            it('throws on bad params', () => Scrypt.kdf(password, 'bad params')
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Params must be an object')));
            it('throws on bad logN', () => Scrypt.kdf(password, { logN: 'bad' })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter logN must be an integer; received bad')));
            it('throws on zero logN', () => Scrypt.kdf(password, { logN: 0 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter logN must be between 1 and 30; received 0')));
            it('throws on non-integer logN', () => Scrypt.kdf(password, { logN: 12.12 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter logN must be an integer; received 12.12')));
            it('throws on non-integer r', () => Scrypt.kdf(password, { logN: 12,  r: 8.8 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter r must be a positive integer; received 8.8')));
            it('throws on non-integer p', () => Scrypt.kdf(password, { logN: 12,  p: 1.1 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter p must be a positive integer; received 1.1')));
            it('throws on 0 r', () => Scrypt.kdf(password, { logN: 12,  r: 0 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter r must be a positive integer; received 0')));
            it('throws on 0 p', () => Scrypt.kdf(password, { logN: 12,  p: 0 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameter p must be a positive integer; received 0')));
            it('throws on out-of-range r', () => Scrypt.kdf(password, { logN: 12,  r: 2**30 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameters p*r must be <= 2^30-1')));
            it('throws on out-of-range p', () => Scrypt.kdf(password, { logN: 12,  p: 2**30 })
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Parameters p*r must be <= 2^30-1')));
        });

        describe('verify errors', function() {
            it('throws on bad passphrase type', async () => Scrypt.verify(await Scrypt.kdf(password, { logN: 12 }), null)
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Passphrase must be a string, TypedArray, or Buffer')));
            it('throws on bad key type', () => Scrypt.verify(null, 'passwd')
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Key must be a string')));
            it('throws on bad key', () => Scrypt.verify('key', 'passwd')
                .then(() => { throw new Error('Test should fail'); })
                .catch(error => expect(error.message).to.equal('Invalid key')));
            it('fails to verify on checksum failure', async () => {
                const keyBuff = Buffer.from(await Scrypt.kdf(password, { logN: 12 }), 'base64');
                keyBuff[7] = 11; // patch logN to new value
                const keybis = keyBuff.toString('base64');
                expect(Scrypt.viewParams(keybis)).to.deep.equal({ logN: 11, r: 8, p: 1 });
                expect(await Scrypt.verify(keybis, password)).to.be.false;
            });
        });

        describe('viewParams errors', function() { // note Scrypt.viewParams is not async
            it('throws on null key', () => expect(() => Scrypt.viewParams(null)).to.throw(TypeError, 'Key must be a string'));
            it('throws on numeric key', () => expect(() => Scrypt.viewParams(99)).to.throw(TypeError, 'Key must be a string'));
            it('throws on invalid key', () => expect(() => Scrypt.viewParams('bad key')).to.throw(RangeError, 'Invalid key'));
        });

    });

});
