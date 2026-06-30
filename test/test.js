'use strict';

/**
 * Tests for SM2/SM3/SM4 Polyfill
 */

const assert = require('assert');
const smPolyfill = require('../lib/index.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

console.log('=== SM Polyfill Tests ===\n');
console.log(`Node.js ${process.version}, OpenSSL ${process.versions.openssl}\n`);

// Check environment
console.log('Environment:');
console.log(`  Native SM2 support: ${smPolyfill.checkNativeSM2Support()}`);
console.log(`  Needs polyfill: ${smPolyfill.needsPolyfill()}`);
console.log(`  sm-crypto-v2 available: ${smPolyfill.isSmCryptoAvailable()}`);
console.log('');

// Test SM3
test('SM3 hash produces correct result', () => {
  const hash = smPolyfill.sm3('abc').toString('hex');
  assert.strictEqual(
    hash,
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    'SM3 hash of "abc" should match known test vector'
  );
});

// Test SM4
test('SM4-CTR cipher round-trip', () => {
  const crypto = require('crypto');
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const plaintext = Buffer.from('Hello SM4!');
  
  const cipher = smPolyfill.createSM4Cipher('sm4-ctr', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  
  const decipher = smPolyfill.createSM4Decipher('sm4-ctr', key, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  
  assert(decrypted.equals(plaintext), 'Decrypted text should match original');
});

// Generate test keys
console.log('\nGenerating SM2 test keys...');
let testKeys;
try {
  // Use ssh2's keygen if available, otherwise use native
  try {
    const keygen = require('../../../lib/keygen.js');
    const result = keygen.generateKeyPairSync('sm2', { comment: 'test' });
    testKeys = {
      privateKey: result.private,
      publicKey: result.public,
    };
    console.log('  Generated using ssh2 keygen (OpenSSH format)');
  } catch {
    testKeys = smPolyfill.generateKeyPair();
    console.log('  Generated using native crypto (PEM format)');
  }
} catch (err) {
  console.error(`  Failed to generate keys: ${err.message}`);
  console.log('\n=== Test Summary ===');
  console.log(`Total: ${passed + failed}, Passed: ${passed}, Failed: ${failed}`);
  process.exit(1);
}

// Test SM2 sign/verify
test('SM2 sign produces signature', () => {
  const data = Buffer.from('Hello SM2!');
  const sig = smPolyfill.sign(data, testKeys.privateKey, 'sm3');
  
  assert(Buffer.isBuffer(sig), 'Signature should be a Buffer');
  assert(sig.length > 0, 'Signature should not be empty');
});

test('SM2 verify succeeds with valid signature', () => {
  const data = Buffer.from('Hello SM2!');
  const sig = smPolyfill.sign(data, testKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(data, sig, testKeys.publicKey, 'sm3');
  
  assert.strictEqual(verified, true, 'Signature should verify');
});

test('SM2 verify fails with wrong data', () => {
  const data = Buffer.from('Hello SM2!');
  const wrongData = Buffer.from('Wrong data');
  const sig = smPolyfill.sign(data, testKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(wrongData, sig, testKeys.publicKey, 'sm3');
  
  assert.strictEqual(verified, false, 'Signature should not verify with wrong data');
});

test('SM2 sign/verify with string data', () => {
  const data = 'String data to sign';
  const sig = smPolyfill.sign(data, testKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(data, sig, testKeys.publicKey, 'sm3');
  
  assert.strictEqual(verified, true, 'Signature should verify with string data');
});

test('SM2 sign rejects non-sm3 hash', () => {
  const data = Buffer.from('test');
  assert.throws(() => {
    smPolyfill.sign(data, testKeys.privateKey, 'sha256');
  }, /Unsupported hash algorithm/);
});

// Test key parsing (only when keys are in the expected format)
const isOpenSSH = typeof testKeys.privateKey === 'string' && testKeys.privateKey.includes('-----BEGIN OPENSSH');
const isPEM = typeof testKeys.privateKey === 'string' && testKeys.privateKey.includes('-----BEGIN EC');

if (isOpenSSH) {
  test('Parse OpenSSH private key', () => {
    const d = smPolyfill.parseOpenSSHPrivateKey(testKeys.privateKey);
    assert(typeof d === 'string', 'Should return hex string');
    assert(d.length === 64, 'Private key scalar should be 32 bytes (64 hex chars)');
  });

  test('Parse OpenSSH public key', () => {
    const xy = smPolyfill.parseOpenSSHPublicKey(testKeys.publicKey);
    assert(typeof xy === 'string', 'Should return hex string');
    assert(xy.length === 130, 'Public key (with 0x04 prefix) should be 65 bytes (130 hex chars)');
    assert(xy.startsWith('04'), 'Public key should start with 04 prefix');
  });
} else {
  console.log('  SKIP: Parse OpenSSH private key (keys are PEM format)');
  console.log('  SKIP: Parse OpenSSH public key (keys are PEM format)');
}

// Test PEM key support
console.log('\n--- PEM Key Format Tests ---\n');

// Generate PEM keys explicitly for testing
const crypto = require('crypto');
const pemKeys = smPolyfill.generateKeyPair();

test('SM2 sign/verify with PEM keys', () => {
  const data = Buffer.from('Hello PEM!');
  const sig = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(data, sig, pemKeys.publicKey, 'sm3');
  assert.strictEqual(verified, true, 'Signature should verify with PEM keys');
});

test('SM2 verify fails with wrong data (PEM keys)', () => {
  const data = Buffer.from('Hello PEM!');
  const wrongData = Buffer.from('Wrong data');
  const sig = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(wrongData, sig, pemKeys.publicKey, 'sm3');
  assert.strictEqual(verified, false, 'Should not verify with wrong data (PEM keys)');
});

test('SM2 sign/verify with PEM keys and string data', () => {
  const data = 'String data with PEM keys';
  const sig = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(data, sig, pemKeys.publicKey, 'sm3');
  assert.strictEqual(verified, true, 'Should verify string data with PEM keys');
});

test('PEM sign/verify with sm3 hash algorithm explicit', () => {
  const data = Buffer.from('explicit hash algo test');
  const sig = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
  const verified = smPolyfill.verify(data, sig, pemKeys.publicKey, 'sm3');
  assert.strictEqual(verified, true, 'Should verify with explicit sm3 hash algo');
});

test('PEM sign produces valid signature', () => {
  const data = Buffer.from('test pem sign');
  const sig = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
  assert(Buffer.isBuffer(sig), 'Signature should be a Buffer');
  assert(sig.length > 0, 'Signature should not be empty');
});

// Test signature conversion
test('Signature DER conversion round-trip', () => {
  // Create a test signature (r + s concatenated)
  const crypto = require('crypto');
  const r = crypto.randomBytes(32).toString('hex');
  const s = crypto.randomBytes(32).toString('hex');
  const sigHex = r + s;
  
  const der = smPolyfill.signatureToDER(sigHex);
  const recovered = smPolyfill.signatureFromDER(der);
  
  assert.strictEqual(recovered, sigHex, 'Signature should round-trip through DER');
});

// Summary
console.log('\n=== Test Summary ===');
console.log(`Total: ${passed + failed}, Passed: ${passed}, Failed: ${failed}`);

if (failed > 0) {
  process.exit(1);
}
