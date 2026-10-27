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

// Test derivePublicKeyFromPrivate
console.log('\n--- Key Derivation Tests ---\n');

test('derivePublicKeyFromPrivate returns correct public key', () => {
  // Extract private key hex from PEM using the same ASN.1 parsing as sign()
  const pemLines = pemKeys.privateKey.split('\n');
  const derB64 = pemLines.filter(l => !l.startsWith('-----')).join('');
  const der = Buffer.from(derB64, 'base64');

  let pos = 0;
  if (der[pos++] !== 0x30) throw new Error('Invalid DER');
  let len = der[pos++];
  if (len & 0x80) pos += (len & 0x7f);
  if (der[pos++] !== 0x02) throw new Error('Invalid DER');
  const verLen = der[pos++];
  pos += verLen;
  if (der[pos++] !== 0x04) throw new Error('Invalid DER');
  const privLen = der[pos++];
  const privKeyHex = der.slice(pos, pos + privLen).toString('hex');

  const derivedPub = smPolyfill.derivePublicKeyFromPrivate(privKeyHex);
  assert(typeof derivedPub === 'string', 'Should return a string');
  assert(derivedPub.length === 130, 'Public key should be 65 bytes (130 hex chars)');
  assert(derivedPub.startsWith('04'), 'Public key should start with 04 prefix');

  // Cross-verify: sign with hex private key (polyfill path), verify with derived public key
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = Buffer.from('derive key test');
    const sig = smPolyfill.sign(data, privKeyHex, 'sm3');
    const verified = smPolyfill.verify(data, sig, derivedPub, 'sm3');
    assert.strictEqual(verified, true, 'Signature with derived public key should verify');
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

// Test polyfill path (hex private key, force polyfill)
console.log('\n--- Polyfill Path Tests (hex key, forced polyfill) ---\n');

test('SM2 sign/verify with hex private key (polyfill path)', () => {
  // Extract private key hex from PEM
  const pemLines = pemKeys.privateKey.split('\n');
  const derB64 = pemLines.filter(l => !l.startsWith('-----')).join('');
  const der = Buffer.from(derB64, 'base64');

  let pos = 0;
  if (der[pos++] !== 0x30) throw new Error('Invalid DER');
  let len = der[pos++];
  if (len & 0x80) pos += (len & 0x7f);
  if (der[pos++] !== 0x02) throw new Error('Invalid DER');
  const verLen = der[pos++];
  pos += verLen;
  if (der[pos++] !== 0x04) throw new Error('Invalid DER');
  const privLen = der[pos++];
  const privKeyHex = der.slice(pos, pos + privLen).toString('hex');

  // Derive public key hex from PEM public key
  const pubPemLines = pemKeys.publicKey.split('\n');
  const pubDerB64 = pubPemLines.filter(l => !l.startsWith('-----')).join('');
  const pubDer = Buffer.from(pubDerB64, 'base64');

  let pubPos = 0;
  if (pubDer[pubPos++] !== 0x30) throw new Error('Invalid DER');
  let pubLen = pubDer[pubPos++];
  if (pubLen & 0x80) pubPos += (pubLen & 0x7f);
  if (pubDer[pubPos++] !== 0x30) throw new Error('Invalid DER');
  const algoLen = pubDer[pubPos++];
  pubPos += algoLen;
  if (pubDer[pubPos++] !== 0x03) throw new Error('Invalid DER');
  const bitLen = pubDer[pubPos++];
  pubPos++;
  const pubKeyHex = pubDer.slice(pubPos, pubPos + bitLen - 1).toString('hex');

  // Force polyfill path
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = Buffer.from('Hello hex key!');
    const sig = smPolyfill.sign(data, privKeyHex, 'sm3');
    assert(Buffer.isBuffer(sig), 'Signature should be a Buffer');
    assert(sig.length > 0, 'Signature should not be empty');

    const verified = smPolyfill.verify(data, sig, pubKeyHex, 'sm3');
    assert.strictEqual(verified, true, 'Hex key signature should verify');

    // Verify wrong data fails
    const wrongData = Buffer.from('Wrong data');
    const wrongVerified = smPolyfill.verify(wrongData, sig, pubKeyHex, 'sm3');
    assert.strictEqual(wrongVerified, false, 'Should not verify with wrong data (hex key)');
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

test('SM2 polyfill path with string data', () => {
  // Extract private key hex from PEM
  const pemLines = pemKeys.privateKey.split('\n');
  const derB64 = pemLines.filter(l => !l.startsWith('-----')).join('');
  const der = Buffer.from(derB64, 'base64');

  let pos = 0;
  if (der[pos++] !== 0x30) throw new Error('Invalid DER');
  let len = der[pos++];
  if (len & 0x80) pos += (len & 0x7f);
  if (der[pos++] !== 0x02) throw new Error('Invalid DER');
  const verLen = der[pos++];
  pos += verLen;
  if (der[pos++] !== 0x04) throw new Error('Invalid DER');
  const privLen = der[pos++];
  const privKeyHex = der.slice(pos, pos + privLen).toString('hex');

  // Derive public key
  const pubKeyHex = smPolyfill.derivePublicKeyFromPrivate(privKeyHex);

  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = 'String data with hex key';
    const sig = smPolyfill.sign(data, privKeyHex, 'sm3');
    const verified = smPolyfill.verify(data, sig, pubKeyHex, 'sm3');
    assert.strictEqual(verified, true, 'Should verify string data with hex key (polyfill)');
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

// Test binary payloads and key input forms on the polyfill path
console.log('\n--- Binary Payload / Key Input Tests (polyfill path) ---\n');

const privKeyObject = crypto.createPrivateKey(pemKeys.privateKey);
const pubKeyObject = crypto.createPublicKey(pemKeys.publicKey);
const pkcs8Pem = privKeyObject.export({ type: 'pkcs8', format: 'pem' });

test('polyfill signs raw bytes, not a UTF-8 re-encoding', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const reencoded = Buffer.from(data.toString('utf8'), 'utf8');

    assert(!data.equals(reencoded), 'payload must not survive a UTF-8 round-trip');

    const sig = smPolyfill.sign(data, privKeyObject, 'sm3');
    assert.strictEqual(
      smPolyfill.verify(data, sig, pubKeyObject, 'sm3'),
      true,
      'signature should verify against the original bytes'
    );
    assert.strictEqual(
      smPolyfill.verify(reencoded, sig, pubKeyObject, 'sm3'),
      false,
      'signature must not verify against the UTF-8 re-encoding of the payload'
    );
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

test('polyfill path accepts PKCS#8 PEM private keys', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    assert(pkcs8Pem.includes('BEGIN PRIVATE KEY'), 'expected a PKCS#8 PEM');
    const data = Buffer.from('pkcs8 key test');
    const sig = smPolyfill.sign(data, pkcs8Pem, 'sm3');
    assert.strictEqual(smPolyfill.verify(data, sig, pubKeyObject, 'sm3'), true);
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

test('polyfill path accepts KeyObject keys', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = Buffer.from('key object test');
    const sig = smPolyfill.sign(data, privKeyObject, 'sm3');
    assert.strictEqual(smPolyfill.verify(data, sig, pubKeyObject, 'sm3'), true);
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

test('polyfill path rejects unusable private key input clearly', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    assert.throws(() => {
      smPolyfill.sign(Buffer.from('x'), {}, 'sm3');
    }, /Invalid private key/);
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
});

test('polyfill and native paths produce interchangeable signatures', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  if (!origCheck) {
    console.log('    (native SM2 unavailable here, cross-path check skipped)');
    return;
  }

  const data = Buffer.from('cross path interop');
  const sigNative = crypto.sign('sm3', data, privKeyObject);

  smPolyfill._setNativeSM2Support(false);
  let sigPoly;
  try {
    sigPoly = smPolyfill.sign(data, pemKeys.privateKey, 'sm3');
    assert.strictEqual(
      smPolyfill.verify(data, sigNative, pemKeys.publicKey, 'sm3'),
      true,
      'polyfill must verify a signature made by the native path'
    );
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }

  assert.strictEqual(
    smPolyfill.verify(data, sigPoly, pemKeys.publicKey, 'sm3'),
    true,
    'native path must verify a signature made by the polyfill'
  );
});

test('explicit GM/T user ID round-trips and is distinct from the default', () => {
  const origCheck = smPolyfill.checkNativeSM2Support();
  smPolyfill._setNativeSM2Support(false);
  try {
    const data = Buffer.from('user id test');
    const gmId = { userId: '1234567812345678' };
    const sig = smPolyfill.sign(data, privKeyObject, 'sm3', gmId);

    assert.strictEqual(smPolyfill.verify(data, sig, pubKeyObject, 'sm3', gmId), true,
      'signature should verify with the same user ID');
    assert.strictEqual(smPolyfill.verify(data, sig, pubKeyObject, 'sm3'), false,
      'signature must not verify under the default user ID');
  } finally {
    smPolyfill._setNativeSM2Support(origCheck);
  }
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
