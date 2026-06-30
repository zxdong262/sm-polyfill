'use strict';

/**
 * SM2/SM3/SM4 Polyfill for Node.js 16 and earlier
 * 
 * Node.js 16 (OpenSSL 1.1.1) has partial SM algorithm support:
 * - SM2 ECDH key exchange: Works
 * - SM3 hash: Works
 * - SM4 cipher: Works
 * - SM2 sign/verify: FAILS (requires OpenSSL 3.0+)
 * 
 * This polyfill provides SM2 signing/verification using the sm-crypto-v2
 * pure JavaScript implementation when native support is unavailable.
 * 
 * Usage:
 *   const smPolyfill = require('sm-polyfill');
 *   
 *   // Check if polyfill is needed
 *   if (smPolyfill.needsPolyfill()) {
 *     console.log('Using SM2 polyfill');
 *   }
 *   
 *   // Sign data
 *   const signature = smPolyfill.sign(data, privateKeyPEM, 'sm3');
 *   
 *   // Verify signature
 *   const verified = smPolyfill.verify(data, signature, publicKeyPEM, 'sm3');
 */

const crypto = require('crypto');

// Cache the native SM2 support check result
let nativeSM2Supported = null;

/**
 * Check if native SM2 signing works
 * @returns {boolean} True if native SM2 sign/verify works
 */
function checkNativeSM2Support() {
  if (nativeSM2Supported !== null) {
    return nativeSM2Supported;
  }
  
  try {
    // Try to generate SM2 keys and sign/verify
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'SM2',
    });
    const data = Buffer.from('sm2-polyfill-test');
    const sig = crypto.sign('sm3', data, privateKey);
    nativeSM2Supported = crypto.verify('sm3', data, publicKey, sig) === true;
  } catch {
    nativeSM2Supported = false;
  }
  
  return nativeSM2Supported;
}

/**
 * Check if the polyfill is needed (native SM2 doesn't work)
 * @returns {boolean} True if polyfill is needed
 */
function needsPolyfill() {
  return !checkNativeSM2Support();
}

/**
 * Check if sm-crypto-v2 is available
 * @returns {boolean} True if sm-crypto-v2 is installed
 */
function isSmCryptoAvailable() {
  try {
    require('sm-crypto-v2');
    return true;
  } catch {
    return false;
  }
}

// Lazy-load sm-crypto-v2
let sm2Module = null;
let sm3Module = null;

function getSM2() {
  if (sm2Module) return sm2Module;
  try {
    sm2Module = require('sm-crypto-v2').sm2;
    return sm2Module;
  } catch {
    throw new Error(
      'sm-crypto-v2 package is required for SM2 polyfill. ' +
      'Install it with: npm install sm-crypto-v2'
    );
  }
}

function getSM3() {
  if (sm3Module) return sm3Module;
  try {
    sm3Module = require('sm-crypto-v2').sm3;
    return sm3Module;
  } catch {
    throw new Error(
      'sm-crypto-v2 package is required for SM3 polyfill. ' +
      'Install it with: npm install sm-crypto-v2'
    );
  }
}

/**
 * Parse OpenSSH format private key to extract SM2 private key scalar (d)
 * 
 * OpenSSH private key format:
 * - fixed: "openssh-key-v1\0" (15 bytes, NOT length-prefixed)
 * - string: cipher name
 * - string: kdf name
 * - string: kdf options
 * - uint32: number of keys
 * - string: public key (key type + Q)
 * - string: private key section:
 *   - uint32: checkint1
 *   - uint32: checkint2
 *   - string: key type
 *   - string: Q (public key point)
 *   - string: d (private key scalar)
 *   - string: comment
 *   - padding
 * 
 * @param {string|Buffer} privateKeyPem - OpenSSH format private key
 * @returns {string} Private key scalar as hex string
 */
function parseOpenSSHPrivateKey(privateKeyPem) {
  const pemStr = typeof privateKeyPem === 'string' 
    ? privateKeyPem 
    : privateKeyPem.toString('utf8');
  
  // Extract base64 content from PEM
  const match = pemStr.match(/-----BEGIN OPENSSH PRIVATE KEY-----\s*([\s\S]*?)\s*-----END OPENSSH PRIVATE KEY-----/);
  if (!match) {
    throw new Error('Invalid OpenSSH private key format');
  }
  
  const base64Content = match[1].replace(/\s/g, '');
  const der = Buffer.from(base64Content, 'base64');
  
  let offset = 0;
  
  // Auth magic is fixed: "openssh-key-v1\0" (15 bytes)
  const AUTH_MAGIC = 'openssh-key-v1';
  const magic = der.slice(0, AUTH_MAGIC.length).toString();
  if (magic !== AUTH_MAGIC) {
    throw new Error('Invalid OpenSSH key format: wrong magic');
  }
  offset = AUTH_MAGIC.length + 1; // +1 for null terminator
  
  function readString() {
    if (offset + 4 > der.length) {
      throw new Error('Unexpected end of key data');
    }
    const len = der.readUInt32BE(offset);
    offset += 4;
    if (offset + len > der.length) {
      throw new Error('String length exceeds data');
    }
    const str = der.slice(offset, offset + len);
    offset += len;
    return str;
  }
  
  function readUInt32() {
    if (offset + 4 > der.length) {
      throw new Error('Unexpected end of key data');
    }
    const val = der.readUInt32BE(offset);
    offset += 4;
    return val;
  }
  
  // Parse OpenSSH format
  readString(); // cipher name ("none")
  readString(); // kdf name ("none")
  readString(); // kdf options (empty)
  
  const nkeys = readUInt32();
  if (nkeys !== 1) {
    throw new Error(`Expected 1 key, got ${nkeys}`);
  }
  
  readString(); // public key blob
  
  // Parse private key section
  const privKeyBlob = readString();
  let privOffset = 0;
  
  function privReadUInt32() {
    const val = privKeyBlob.readUInt32BE(privOffset);
    privOffset += 4;
    return val;
  }
  
  function privReadString() {
    const len = privKeyBlob.readUInt32BE(privOffset);
    privOffset += 4;
    const str = privKeyBlob.slice(privOffset, privOffset + len);
    privOffset += len;
    return str;
  }
  
  const check1 = privReadUInt32();
  const check2 = privReadUInt32();
  
  if (check1 !== check2) {
    throw new Error('Private key check integers do not match');
  }
  
  const keyType = privReadString().toString('utf8');
  if (keyType !== 'ssh-sm2') {
    throw new Error(`Expected key type 'ssh-sm2', got '${keyType}'`);
  }
  
  privReadString(); // Q (public key point) - skip
  
  let d = privReadString(); // d (private key scalar)
  
  // Remove leading zero byte if present (padding for positive integers)
  if (d[0] === 0) {
    d = d.slice(1);
  }
  
  // Pad to 32 bytes if needed
  if (d.length < 32) {
    const padded = Buffer.alloc(32);
    d.copy(padded, 32 - d.length);
    d = padded;
  }
  
  return d.toString('hex');
}

/**
 * Parse OpenSSH format public key to extract SM2 public key point (Q)
 * 
 * OpenSSH public key format:
 * - string: key type ("ssh-sm2")
 * - string: Q (uncompressed point: 0x04 + X(32) + Y(32))
 * 
 * @param {string|Buffer} publicKeyPem - OpenSSH format public key
 * @returns {string} Public key point (with 0x04 prefix) as hex string
 */
function parseOpenSSHPublicKey(publicKeyPem) {
  const pemStr = typeof publicKeyPem === 'string'
    ? publicKeyPem
    : publicKeyPem.toString('utf8');
  
  // Try OpenSSH format first (---- BEGIN SSH2 PUBLIC KEY ----)
  let base64Content;
  
  const opensshMatch = pemStr.match(/ssh-sm2\s+([A-Za-z0-9+/=]+)/);
  if (opensshMatch) {
    base64Content = opensshMatch[1];
  } else {
    // Try PEM format
    const pemMatch = pemStr.match(/-----BEGIN.*?-----\s*([\s\S]*?)\s*-----END.*?-----/);
    if (pemMatch) {
      base64Content = pemMatch[1].replace(/\s/g, '');
    } else {
      // Assume it's already base64
      base64Content = pemStr.replace(/\s/g, '');
    }
  }
  
  const der = Buffer.from(base64Content, 'base64');
  let offset = 0;
  
  function readString() {
    if (offset + 4 > der.length) {
      throw new Error('Unexpected end of key data');
    }
    const len = der.readUInt32BE(offset);
    offset += 4;
    if (offset + len > der.length) {
      throw new Error('String length exceeds data');
    }
    const str = der.slice(offset, offset + len);
    offset += len;
    return str;
  }
  
  const keyType = readString().toString('utf8');
  if (keyType !== 'ssh-sm2') {
    throw new Error(`Expected key type 'ssh-sm2', got '${keyType}'`);
  }
  
  const Q = readString(); // Public key point (0x04 + X + Y)
  
  // sm-crypto-v2 expects the full uncompressed point with 0x04 prefix
  // Q is 65 bytes: 0x04 + X(32) + Y(32)
  if (Q.length !== 65 || Q[0] !== 0x04) {
    throw new Error('Invalid SM2 public key point format');
  }
  
  // Return with 0x04 prefix (sm-crypto-v2 format)
  return Q.toString('hex');
}

/**
 * Convert sm-crypto-v2 signature (r, s as concatenated hex) to DER format
 * 
 * sm-crypto-v2 returns signature as r(32 bytes) + s(32 bytes) = 64 bytes
 * SSH expects DER-encoded ASN.1 SEQUENCE { INTEGER r, INTEGER s }
 * 
 * @param {string} sigHex - Signature as hex string (64 bytes)
 * @returns {Buffer} DER-encoded signature
 */
function signatureToDER(sigHex) {
  const r = Buffer.from(sigHex.slice(0, 64), 'hex');
  const s = Buffer.from(sigHex.slice(64, 128), 'hex');
  
  // Convert to DER format
  function encodeInteger(buf) {
    // Remove leading zeros but keep one if high bit is set
    let start = 0;
    while (start < buf.length - 1 && buf[start] === 0) {
      start++;
    }
    
    // If high bit is set, prepend a zero byte
    const needsPadding = buf[start] & 0x80;
    const len = buf.length - start + (needsPadding ? 1 : 0);
    
    const result = Buffer.alloc(2 + len);
    result[0] = 0x02; // INTEGER tag
    result[1] = len;
    
    if (needsPadding) {
      result[2] = 0;
      buf.copy(result, 3, start);
    } else {
      buf.copy(result, 2, start);
    }
    
    return result;
  }
  
  const rDer = encodeInteger(r);
  const sDer = encodeInteger(s);
  
  const seqLen = rDer.length + sDer.length;
  const result = Buffer.alloc(2 + seqLen);
  result[0] = 0x30; // SEQUENCE tag
  result[1] = seqLen;
  rDer.copy(result, 2);
  sDer.copy(result, 2 + rDer.length);
  
  return result;
}

/**
 * Convert DER signature to sm-crypto format (r + s concatenated)
 * 
 * @param {Buffer} derSig - DER-encoded signature
 * @returns {string} Signature as hex string (r + s)
 */
function signatureFromDER(derSig) {
  if (derSig[0] !== 0x30) {
    throw new Error('Invalid DER signature: expected SEQUENCE');
  }
  
  let offset = 2;
  
  function decodeInteger() {
    if (derSig[offset] !== 0x02) {
      throw new Error('Invalid DER signature: expected INTEGER');
    }
    offset++;
    const len = derSig[offset];
    offset++;
    
    let intBuf = derSig.slice(offset, offset + len);
    offset += len;
    
    // Remove leading zero if present (padding for positive integers)
    if (intBuf[0] === 0) {
      intBuf = intBuf.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (intBuf.length < 32) {
      const padded = Buffer.alloc(32);
      intBuf.copy(padded, 32 - intBuf.length);
      intBuf = padded;
    }
    
    return intBuf;
  }
  
  const r = decodeInteger();
  const s = decodeInteger();
  
  return Buffer.concat([r, s]).toString('hex');
}

/**
 * Sign data using SM2 with SM3 hash
 * 
 * @param {Buffer|string} data - Data to sign
 * @param {string|Buffer} privateKey - Private key in OpenSSH/PEM format
 * @param {string} hashAlgo - Hash algorithm (must be 'sm3')
 * @returns {Buffer} Signature in DER format
 */
function sign(data, privateKey, hashAlgo) {
  if (hashAlgo && hashAlgo !== 'sm3') {
    throw new Error(`Unsupported hash algorithm: ${hashAlgo}. SM2 only supports 'sm3'.`);
  }
  
  // Check if native signing works with this key format
  if (checkNativeSM2Support()) {
    try {
      // Try native crypto (works with PEM/DER format keys)
      const keyObj = crypto.createPrivateKey(privateKey);
      return crypto.sign('sm3', data, keyObj);
    } catch {
      // Fall through to polyfill for OpenSSH format keys
    }
  }
  
  // Use sm-crypto polyfill
  const sm2 = getSM2();
  let privateKeyHex;
  
  // Detect key format and parse accordingly
  const keyStr = typeof privateKey === 'string' ? privateKey : privateKey.toString();
  if (keyStr.includes('-----BEGIN') && keyStr.includes('PRIVATE KEY')) {
    // PEM format - extract raw private key by parsing ASN.1 DER
    try {
      // Extract DER from PEM
      const pemLines = keyStr.split('\n');
      const derB64 = pemLines
        .filter(l => !l.startsWith('-----'))
        .join('');
      const der = Buffer.from(derB64, 'base64');
      
      // Parse ASN.1 DER to find the private key bytes
      // EC private key structure: SEQUENCE { version, privateKey OCTET STRING, ... }
      // The private key is typically 32 bytes for SM2
      let pos = 0;
      
      // Skip outer SEQUENCE tag (0x30) and length
      if (der[pos++] !== 0x30) throw new Error('Invalid DER');
      let len = der[pos++];
      if (len & 0x80) {
        const lenBytes = len & 0x7f;
        pos += lenBytes;
      }
      
      // Skip version INTEGER
      if (der[pos++] !== 0x02) throw new Error('Invalid DER');
      const verLen = der[pos++];
      pos += verLen;
      
      // Read privateKey OCTET STRING (0x04)
      if (der[pos++] !== 0x04) throw new Error('Invalid DER');
      const privLen = der[pos++];
      privateKeyHex = der.slice(pos, pos + privLen).toString('hex');
    } catch (e) {
      throw new Error(`Failed to parse PEM private key: ${e.message}`);
    }
  } else {
    // OpenSSH format
    privateKeyHex = parseOpenSSHPrivateKey(privateKey);
  }
  
  const dataStr = typeof data === 'string' ? data : data.toString('utf8');
  
  const sigHex = sm2.doSignature(dataStr, privateKeyHex, {
    der: false,
    hash: true,
  });
  
  return signatureToDER(sigHex);
}

/**
 * Verify SM2 signature with SM3 hash
 * 
 * @param {Buffer|string} data - Original data
 * @param {Buffer} signature - Signature in DER format
 * @param {string|Buffer} publicKey - Public key in OpenSSH/PEM format
 * @param {string} hashAlgo - Hash algorithm (must be 'sm3')
 * @returns {boolean} True if signature is valid
 */
function verify(data, signature, publicKey, hashAlgo) {
  if (hashAlgo && hashAlgo !== 'sm3') {
    throw new Error(`Unsupported hash algorithm: ${hashAlgo}. SM2 only supports 'sm3'.`);
  }
  
  // Check if native verification works with this key format
  if (checkNativeSM2Support()) {
    try {
      // Try native crypto (works with PEM/DER format keys)
      const keyObj = crypto.createPublicKey(publicKey);
      return crypto.verify('sm3', data, keyObj, signature);
    } catch {
      // Fall through to polyfill for OpenSSH format keys
    }
  }
  
  // Use sm-crypto polyfill
  const sm2 = getSM2();
  let publicKeyHex;
  
  // Detect key format and parse accordingly
  const keyStr = typeof publicKey === 'string' ? publicKey : publicKey.toString();
  if (keyStr.includes('-----BEGIN') && keyStr.includes('PUBLIC KEY')) {
    // PEM format - extract raw public key by parsing ASN.1 DER
    try {
      // Extract DER from PEM
      const pemLines = keyStr.split('\n');
      const derB64 = pemLines
        .filter(l => !l.startsWith('-----'))
        .join('');
      const der = Buffer.from(derB64, 'base64');
      
      // SubjectPublicKeyInfo: SEQUENCE { algorithm, subjectPublicKey BIT STRING }
      // The public key is in the BIT STRING, typically starting with 0x04 (uncompressed)
      // followed by x and y coordinates (32 bytes each for SM2)
      
      // Find the BIT STRING (tag 0x03) containing the public key
      // Skip the outer SEQUENCE and algorithm identifier
      let pos = 0;
      
      // Skip outer SEQUENCE
      if (der[pos++] !== 0x30) throw new Error('Invalid DER');
      let len = der[pos++];
      if (len & 0x80) pos += (len & 0x7f);
      
      // Skip algorithm SEQUENCE
      if (der[pos++] !== 0x30) throw new Error('Invalid DER');
      const algoLen = der[pos++];
      pos += algoLen;
      
      // Read BIT STRING containing public key
      if (der[pos++] !== 0x03) throw new Error('Invalid DER');
      const bitLen = der[pos++];
      // Skip the unused bits byte (usually 0x00)
      pos++;
      // The rest is the uncompressed public key (0x04 + x + y)
      publicKeyHex = der.slice(pos, pos + bitLen - 1).toString('hex');
    } catch (e) {
      throw new Error(`Failed to parse PEM public key: ${e.message}`);
    }
  } else if (keyStr.startsWith('ssh-') || keyStr.startsWith('ecdsa-sha2-')) {
    // OpenSSH public key format (base64 encoded)
    publicKeyHex = parseOpenSSHPublicKey(publicKey);
  } else {
    // Assume it's already a hex string or Buffer with raw key
    publicKeyHex = typeof publicKey === 'string' ? publicKey : publicKey.toString('hex');
  }
  
  const dataStr = typeof data === 'string' ? data : data.toString('utf8');
  const sigHex = signatureFromDER(signature);
  
  return sm2.doVerifySignature(dataStr, sigHex, publicKeyHex, {
    hash: true,
  });
}

/**
 * Generate SM2 key pair (using native crypto, which works on all versions)
 * 
 * @returns {{ privateKey: string, publicKey: string }} Key pair in OpenSSH format
 */
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'SM2',
  });
  
  // Export in a format we can use
  const privPem = privateKey.export({ type: 'sec1', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  
  return {
    privateKey: privPem,
    publicKey: pubPem,
  };
}

/**
 * SM3 hash function (works on all Node.js versions)
 * 
 * @param {Buffer|string} data - Data to hash
 * @returns {Buffer} 32-byte hash
 */
function sm3(data) {
  // Native SM3 works on all versions
  return crypto.createHash('sm3').update(data).digest();
}

/**
 * SM4 cipher (works on all Node.js versions)
 * 
 * @param {string} algorithm - 'sm4-ctr', 'sm4-cbc', etc.
 * @param {Buffer} key - 16-byte key
 * @param {Buffer} iv - Initialization vector
 * @returns {object} Cipher object
 */
function createSM4Cipher(algorithm, key, iv) {
  return crypto.createCipheriv(algorithm, key, iv);
}

/**
 * SM4 decipher (works on all Node.js versions)
 * 
 * @param {string} algorithm - 'sm4-ctr', 'sm4-cbc', etc.
 * @param {Buffer} key - 16-byte key
 * @param {Buffer} iv - Initialization vector
 * @returns {object} Decipher object
 */
function createSM4Decipher(algorithm, key, iv) {
  return crypto.createDecipheriv(algorithm, key, iv);
}

// Export the polyfill API
module.exports = {
  // Core functions
  sign,
  verify,
  generateKeyPair,
  
  // SM3/SM4 (just wrappers around native, which works)
  sm3,
  createSM4Cipher,
  createSM4Decipher,
  
  // Utility functions
  needsPolyfill,
  checkNativeSM2Support,
  isSmCryptoAvailable,
  
  // Key parsing utilities
  parseOpenSSHPrivateKey,
  parseOpenSSHPublicKey,
  
  // Signature conversion utilities
  signatureToDER,
  signatureFromDER,
};
