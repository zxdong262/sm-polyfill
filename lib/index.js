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

// Polyfill globalThis.crypto for Node.js 16 and earlier
// Node.js 16 has crypto.webcrypto but globalThis.crypto may be undefined
// when running from a file (it's only available in eval/repl context)
if (typeof globalThis !== 'undefined' && !globalThis.crypto) {
  if (crypto.webcrypto) {
    globalThis.crypto = crypto.webcrypto;
  }
}

// Polyfill globalThis.crypto.getRandomValues for Node.js 16
// Node.js 16 has globalThis.crypto but getRandomValues may be missing
if (typeof globalThis !== 'undefined' && globalThis.crypto && !globalThis.crypto.getRandomValues) {
  if (crypto.webcrypto && crypto.webcrypto.getRandomValues) {
    globalThis.crypto.getRandomValues = crypto.webcrypto.getRandomValues.bind(crypto.webcrypto);
  }
}

// Force synchronous initialization of sm-crypto-v2's RNG
// This must be done before sm-crypto-v2 is loaded
if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
  // Create a sync wrapper that sm-crypto-v2 can use
  const _origGetRandomValues = globalThis.crypto.getRandomValues;
  globalThis.crypto.getRandomValues = function(array) {
    // If webcrypto.getRandomValues is async, use crypto.randomBytes instead
    if (crypto.randomBytes) {
      const bytes = crypto.randomBytes(array.length);
      array.set(bytes);
      return array;
    }
    return _origGetRandomValues.call(this, array);
  };
}

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
 * Override the cached native SM2 support flag. Intended for tests only:
 * sign()/verify() call the module-local check, so assigning to the exported
 * property does not redirect them.
 * 
 * @param {boolean|null} value - true/false to force, null to re-probe
 */
function setNativeSM2Support(value) {
  nativeSM2Supported = value === null ? null : !!value;
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
let rngInitialized = false;

function getSM2() {
  if (sm2Module) return sm2Module;
  try {
    sm2Module = require('sm-crypto-v2').sm2;
    // Initialize RNG pool synchronously using Node.js crypto
    // This avoids the async initialization race condition
    if (!rngInitialized) {
      try {
        // Pre-warm the pool by calling the internal randomBytes function
        // which will trigger pool initialization
        const cryptoModule = require('crypto');
        if (cryptoModule.webcrypto && cryptoModule.webcrypto.getRandomValues) {
          // Ensure globalThis.crypto.getRandomValues is polyfilled
          if (!globalThis.crypto.getRandomValues) {
            globalThis.crypto.getRandomValues = cryptoModule.webcrypto.getRandomValues.bind(cryptoModule.webcrypto);
          }
        }
        rngInitialized = true;
      } catch {
        // Ignore errors, sm-crypto-v2 will handle it
      }
    }
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
 * Derive SM2 public key from private key using Node.js ECDH
 * This works on Node.js 16 even though SM2 signing doesn't
 * @param {string} privateKeyHex - Private key as hex string (64 chars)
 * @returns {string} Public key as hex string (130 chars with 04 prefix)
 */
function derivePublicKeyFromPrivate(privateKeyHex) {
  const ecdh = crypto.createECDH('SM2');
  // privateKeyHex is the raw scalar d
  ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
  // getPublicKey returns uncompressed point (04 + x + y) by default
  return ecdh.getPublicKey('hex', 'uncompressed');
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
 * Minimal DER TLV reader
 * 
 * @param {Buffer} buf
 * @param {number} pos - Offset of the tag byte
 * @returns {{tag: number, start: number, end: number, next: number}}
 */
function readTLV(buf, pos) {
  if (pos + 2 > buf.length) {
    throw new Error('Unexpected end of DER data');
  }
  
  const tag = buf[pos];
  let len = buf[pos + 1];
  let p = pos + 2;
  
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > buf.length) {
      throw new Error('Unsupported DER length encoding');
    }
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | buf[p + i];
    }
    p += n;
  }
  
  if (p + len > buf.length) {
    throw new Error('DER length exceeds data');
  }
  
  return { tag, start: p, end: p + len, next: p + len };
}

/**
 * Extract the SM2 private scalar (d) from a DER-encoded EC private key
 * 
 * Handles both SEC1/RFC 5915 ("BEGIN EC PRIVATE KEY") and PKCS#8
 * ("BEGIN PRIVATE KEY", which wraps a SEC1 structure).
 * 
 * @param {Buffer} der
 * @param {number} [depth]
 * @returns {Buffer} Private scalar
 */
function privateScalarFromDER(der, depth) {
  depth = depth || 0;
  if (depth > 2) {
    throw new Error('Invalid private key structure');
  }
  
  const seq = readTLV(der, 0);
  if (seq.tag !== 0x30) {
    throw new Error('Expected SEQUENCE');
  }
  
  const version = readTLV(der, seq.start);
  if (version.tag !== 0x02) {
    throw new Error('Expected version INTEGER');
  }
  
  const next = readTLV(der, version.next);
  
  if (next.tag === 0x04) {
    // SEC1: version, privateKey OCTET STRING, ...
    return der.slice(next.start, next.end);
  }
  
  if (next.tag === 0x30) {
    // PKCS#8: version, AlgorithmIdentifier SEQUENCE, privateKey OCTET STRING
    const octets = readTLV(der, next.next);
    if (octets.tag !== 0x04) {
      throw new Error('Expected privateKey OCTET STRING');
    }
    return privateScalarFromDER(der.slice(octets.start, octets.end), depth + 1);
  }
  
  throw new Error('Unexpected private key structure');
}

/**
 * Extract the uncompressed SM2 public point from a DER SubjectPublicKeyInfo
 * 
 * @param {Buffer} der
 * @returns {string} Public key point (0x04 + X + Y) as hex
 */
function publicPointFromSPKI(der) {
  const seq = readTLV(der, 0);
  if (seq.tag !== 0x30) {
    throw new Error('Expected SEQUENCE');
  }
  
  const algorithm = readTLV(der, seq.start);
  if (algorithm.tag !== 0x30) {
    throw new Error('Expected AlgorithmIdentifier');
  }
  
  const bitString = readTLV(der, algorithm.next);
  if (bitString.tag !== 0x03) {
    throw new Error('Expected BIT STRING');
  }
  
  // Skip the unused-bits octet, the rest is 0x04 + X + Y
  const point = der.slice(bitString.start + 1, bitString.end);
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error('Invalid SM2 public key point');
  }
  
  return point.toString('hex');
}

/**
 * @param {*} key
 * @returns {boolean} True for a crypto.KeyObject
 */
function isKeyObject(key) {
  return !!key && typeof key === 'object' && typeof key.export === 'function' &&
    (key.type === 'private' || key.type === 'public');
}

/**
 * Normalize a private scalar to 64 hex chars (32 bytes)
 * 
 * @param {string} hex
 * @returns {string}
 */
function normalizeScalarHex(hex) {
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Invalid private key: expected hex, PEM, OpenSSH key or KeyObject');
  }
  
  let s = hex.replace(/^0+/, '');
  if (s.length < 64) {
    s = s.padStart(64, '0');
  } else if (s.length > 64) {
    // Strip leading bytes of an over-long value
    s = s.slice(-64);
  }
  return s;
}

/**
 * Resolve any supported private key form to a 64-char hex scalar
 * 
 * @param {string|Buffer|import('crypto').KeyObject} privateKey
 * @returns {string}
 */
function resolvePrivateKeyHex(privateKey) {
  if (isKeyObject(privateKey)) {
    return privateScalarFromDER(
      privateKey.export({ type: 'pkcs8', format: 'der' })
    ).toString('hex');
  }
  
  const text = Buffer.isBuffer(privateKey) ? privateKey.toString('utf8') : String(privateKey);
  
  if (text.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    return parseOpenSSHPrivateKey(privateKey);
  }
  
  if (text.includes('-----BEGIN') && text.includes('PRIVATE KEY')) {
    try {
      const b64 = text
        .split('\n')
        .filter(l => !l.trim().startsWith('-----'))
        .join('');
      return privateScalarFromDER(Buffer.from(b64, 'base64')).toString('hex');
    } catch (e) {
      throw new Error(`Failed to parse PEM private key: ${e.message}`);
    }
  }
  
  // Already a hex scalar
  return Buffer.isBuffer(privateKey) ? privateKey.toString('hex') : text;
}

/**
 * Resolve any supported public key form to an uncompressed point (hex)
 * 
 * @param {string|Buffer|import('crypto').KeyObject} publicKey
 * @returns {string}
 */
function resolvePublicKeyHex(publicKey) {
  if (isKeyObject(publicKey)) {
    return publicPointFromSPKI(publicKey.export({ type: 'spki', format: 'der' }));
  }
  
  const text = Buffer.isBuffer(publicKey) ? publicKey.toString('utf8') : String(publicKey);
  
  if (text.includes('-----BEGIN') && text.includes('PUBLIC KEY')) {
    try {
      const b64 = text
        .split('\n')
        .filter(l => !l.trim().startsWith('-----'))
        .join('');
      return publicPointFromSPKI(Buffer.from(b64, 'base64'));
    } catch (e) {
      throw new Error(`Failed to parse PEM public key: ${e.message}`);
    }
  }
  
  if (text.includes('ssh-')) {
    return parseOpenSSHPublicKey(publicKey);
  }
  
  // Already a hex point
  return Buffer.isBuffer(publicKey) ? publicKey.toString('hex') : text;
}

/**
 * SM2 user ID (distinguishing identifier) used when computing the ZA prehash.
 * 
 * Node's native SM2 signing (via OpenSSL) uses an EMPTY user ID, so the
 * polyfill must use the same one for the two paths to produce interchangeable
 * signatures. This differs from the GM/T 0009 default "1234567812345678" that
 * some other libraries use - pass `{ userId }` to override.
 */
const DEFAULT_SM2_USER_ID = '';

/**
 * Resolve the user ID for a call, honouring an explicit override
 * 
 * @param {{userId?: string}} [options]
 * @returns {string}
 */
function resolveUserId(options) {
  if (options && options.userId !== undefined) {
    return options.userId;
  }
  return DEFAULT_SM2_USER_ID;
}

/**
 * Sign data using SM2 with SM3 hash
 * 
 * @param {Buffer|string} data - Data to sign
 * @param {string|Buffer} privateKey - Private key in OpenSSH/PEM format
 * @param {string} hashAlgo - Hash algorithm (must be 'sm3')
 * @param {{userId?: string}} [options] - `userId` overrides the SM2 user ID
 * @returns {Buffer} Signature in DER format
 */
function sign(data, privateKey, hashAlgo, options) {
  if (hashAlgo && hashAlgo !== 'sm3') {
    throw new Error(`Unsupported hash algorithm: ${hashAlgo}. SM2 only supports 'sm3'.`);
  }
  
  const userId = resolveUserId(options);
  // Native signing cannot be told which user ID to use, so a non-default ID
  // has to go through the polyfill
  const nativeUsable = checkNativeSM2Support() && userId === DEFAULT_SM2_USER_ID;
  
  // Check if native signing works with this key format
  if (nativeUsable) {
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
  const privateKeyHex = normalizeScalarHex(resolvePrivateKeyHex(privateKey));
  
  // Derive public key from private key using Node.js ECDH
  // This avoids the buggy getPublicKeyFromPrivateKey in sm-crypto-v2
  const publicKeyHex = derivePublicKeyFromPrivate(privateKeyHex);
  
  // Pass the payload through untouched. sm-crypto hashes raw bytes for
  // Buffer/Uint8Array input and treats strings as UTF-8 text, so converting a
  // Buffer with toString('utf8') here would replace any non-UTF-8 byte with
  // U+FFFD and sign different bytes than the caller supplied.
  //
  // Pass publicKey explicitly to avoid sm-crypto-v2's buggy getPublicKeyFromPrivateKey
  const sigHex = sm2.doSignature(data, privateKeyHex, {
    der: false,
    hash: true,
    publicKey: publicKeyHex,
    userId,
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
 * @param {{userId?: string}} [options] - `userId` overrides the SM2 user ID
 * @returns {boolean} True if signature is valid
 */
function verify(data, signature, publicKey, hashAlgo, options) {
  if (hashAlgo && hashAlgo !== 'sm3') {
    throw new Error(`Unsupported hash algorithm: ${hashAlgo}. SM2 only supports 'sm3'.`);
  }
  
  const userId = resolveUserId(options);
  const nativeUsable = checkNativeSM2Support() && userId === DEFAULT_SM2_USER_ID;
  
  // Check if native verification works with this key format
  if (nativeUsable) {
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
  const publicKeyHex = resolvePublicKeyHex(publicKey);
  const sigHex = signatureFromDER(signature);
  
  // Raw bytes in, raw bytes hashed - see the note in sign()
  return sm2.doVerifySignature(data, sigHex, publicKeyHex, {
    hash: true,
    userId,
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
  
  // Test hook: forces the polyfill path (see setNativeSM2Support)
  _setNativeSM2Support: setNativeSM2Support,
  
  // Key parsing utilities
  parseOpenSSHPrivateKey,
  parseOpenSSHPublicKey,
  
  // Key derivation
  derivePublicKeyFromPrivate,
  
  // Signature conversion utilities
  signatureToDER,
  signatureFromDER,
};
