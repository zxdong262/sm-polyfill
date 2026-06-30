# sm-polyfill

[![NPM Version](https://img.shields.io/npm/v/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)
[![Node.js Version](https://img.shields.io/node/v/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/zxdong262/sm-polyfill/blob/master/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zxdong262/sm-polyfill/test.yml?branch=master)](https://github.com/zxdong262/sm-polyfill/actions)
[![npm downloads](https://img.shields.io/npm/dm/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)

**[English](./README.md)** | **[中文](./README_CN.md)**

SM2/SM3/SM4 polyfill for Node.js 16 and earlier. Provides SM2 signing/verification using [sm-crypto-v2](https://www.npmjs.com/package/sm-crypto-v2) when native OpenSSL support is unavailable.

## Background

Node.js 16 (OpenSSL 1.1.1) has **partial** SM algorithm support:
- ✅ SM2 ECDH key exchange
- ✅ SM3 hash
- ✅ SM4 cipher
- ❌ SM2 sign/verify (requires OpenSSL 3.0+)

Node.js 18+ (OpenSSL 3.0+) has **full** SM algorithm support.

This polyfill enables SM2 signing/verification on Node.js 16 by falling back to the pure JavaScript `sm-crypto-v2` implementation when native support is unavailable.

## Installation

```bash
npm install sm-polyfill
```

## Usage

### Basic Sign/Verify

```javascript
const smPolyfill = require('sm-polyfill');

// Check if polyfill is being used
if (smPolyfill.needsPolyfill()) {
  console.log('Using SM2 polyfill (Node.js 16 or earlier)');
} else {
  console.log('Using native SM2 (Node.js 18+)');
}

// Sign data
const data = Buffer.from('Hello SM2!');
const privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\n...';
const signature = smPolyfill.sign(data, privateKey, 'sm3');

// Verify signature
const publicKey = 'ssh-sm2 AAAA...';
const verified = smPolyfill.verify(data, signature, publicKey, 'sm3');
console.log('Verified:', verified);
```

### PEM Key Format

Both PEM and OpenSSH key formats are supported for `sign` and `verify`:

```javascript
const smPolyfill = require('sm-polyfill');

// Generate a key pair (PEM format)
const keys = smPolyfill.generateKeyPair();
// keys.privateKey => SEC1 PEM (-----BEGIN EC PRIVATE KEY-----)
// keys.publicKey  => SPKI PEM (-----BEGIN PUBLIC KEY-----)

// Sign with PEM private key
const data = Buffer.from('Hello PEM!');
const sig = smPolyfill.sign(data, keys.privateKey, 'sm3');

// Verify with PEM public key
const ok = smPolyfill.verify(data, sig, keys.publicKey, 'sm3');
console.log('Verified:', ok); // true
```

### SM3 Hash

```javascript
const hash = smPolyfill.sm3('abc');
console.log(hash.toString('hex'));
// 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

### SM4 Cipher

```javascript
const crypto = require('crypto');
const key = crypto.randomBytes(16);
const iv = crypto.randomBytes(16);

// Encrypt
const cipher = smPolyfill.createSM4Cipher('sm4-ctr', key, iv);
const encrypted = Buffer.concat([cipher.update('Hello SM4!'), cipher.final()]);

// Decrypt
const decipher = smPolyfill.createSM4Decipher('sm4-ctr', key, iv);
const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
```

### Key Generation

```javascript
const keys = smPolyfill.generateKeyPair();
console.log(keys.privateKey); // PEM format (SEC1)
console.log(keys.publicKey);  // PEM format (SPKI)
```

## API

### `sign(data, privateKey, hashAlgo)`

Sign data using SM2 with SM3 hash.

- `data`: Buffer or string - Data to sign
- `privateKey`: string or Buffer - Private key in **PEM** (SEC1) or **OpenSSH** format
- `hashAlgo`: string - Must be `'sm3'`
- Returns: Buffer - Signature in DER format

### `verify(data, signature, publicKey, hashAlgo)`

Verify SM2 signature with SM3 hash.

- `data`: Buffer or string - Original data
- `signature`: Buffer - Signature in DER format
- `publicKey`: string or Buffer - Public key in **PEM** (SPKI), **OpenSSH**, or **hex** format
- `hashAlgo`: string - Must be `'sm3'`
- Returns: boolean - True if signature is valid

### `sm3(data)`

Compute SM3 hash.

- `data`: Buffer or string - Data to hash
- Returns: Buffer - 32-byte hash

### `createSM4Cipher(algorithm, key, iv)`

Create SM4 cipher.

- `algorithm`: string - `'sm4-ctr'`, `'sm4-cbc'`, etc.
- `key`: Buffer - 16-byte key
- `iv`: Buffer - Initialization vector
- Returns: Cipher object

### `createSM4Decipher(algorithm, key, iv)`

Create SM4 decipher.

- `algorithm`: string - `'sm4-ctr'`, `'sm4-cbc'`, etc.
- `key`: Buffer - 16-byte key
- `iv`: Buffer - Initialization vector
- Returns: Decipher object

### `generateKeyPair()`

Generate an SM2 key pair in PEM format.

- Returns: `{ privateKey: string, publicKey: string }` - SEC1 private key and SPKI public key in PEM format

### `needsPolyfill()`

Check if the polyfill is needed (native SM2 doesn't work).

- Returns: boolean

### `checkNativeSM2Support()`

Check if native SM2 signing works.

- Returns: boolean

### `isSmCryptoAvailable()`

Check if sm-crypto-v2 package is available.

- Returns: boolean

### `parseOpenSSHPrivateKey(privateKey)`

Parse OpenSSH format private key and extract the private key scalar.

- `privateKey`: string or Buffer - OpenSSH format private key
- Returns: string - Private key scalar as hex string

### `parseOpenSSHPublicKey(publicKey)`

Parse OpenSSH format public key and extract the public key point.

- `publicKey`: string or Buffer - OpenSSH format public key
- Returns: string - Public key point (with 0x04 prefix) as hex string

### `signatureToDER(sigHex)`

Convert sm-crypto-v2 signature format to DER.

- `sigHex`: string - Signature as hex (r + s concatenated)
- Returns: Buffer - DER-encoded signature

### `signatureFromDER(derSig)`

Convert DER signature to sm-crypto-v2 format.

- `derSig`: Buffer - DER-encoded signature
- Returns: string - Signature as hex (r + s concatenated)

## How It Works

1. **Detection**: The library first checks if native SM2 signing works by attempting to sign and verify test data.

2. **Native Path**: If native SM2 works AND the key is in PEM/DER format, it uses Node.js's built-in `crypto.sign()` and `crypto.verify()`.

3. **Polyfill Path**: If native SM2 doesn't work OR the key is in OpenSSH format, it:
   - Detects the key format (PEM or OpenSSH) automatically
   - For PEM keys: parses ASN.1 DER to extract raw key material (SEC1 for private, SPKI for public)
   - For OpenSSH keys: parses the OpenSSH key format to extract raw key material
   - Uses `sm-crypto-v2` for the actual signing/verification
   - Converts between DER and sm-crypto-v2 signature formats

## Key Format Support

The polyfill supports multiple key formats:

| Format | Private Key | Public Key |
|--------|------------|------------|
| **PEM** (SEC1/SPKI) | `-----BEGIN EC PRIVATE KEY-----` | `-----BEGIN PUBLIC KEY-----` |
| **OpenSSH** | `-----BEGIN OPENSSH PRIVATE KEY-----` | `ssh-sm2 AAAA...` |
| **Hex** | — | Raw hex string |

## Requirements

- Node.js >= 14.0.0
- `sm-crypto-v2` package (installed automatically)

## License

[MIT](./LICENSE)
