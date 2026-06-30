# sm-polyfill

[![NPM Version](https://img.shields.io/npm/v/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)
[![Node.js Version](https://img.shields.io/node/v/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/zxdong262/sm-polyfill/blob/master/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zxdong262/sm-polyfill/test.yml?branch=master)](https://github.com/zxdong262/sm-polyfill/actions)
[![npm downloads](https://img.shields.io/npm/dm/sm-polyfill.svg)](https://www.npmjs.com/package/sm-polyfill)

**[English](./README.md)** | **[中文](./README_CN.md)**

国密 SM2/SM3/SM4 Node.js polyfill。在原生 OpenSSL 不支持国密算法时，通过 [sm-crypto-v2](https://www.npmjs.com/package/sm-crypto-v2) 提供 SM2 签名/验签能力。

## 背景

Node.js 16（OpenSSL 1.1.1）对国密算法的支持**不完整**：
- ✅ SM2 ECDH 密钥交换
- ✅ SM3 哈希
- ✅ SM4 加密
- ❌ SM2 签名/验签（需要 OpenSSL 3.0+）

Node.js 18+（OpenSSL 3.0+）**完整支持**国密算法。

本 polyfill 在原生支持不可用时，通过纯 JavaScript 实现的 `sm-crypto-v2` 回退方案，使 SM2 签名/验签在 Node.js 16 上也能正常工作。

## 安装

```bash
npm install sm-polyfill
```

## 使用方法

### 基本签名/验签

```javascript
const smPolyfill = require('sm-polyfill');

// 检查是否需要 polyfill
if (smPolyfill.needsPolyfill()) {
  console.log('使用 SM2 polyfill（Node.js 16 或更早版本）');
} else {
  console.log('使用原生 SM2（Node.js 18+）');
}

// 签名
const data = Buffer.from('Hello SM2!');
const privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\n...';
const signature = smPolyfill.sign(data, privateKey, 'sm3');

// 验签
const publicKey = 'ssh-sm2 AAAA...';
const verified = smPolyfill.verify(data, signature, publicKey, 'sm3');
console.log('验签结果:', verified);
```

### PEM 密钥格式

`sign` 和 `verify` 同时支持 PEM 和 OpenSSH 两种密钥格式：

```javascript
const smPolyfill = require('sm-polyfill');

// 生成密钥对（PEM 格式）
const keys = smPolyfill.generateKeyPair();
// keys.privateKey => SEC1 PEM (-----BEGIN EC PRIVATE KEY-----)
// keys.publicKey  => SPKI PEM (-----BEGIN PUBLIC KEY-----)

// 使用 PEM 私钥签名
const data = Buffer.from('Hello PEM!');
const sig = smPolyfill.sign(data, keys.privateKey, 'sm3');

// 使用 PEM 公钥验签
const ok = smPolyfill.verify(data, sig, keys.publicKey, 'sm3');
console.log('验签结果:', ok); // true
```

### SM3 哈希

```javascript
const hash = smPolyfill.sm3('abc');
console.log(hash.toString('hex'));
// 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

### SM4 加解密

```javascript
const crypto = require('crypto');
const key = crypto.randomBytes(16);
const iv = crypto.randomBytes(16);

// 加密
const cipher = smPolyfill.createSM4Cipher('sm4-ctr', key, iv);
const encrypted = Buffer.concat([cipher.update('Hello SM4!'), cipher.final()]);

// 解密
const decipher = smPolyfill.createSM4Decipher('sm4-ctr', key, iv);
const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
```

### 密钥生成

```javascript
const keys = smPolyfill.generateKeyPair();
console.log(keys.privateKey); // PEM 格式（SEC1）
console.log(keys.publicKey);  // PEM 格式（SPKI）
```

## API

### `sign(data, privateKey, hashAlgo)`

使用 SM2 和 SM3 哈希对数据签名。

- `data`：Buffer 或 string - 待签名数据
- `privateKey`：string 或 Buffer - **PEM**（SEC1）或 **OpenSSH** 格式私钥
- `hashAlgo`：string - 必须为 `'sm3'`
- 返回：Buffer - DER 格式签名

### `verify(data, signature, publicKey, hashAlgo)`

使用 SM3 哈希验证 SM2 签名。

- `data`：Buffer 或 string - 原始数据
- `signature`：Buffer - DER 格式签名
- `publicKey`：string 或 Buffer - **PEM**（SPKI）、**OpenSSH** 或 **hex** 格式公钥
- `hashAlgo`：string - 必须为 `'sm3'`
- 返回：boolean - 签名有效返回 true

### `sm3(data)`

计算 SM3 哈希值。

- `data`：Buffer 或 string - 待哈希数据
- 返回：Buffer - 32 字节哈希值

### `createSM4Cipher(algorithm, key, iv)`

创建 SM4 加密器。

- `algorithm`：string - `'sm4-ctr'`、`'sm4-cbc'` 等
- `key`：Buffer - 16 字节密钥
- `iv`：Buffer - 初始化向量
- 返回：Cipher 对象

### `createSM4Decipher(algorithm, key, iv)`

创建 SM4 解密器。

- `algorithm`：string - `'sm4-ctr'`、`'sm4-cbc'` 等
- `key`：Buffer - 16 字节密钥
- `iv`：Buffer - 初始化向量
- 返回：Decipher 对象

### `generateKeyPair()`

生成 SM2 密钥对（PEM 格式）。

- 返回：`{ privateKey: string, publicKey: string }` - SEC1 私钥和 SPKI 公钥（PEM 格式）

### `needsPolyfill()`

检查是否需要 polyfill（原生 SM2 不可用时返回 true）。

- 返回：boolean

### `checkNativeSM2Support()`

检查原生 SM2 签名是否可用。

- 返回：boolean

### `isSmCryptoAvailable()`

检查 sm-crypto-v2 包是否可用。

- 返回：boolean

### `parseOpenSSHPrivateKey(privateKey)`

解析 OpenSSH 格式私钥，提取私钥标量。

- `privateKey`：string 或 Buffer - OpenSSH 格式私钥
- 返回：string - 私钥标量（hex 字符串）

### `parseOpenSSHPublicKey(publicKey)`

解析 OpenSSH 格式公钥，提取公钥坐标点。

- `publicKey`：string 或 Buffer - OpenSSH 格式公钥
- 返回：string - 公钥坐标点（含 0x04 前缀，hex 字符串）

### `signatureToDER(sigHex)`

将 sm-crypto-v2 签名格式转换为 DER。

- `sigHex`：string - hex 格式签名（r + s 拼接）
- 返回：Buffer - DER 编码签名

### `signatureFromDER(derSig)`

将 DER 签名转换为 sm-crypto-v2 格式。

- `derSig`：Buffer - DER 编码签名
- 返回：string - hex 格式签名（r + s 拼接）

## 工作原理

1. **检测**：库首先尝试签名并验证测试数据，检查原生 SM2 是否可用。

2. **原生路径**：如果原生 SM2 可用且密钥为 PEM/DER 格式，直接使用 Node.js 内置的 `crypto.sign()` 和 `crypto.verify()`。

3. **Polyfill 路径**：如果原生 SM2 不可用或密钥为 OpenSSH 格式：
   - 自动检测密钥格式（PEM 或 OpenSSH）
   - PEM 密钥：解析 ASN.1 DER 提取原始密钥数据（私钥用 SEC1，公钥用 SPKI）
   - OpenSSH 密钥：解析 OpenSSH 密钥格式提取原始密钥数据
   - 使用 `sm-crypto-v2` 执行签名/验签
   - 在 DER 和 sm-crypto-v2 签名格式之间进行转换

## 密钥格式支持

本 polyfill 支持多种密钥格式：

| 格式 | 私钥 | 公钥 |
|------|------|------|
| **PEM**（SEC1/SPKI） | `-----BEGIN EC PRIVATE KEY-----` | `-----BEGIN PUBLIC KEY-----` |
| **OpenSSH** | `-----BEGIN OPENSSH PRIVATE KEY-----` | `ssh-sm2 AAAA...` |
| **Hex** | — | 原始 hex 字符串 |

## 环境要求

- Node.js >= 14.0.0
- `sm-crypto-v2` 包（自动安装）

## 许可证

[MIT](./LICENSE)
