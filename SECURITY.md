# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

Only the latest 1.x release receives fixes. Please upgrade before reporting an
issue that may already be patched.

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:

<https://github.com/zxdong262/sm-polyfill/security/advisories/new>

That form creates a private advisory visible only to you and the maintainer, and
gives us a place to discuss, fix, and publish the advisory with a CVE if needed.

If you cannot use that form, open a public issue that says only that you have a
security report and how to reach you — no details, no proof of concept, no key
material.

### What to include

- Affected version(s) and Node.js version (`node -v`)
- A minimal reproduction: input, expected result, actual result
- Impact — e.g. signature accepted that should be rejected, key material leaked
  into an error message or log, memory exhaustion on malformed input
- Whether the issue also reproduces on Node.js 18+ (native OpenSSL 3 path) or
  only on the polyfill path

Never send real private keys. Generate a throwaway key pair with
`smPolyfill.generateKeyPair()` and use that.

## Scope

In scope:

- `sign()` / `verify()` accepting a signature it should reject, or rejecting a
  valid one
- Key parsing (`parseOpenSSHPrivateKey`, `parseOpenSSHPublicKey`, PEM/DER
  handling) — crashes, incorrect extraction, acceptance of malformed input
- Signature format conversion (`signatureToDER`, `signatureFromDER`) producing
  malleable or non-canonical output
- Secret leakage: private key bytes appearing in thrown errors, logs, or
  `util.inspect` output
- Denial of service from untrusted input (unbounded allocation, pathological
  parsing)

Out of scope:

- Timing side channels in the pure-JS implementation. `sm-crypto-v2` is not
  constant-time by design; the polyfill exists for compatibility with Node.js 16,
  not for side-channel resistance. Report those upstream to
  [sm-crypto-v2](https://www.npmjs.com/package/sm-crypto-v2).
- Vulnerabilities in Node.js itself or in OpenSSL. Report them to the respective
  projects.
- Using this library to sign or verify data you do not trust the key source for.

## Disclosure

We aim to acknowledge a report within a few days. Please give us a reasonable
window to ship a fix before publishing details; we will credit you in the
advisory unless you prefer otherwise.
