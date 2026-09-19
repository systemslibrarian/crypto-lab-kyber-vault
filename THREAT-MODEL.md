# Threat Model

Last reviewed: **September 19, 2026**

## System and trust boundaries

`kyber-vault` is a static educational site. GitHub Actions installs locked npm
dependencies, tests and builds the Vite application, then publishes static files
to GitHub Pages. In the browser, ML-KEM runs in pure JavaScript through exactly
pinned `@noble/post-quantum`; HKDF-SHA256, AES-256-GCM, SHA-256, X25519, and
randomness use browser Web Crypto.

The important boundaries are:

1. source repository and pull-request review;
2. GitHub Actions, pinned third-party actions, and the npm supply chain;
3. GitHub Pages delivery and the user's browser;
4. JavaScript memory containing private keys and shared secrets; and
5. user-controlled plaintext and tampered demo ciphertexts.

No backend receives generated keys, messages, or benchmark data. The production
Content Security Policy uses `connect-src 'none'`, and browser tests fail on any
off-origin runtime request.

## Assets

- accuracy of FIPS 203 operations and educational claims;
- generated ML-KEM private keys and shared secrets while the page is open;
- user-entered demo plaintext;
- integrity of source, dependencies, CI, and published static assets; and
- reproducibility of conformance and benchmark evidence.

## Adversaries considered

- a network observer who can read or alter unauthenticated traffic before HTTPS;
- an active protocol attacker who substitutes a public key or tampers with a
  ciphertext;
- malicious user input rendered by the page;
- a compromised or vulnerable npm dependency or GitHub Action;
- a same-device attacker with script execution, browser-extension privileges,
  local timing access, or memory inspection; and
- accidental maintainer regressions in cryptography, claims, accessibility, or
  deployment configuration.

## Security goals and controls

| Goal | Controls |
| --- | --- |
| Correct ML-KEM behavior | Pinned NIST ACVP vectors for all profiles, invalid-key cases, malformed-length tests, and implicit-rejection tests |
| Prevent runtime exfiltration | Static hosting, strict CSP, `connect-src 'none'`, no third-party runtime requests, and browser regression tests |
| Protect hybrid ciphertext integrity | HKDF context binding and AES-256-GCM authentication, including a tamper-failure test |
| Make supply-chain changes reviewable | Exact ML-KEM pin, npm lockfile/integrity receipt, vulnerability audit, dependency review, SBOM artifact, Dependabot, and immutable Action SHAs |
| Prevent unsupported claims | Primary-source links, dated review status, visible errata, explicit Kyber/ML-KEM and toy/real boundaries |
| Preserve delivery quality | Type checking, unit/conformance tests, Playwright journeys, axe WCAG gates, responsive/forced-colors/reduced-motion checks, and Lighthouse budgets |

## Explicit non-goals

This repository does not provide peer authentication, certificate handling,
key persistence, secure deletion, a hardened constant-time runtime, FIPS 140
module validation, production availability, or a complete network protocol.
It does not defend against a compromised browser, extension, operating system,
GitHub account, or maintainer credential.

## Residual risks

- The pure-JavaScript ML-KEM implementation makes no constant-time claim.
- Garbage collection prevents guaranteed erasure of all secret copies.
- A meta-delivered CSP cannot set `frame-ancestors`; GitHub Pages does not let
  this repository configure arbitrary response headers.
- The demo does not authenticate public keys, so it is vulnerable to active key
  substitution if treated as a protocol.
- Browser CSPRNG, Web Crypto, JIT, and native code remain trusted dependencies.
- A green test suite is evidence, not a proof of implementation or protocol
  security.
