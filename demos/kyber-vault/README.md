# kyber-vault demo

## 1. What It Is

`kyber-vault` is a browser demo of final FIPS 203 ML-KEM, the NIST standard derived from CRYSTALS-Kyber. It includes ML-KEM-512, ML-KEM-768, and ML-KEM-1024 flows from key generation through encapsulation and decapsulation. It also demonstrates a hybrid construction using ML-KEM + HKDF-SHA256 + AES-256-GCM for authenticated message encryption. The core problem solved here is quantum-resistant key establishment so two parties can derive a shared secret over an untrusted network. This is post-quantum asymmetric cryptography (a KEM), with an additional symmetric authenticated-encryption layer in the hybrid path.

## 2. When to Use It

- Use ML-KEM when designing new systems that need long-term confidentiality against harvest-now-decrypt-later threats, because it provides post-quantum key establishment.
- Use the hybrid ML-KEM + AES-256-GCM path when you need to exchange a message after deriving key material, because it shows a complete KEM-to-encryption workflow.
- Use ML-KEM-512/768/1024 selection in testing or architecture reviews, because different parameter sets let you evaluate size and performance trade-offs.
- Do not use this demo as production cryptographic infrastructure, because it is an educational browser implementation and not a hardened deployment target.

## 3. Live Demo

Live demo: [https://systemslibrarian.github.io/crypto-lab-kyber-vault/](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)

In the demo, you can step through KeyGen, Encaps, and Decaps, inspect artifacts and timings, and run a hybrid encrypt/decrypt flow. You can switch between ML-KEM-512, ML-KEM-768, and ML-KEM-1024, see decision guidance and exact FIPS 203 artifact sizes for each profile, generate illustrative LWE/NTT examples, and run benchmark iterations for ML-KEM and X25519 comparison. The interface explicitly treats NIST categories as comparison targets rather than exact classical or quantum bit-strength measurements.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kyber-vault.git
cd crypto-lab-kyber-vault/demos/kyber-vault
npm ci
npm run dev
```

No environment variables are required for local development.

The production page enforces a strict Content Security Policy, contains no
inline scripts or styles, and makes no third-party runtime requests. A
Playwright security gate fails on CSP violations, browser errors, or any
off-origin request.

The ML-KEM implementation is exactly pinned to `@noble/post-quantum@0.7.1`;
the production UI derives both that version and its npm integrity receipt from
`package-lock.json` at build time. ML-KEM runs as pure JavaScript, while
HKDF-SHA256, AES-256-GCM, SHA-256, and cryptographic randomness use browser Web
Crypto. The app fails closed if `crypto.getRandomValues` or `crypto.subtle` is
unavailable.

This runtime has important limitations: the upstream project reports a
self-audit at 0.6.1, not an independent audit; it makes no constant-time claim
for JavaScript execution; and a garbage-collected browser cannot guarantee
complete erasure of secret copies. The interface exposes these limits next to
the implementation details. Use a reviewed, supported, side-channel-hardened
implementation and an authenticated protocol for production systems.

## 5. Cryptographic Conformance Evidence

The test suite pins a compact subset of the NIST ACVP-Server FIPS 203 vectors
to commit `975de31eb83d87039ec88934fdc47d8c312b892d`. For ML-KEM-512,
ML-KEM-768, and ML-KEM-1024, it checks KeyGen, encapsulation, and
decapsulation outputs byte for byte, rejects NIST-invalid encapsulation and
decapsulation keys, rejects malformed artifact lengths, and exercises
implicit rejection after ciphertext corruption.

The selected vector IDs and original NIST file paths are preserved in
`test-vectors/nist-acvp-ml-kem.json`. These automated checks are reproducible
conformance evidence; they are not a claim that this educational application
or its JavaScript dependency has received a NIST CMVP validation certificate.

## 6. Source Freshness and Standards Status

Sources and claims were last reviewed on **September 19, 2026**.

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) is the authoritative publication page. Its November 17, 2025 planning note reports an issue that NIST intends to correct in a future update or revision and links the live errata spreadsheet.
- [OpenSSH 9.9 release notes](https://www.openssh.com/releasenotes.html#9.9) document `mlkem768x25519-sha256`, a hybrid of final FIPS 203 ML-KEM and X25519; OpenSSH 10.0 later made it the default.
- [Apple's PQ3 design](https://security.apple.com/blog/imessage-pq3/) specifies Kyber-1024, and the [Signal PQXDH specification](https://signal.org/docs/specifications/pqxdh/) gives CRYSTALS-KYBER-1024 as its concrete example. These are pre-standard Kyber-lineage examples, not evidence that those documented protocol versions use final FIPS 203 ML-KEM.

Final ML-KEM and pre-standard CRYSTALS-Kyber must not be treated as interchangeable. Algorithm details changed during standardization, so implementations must not assume byte-compatible keys, ciphertexts, or protocol encodings.

## 7. Part of the Crypto-Lab Suite

This demo is part of the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.
