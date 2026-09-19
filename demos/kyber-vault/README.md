# kyber-vault demo

## 1. What It Is

`kyber-vault` is a browser demo of ML-KEM (CRYSTALS-Kyber), including ML-KEM-512, ML-KEM-768, and ML-KEM-1024 flows from key generation through encapsulation and decapsulation. It also demonstrates a hybrid construction using ML-KEM + HKDF-SHA256 + AES-256-GCM for authenticated message encryption. The core problem solved here is quantum-resistant key establishment so two parties can derive a shared secret over an untrusted network. This is post-quantum asymmetric cryptography (a KEM), with an additional symmetric authenticated-encryption layer in the hybrid path.

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
npm install
npm run dev
```

No environment variables are required for local development.

## 5. Part of the Crypto-Lab Suite

This demo is part of the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.
