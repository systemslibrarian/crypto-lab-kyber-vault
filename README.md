# kyber-vault

## 1. What It Is

This repository hosts a browser demo for ML-KEM (CRYSTALS-Kyber), including ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The demo walks through key generation, encapsulation, and decapsulation, and also includes a hybrid path using HKDF-SHA256 and AES-256-GCM. ML-KEM solves the key-establishment problem by allowing two parties to derive a shared secret over an untrusted channel. The security model is post-quantum asymmetric cryptography (KEM), with symmetric authenticated encryption used for payload protection in the hybrid flow.

## 2. When to Use It

- Use ML-KEM when you need post-quantum key establishment for new systems, because it is standardized for that specific role.
- Use the hybrid ML-KEM + AES-256-GCM path when you need to actually encrypt data after key establishment, because it demonstrates the full KEM-to-cipher pipeline.
- Use this demo when comparing ML-KEM-512/768/1024 trade-offs, because it exposes parameter selection, artifact sizes, and benchmark behavior.
- Do not use this repository as production cryptographic infrastructure, because it is an educational browser demo and not a hardened deployment.

## 3. Live Demo

Live demo: [https://systemslibrarian.github.io/crypto-lab-kyber-vault/](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)

You can run step-by-step KeyGen/Encaps/Decaps operations, inspect key and ciphertext artifacts, and view measured timings. The interface includes controls for parameter selection (ML-KEM-512, ML-KEM-768, ML-KEM-1024), benchmark iterations, and lattice/NTT educational panels.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kyber-vault.git
cd crypto-lab-kyber-vault/demos/kyber-vault
npm install
npm run dev
```

No environment variables are required for local development.

## 5. Part of the Crypto-Lab Suite

This project is part of the Crypto-Lab suite at https://systemslibrarian.github.io/crypto-lab/.

## 6. License

Released under the [MIT License](./LICENSE).