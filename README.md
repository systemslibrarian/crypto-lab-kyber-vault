# crypto-lab-kyber-vault

## What It Is

This repository hosts a browser demo for ML-KEM (CRYSTALS-Kyber), including ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The demo walks through key generation, encapsulation, and decapsulation, and also includes a hybrid path using HKDF-SHA256 and AES-256-GCM. ML-KEM solves the key-establishment problem by allowing two parties to derive a shared secret over an untrusted channel. The security model is post-quantum asymmetric cryptography (KEM), with symmetric authenticated encryption used for payload protection in the hybrid flow.

## When to Use It

- Use ML-KEM when you need post-quantum key establishment for new systems, because it is standardized for that specific role.
- Use the hybrid ML-KEM + AES-256-GCM path when you need to actually encrypt data after key establishment, because it demonstrates the full KEM-to-cipher pipeline.
- Use this demo when comparing ML-KEM-512/768/1024 trade-offs, because it exposes parameter selection, artifact sizes, and benchmark behavior.
- Do not use this repository as production cryptographic infrastructure, because it is an educational browser demo and not a hardened deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)**

You can run step-by-step KeyGen/Encaps/Decaps operations, inspect key and ciphertext artifacts, and view measured timings. The interface includes controls for parameter selection (ML-KEM-512, ML-KEM-768, ML-KEM-1024), benchmark iterations, and lattice/NTT educational panels.

## What Can Go Wrong

- **Implementation timing leaks** — secret-dependent division (KyberSlash) has leaked ML-KEM key bits on some targets; the decapsulation path must be constant-time.
- **FO-transform handling** — the implicit-rejection path of the Fujisaki-Okamoto transform must run in constant time, or decapsulation-failure behavior becomes an oracle.
- **Randomness reuse** — reusing the randomness in encapsulation breaks the IND-CCA guarantee; each encapsulation needs fresh entropy.
- **Parameter-set confusion** — mixing ML-KEM-512/768/1024 keys and ciphertexts yields silent failures or weaker-than-intended security.
- **Using the raw shared secret directly** — the KEM output should be run through a KDF before use; the hybrid path here shows the correct KEM-to-AEAD pipeline.

## Real-World Usage

- Standardized as **FIPS 203 (ML-KEM)** by NIST in 2024.
- Deployed in **TLS 1.3** as the hybrid **X25519MLKEM768** group by Chrome, Cloudflare, and others.
- Used in **Signal's PQXDH** and in **OpenSSH** hybrid key exchange.
- Available in **liboqs / Open Quantum Safe** and **BoringSSL** for experimentation and production hybrids.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kyber-vault
cd crypto-lab-kyber-vault/demos/kyber-vault
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/) — a timing side-channel against ML-KEM implementations.
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — X25519 + ML-KEM-768 hybrid wire protocol.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — ML-KEM inside the TLS 1.3 handshake.
- [crypto-lab-hqc-vault](https://systemslibrarian.github.io/crypto-lab-hqc-vault/) — a code-based post-quantum KEM for contrast.
- [crypto-lab-mceliece-gate](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/) — Classic McEliece, the conservative code-based KEM.

## License

Released under the [MIT License](./LICENSE).

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
