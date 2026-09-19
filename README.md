# crypto-lab-kyber-vault

## What It Is

This repository hosts a browser demo of final FIPS 203 ML-KEM, the NIST
standard derived from CRYSTALS-Kyber. It runs ML-KEM-512, ML-KEM-768, and
ML-KEM-1024 through key generation, encapsulation, and decapsulation. A
teaching-only hybrid path derives a variant-bound AES-256-GCM key with
HKDF-SHA256. ML-KEM establishes a key; it is not message encryption or peer
authentication.

## Exhibits

1. **Real ML-KEM stepper** — runs KeyGen, Encaps, and Decaps, displays the exact
   artifact sizes, and proves byte-for-byte that both parties obtained the same
   32-byte secret while only the ciphertext crossed the wire.
2. **Hybrid ML-KEM + AES-256-GCM** — turns the KEM output into a contextualized
   AES key and demonstrates authenticated decryption failure after tampering.
3. **Scalar LWE primer** — uses a deliberately tiny 4×4, q=17 system to contrast
   clean `b₀ = A·s` with published `b = A·s + e`. It is not ML-KEM's module
   lattice.
4. **Cyclic NTT primer** — animates an 8-point radix-2 butterfly and verifies
   cyclic multiplication in `Z_3329[X]/(X^8-1)`. It is not FIPS 203's incomplete
   negacyclic transform and base-case multiplication.
5. **Parameters, wire costs, and reproducible benchmarks** — compares complete
   construction-level key material, then records warm-up plus raw samples with
   median/p95 summaries, environment metadata, and JSON/CSV export.

## When to Use It

- Use the lab to learn or review FIPS 203 KEM flows, artifact sizes, parameter
  trade-offs, and migration concepts.
- Use its pinned vectors and source links as reproducible educational evidence.
- Do not use this repository as production cryptographic infrastructure. It is
  not independently audited, constant-time, peer-authenticated, or validated as
  a FIPS cryptographic module.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)**

## Standards and Deployment Evidence

Claims were last reviewed on **September 19, 2026**.

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) is the final ML-KEM
  standard and carries a November 17, 2025 planning note linking potential
  errata.
- [OpenSSH 9.9](https://www.openssh.com/releasenotes.html#9.9) added
  `mlkem768x25519-sha256`; OpenSSH 10.0 made it the default.
- [Apple PQ3](https://security.apple.com/blog/imessage-pq3/) and
  [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) document
  Kyber-1024-era constructions. They show the pre-standard lineage, not that
  those documented protocol versions use final FIPS 203 ML-KEM.

## Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kyber-vault
cd crypto-lab-kyber-vault/demos/kyber-vault
npm ci
npm run dev
```

Useful gates:

```bash
npm run audit
npm test
npm run build
npm run test:a11y
npm run sbom
```

## Assurance

- [Security policy](./SECURITY.md)
- [Threat model](./THREAT-MODEL.md)
- [Known limitations](./KNOWN-LIMITATIONS.md)
- Pinned NIST ACVP conformance vectors, strict CSP/off-origin browser tests,
  dependency audit and review, a generated CycloneDX SBOM, immutable Action
  SHAs, axe WCAG checks, responsive/forced-colors/reduced-motion journeys, and
  Lighthouse score budgets run in CI.

## Related Demos

- [crypto-lab-kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/)
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/)
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/)
- [crypto-lab-hqc-vault](https://systemslibrarian.github.io/crypto-lab-hqc-vault/)
- [crypto-lab-mceliece-gate](https://systemslibrarian.github.io/crypto-lab-mceliece-gate/)

## License

Released under the [MIT License](./LICENSE).

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*“So whether you eat or drink or whatever you do, do it all for the glory of
God.” — 1 Corinthians 10:31*
