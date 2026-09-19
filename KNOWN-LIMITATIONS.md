# Known Limitations

Last reviewed: **September 19, 2026**

## Cryptographic implementation

- This is an educational browser demo, not production cryptographic
  infrastructure.
- It ships pure-JavaScript `@noble/post-quantum@0.7.1`. Upstream reports a
  self-audit at 0.6.1, not an independent audit; 0.7.1 contains later changes.
- JavaScript engines, JIT compilation, garbage collection, and browser
  scheduling do not provide a formal constant-time guarantee.
- NIST ACVP known-answer tests demonstrate selected conforming behavior. They do
  not make the library, browser, or demo a CMVP-validated or FIPS 140-validated
  module.
- Private keys and shared secrets remain in application state while the page is
  open. Selected upstream temporary buffers are wiped, but complete erasure of
  copies from a garbage-collected heap cannot be guaranteed.
- Security depends on the browser's `crypto.getRandomValues` and Web Crypto
  implementation. The app fails closed if those APIs are unavailable.

## Protocol composition

- The demo does not authenticate Bob's public key or Alice's identity. It is not
  a complete authenticated key-exchange protocol and is vulnerable to active
  key substitution if copied literally.
- The public-key fingerprint is informational; no trusted channel or PKI checks
  it.
- HKDF binds the selected ML-KEM variant into the AES key schedule, but the demo
  does not bind a full handshake transcript, identities, roles, or application
  context.
- The AES-GCM path demonstrates authenticated encryption for one in-memory
  message. It is not a record protocol and provides no replay handling,
  sequencing, rekeying, persistence, or multi-message nonce strategy.

## Browser and hosting

- GitHub Pages controls HTTP response headers. The meta CSP is strict for loaded
  content but cannot express `frame-ancestors`, sandboxing, or CSP reporting, so
  it is not equivalent to a complete header-delivered policy.
- A malicious browser extension, compromised browser/OS, same-origin script
  injection, or local memory observer can defeat the page's protections.
- The site requires modern browser support for modules, Web Crypto, X25519 for
  that comparison, CSS `color-mix`, and related platform features. X25519
  benchmarking is reported unavailable when the browser lacks it.

## Educational models and measurements

- The scalar LWE panel uses q=17, a 4×4 matrix, CBD η=2, and `Math.random`. It is
  a visualization, not ML-KEM or a security estimator.
- The NTT panel is an 8-point cyclic transform in
  `Z_3329[X]/(X^8-1)`. It is not FIPS 203's incomplete negacyclic transform.
- Browser benchmarks compare pure JavaScript ML-KEM with native Web Crypto
  X25519. Results depend on the device, JIT, power state, browser load, and timer
  precision and must not be treated as portable algorithm rankings.
- Wire-cost totals exclude framing, identifiers, certificates, signatures,
  record headers, and retransmissions.

## Standards freshness

NIST's FIPS 203 publication page carries a November 17, 2025 planning note for
an issue intended for a future update or revision. The app links the live notice;
its last claim review date is September 19, 2026. Standards, errata, browsers,
and upstream libraries can change after that date.
