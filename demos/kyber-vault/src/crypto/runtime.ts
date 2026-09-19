export const CRYPTO_IMPLEMENTATION = Object.freeze({
  library: '@noble/post-quantum',
  version: __NOBLE_POST_QUANTUM_VERSION__,
  integrity: __NOBLE_POST_QUANTUM_INTEGRITY__,
  backend: 'Pure JavaScript ML-KEM; browser Web Crypto for HKDF, AES-GCM, and SHA-256',
});

export interface CryptographicRuntime {
  getRandomValues?: unknown;
  subtle?: unknown;
}

export function assertCryptographicRuntime(
  runtime: CryptographicRuntime | undefined = globalThis.crypto,
): void {
  if (!runtime || typeof runtime.getRandomValues !== 'function' || !runtime.subtle) {
    throw new Error(
      'kyber-vault requires browser Web Crypto with crypto.getRandomValues and crypto.subtle',
    );
  }
}
