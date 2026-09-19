import { describe, expect, it } from 'vitest';
import { assertCryptographicRuntime, CRYPTO_IMPLEMENTATION } from '../crypto/runtime';

describe('cryptographic runtime assurance', () => {
  it('reports the exact library release and npm artifact receipt injected from the lockfile', () => {
    expect(CRYPTO_IMPLEMENTATION.library).toBe('@noble/post-quantum');
    expect(CRYPTO_IMPLEMENTATION.version).toBe('0.7.1');
    expect(CRYPTO_IMPLEMENTATION.integrity).toBe(
      'sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==',
    );
  });

  it('fails closed unless both secure randomness and Web Crypto primitives are available', () => {
    expect(() => assertCryptographicRuntime({})).toThrow(/requires browser Web Crypto/);
    expect(() => assertCryptographicRuntime({ subtle: {} })).toThrow(/requires browser Web Crypto/);
    expect(() => assertCryptographicRuntime({ getRandomValues: () => undefined })).toThrow(
      /requires browser Web Crypto/,
    );
    expect(() =>
      assertCryptographicRuntime({ getRandomValues: () => undefined, subtle: {} }),
    ).not.toThrow();
  });
});
