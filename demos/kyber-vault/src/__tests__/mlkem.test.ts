import { describe, expect, it } from 'vitest';
import {
  type MLKEMVariant,
  ML_KEM_PARAMS,
  decapsulate,
  encapsulate,
  generateKeyPair,
} from '../crypto/mlkem';

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('ML-KEM wrappers', () => {
  it('pins the FIPS 203 algebra and compression parameters for every profile', () => {
    expect(ML_KEM_PARAMS['ml-kem-512']).toMatchObject({
      modulus: 3329,
      polynomialDegree: 256,
      moduleRank: 2,
      eta1: 3,
      eta2: 2,
      du: 10,
      dv: 4,
    });
    expect(ML_KEM_PARAMS['ml-kem-768']).toMatchObject({
      modulus: 3329,
      polynomialDegree: 256,
      moduleRank: 3,
      eta1: 2,
      eta2: 2,
      du: 10,
      dv: 4,
    });
    expect(ML_KEM_PARAMS['ml-kem-1024']).toMatchObject({
      modulus: 3329,
      polynomialDegree: 256,
      moduleRank: 4,
      eta1: 2,
      eta2: 2,
      du: 11,
      dv: 5,
    });
  });
  it('all variants round-trip and shared secret is 32 bytes', async () => {
    for (const variant of VARIANTS) {
      const bob = await generateKeyPair(variant);
      const alice = await encapsulate(bob.publicKey, variant);
      const bobSecret = await decapsulate(alice.ciphertext, bob.privateKey, variant);

      expect(toHex(bobSecret)).toBe(toHex(alice.sharedSecret));
      expect(alice.sharedSecret.length).toBe(32);
      expect(bobSecret.length).toBe(32);
    }
  });

  it('wrong private key yields a different shared secret via implicit rejection', async () => {
    const variant: MLKEMVariant = 'ml-kem-768';
    const bob = await generateKeyPair(variant);
    const mallory = await generateKeyPair(variant);
    const alice = await encapsulate(bob.publicKey, variant);

    const bobSecret = await decapsulate(alice.ciphertext, bob.privateKey, variant);
    const mallorySecret = await decapsulate(alice.ciphertext, mallory.privateKey, variant);

    expect(toHex(bobSecret)).not.toBe(toHex(mallorySecret));
  });

  it('corrupted ciphertext is implicitly rejected without an error oracle', async () => {
    for (const variant of VARIANTS) {
      const bob = await generateKeyPair(variant);
      const alice = await encapsulate(bob.publicKey, variant);
      const corrupted = alice.ciphertext.slice();
      corrupted[Math.floor(corrupted.length / 2)] ^= 1;

      const rejectedSecret = await decapsulate(corrupted, bob.privateKey, variant);

      expect(rejectedSecret).toHaveLength(ML_KEM_PARAMS[variant].sharedSecret);
      expect(toHex(rejectedSecret)).not.toBe(toHex(alice.sharedSecret));
    }
  });

  it('rejects malformed artifact lengths before invoking ML-KEM', async () => {
    for (const variant of VARIANTS) {
      const params = ML_KEM_PARAMS[variant];
      const bob = await generateKeyPair(variant);
      const alice = await encapsulate(bob.publicKey, variant);

      await expect(encapsulate(bob.publicKey.slice(1), variant)).rejects.toThrow(
        /public key length mismatch/,
      );
      await expect(
        decapsulate(alice.ciphertext.slice(1), bob.privateKey, variant),
      ).rejects.toThrow(/ciphertext length mismatch/);
      await expect(
        decapsulate(alice.ciphertext, bob.privateKey.slice(0, params.privateKey - 1), variant),
      ).rejects.toThrow(/private key length mismatch/);
    }
  });

  it('matches FIPS 203 parameter lengths for keys and ciphertext', async () => {
    for (const variant of VARIANTS) {
      const keyPair = await generateKeyPair(variant);
      const encapsResult = await encapsulate(keyPair.publicKey, variant);

      expect(keyPair.publicKey.length).toBe(ML_KEM_PARAMS[variant].publicKey);
      expect(keyPair.privateKey.length).toBe(ML_KEM_PARAMS[variant].privateKey);
      expect(encapsResult.ciphertext.length).toBe(ML_KEM_PARAMS[variant].ciphertext);
      expect(encapsResult.sharedSecret.length).toBe(ML_KEM_PARAMS[variant].sharedSecret);
    }
  });
});
