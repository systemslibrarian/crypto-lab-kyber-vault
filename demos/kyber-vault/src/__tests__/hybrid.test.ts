import { describe, expect, it } from 'vitest';
import { flipBase64Byte, hybridDecrypt, hybridEncrypt } from '../crypto/hybrid';
import { generateKeyPair, type MLKEMVariant } from '../crypto/mlkem';

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];

describe('Hybrid ML-KEM + AES-256-GCM flow', () => {
  it('round-trips encryption/decryption for all variants', async () => {
    for (const variant of VARIANTS) {
      const recipient = await generateKeyPair(variant);
      const message = `round-trip ${variant}`;
      const payload = await hybridEncrypt(message, recipient.publicKey, variant);
      const plaintext = await hybridDecrypt(payload, recipient.privateKey);
      expect(plaintext).toBe(message);
    }
  });

  it('preserves empty messages and a literal leading Unicode byte-order mark', async () => {
    const recipient = await generateKeyPair('ml-kem-768');
    for (const message of ['', '\uFEFFArchive 📚']) {
      const payload = await hybridEncrypt(message, recipient.publicKey, 'ml-kem-768');
      expect(await hybridDecrypt(payload, recipient.privateKey)).toBe(message);
    }
  });

  it.each(VARIANTS)('checks the encrypted fields and treats the fingerprint as a display label (%s)', async (variant) => {
    const recipient = await generateKeyPair(variant);
    const payload = await hybridEncrypt('Library notice', recipient.publicKey, variant);
    expect(payload.publicKeyFingerprint).toMatch(/^[0-9a-f]{16}$/);
    for (const field of ['mlkemCiphertext', 'aesCiphertext', 'aesIV', 'aesTag'] as const) {
      const changed = { ...payload, [field]: flipBase64Byte(payload[field]) };
      await expect(hybridDecrypt(changed, recipient.privateKey)).rejects.toThrow('Authentication failed');
    }
    const relabeled = { ...payload, publicKeyFingerprint: 'informational' };
    expect(await hybridDecrypt(relabeled, recipient.privateKey)).toBe('Library notice');
    const otherVariant = variant === 'ml-kem-768' ? 'ml-kem-512' : 'ml-kem-768';
    await expect(hybridDecrypt({ ...payload, variant: otherVariant }, recipient.privateKey))
      .rejects.toThrow(/length mismatch/);
  });

  it('tampered ML-KEM ciphertext causes explicit AES authentication failure', async () => {
    const recipient = await generateKeyPair('ml-kem-768');
    const payload = await hybridEncrypt('tamper test', recipient.publicKey, 'ml-kem-768');
    const tamperedPayload = {
      ...payload,
      mlkemCiphertext: flipBase64Byte(payload.mlkemCiphertext, 0),
    };

    await expect(hybridDecrypt(tamperedPayload, recipient.privateKey)).rejects.toThrow(
      'Authentication failed',
    );
  });
});
