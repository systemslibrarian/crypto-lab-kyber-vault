// ML-KEM reference: NIST FIPS 203 (August 2024)
// https://csrc.nist.gov/pubs/fips/203/final

import { decapsulate, encapsulate, type MLKEMVariant } from './mlkem';

export interface HybridEncryptResult {
  mlkemCiphertext: string;
  aesCiphertext: string;
  aesIV: string;
  aesTag: string;
  variant: MLKEMVariant;
  publicKeyFingerprint: string;
}

const HKDF_SALT = new TextEncoder().encode('kyber-vault-v1');

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function fingerprintPublicKey(publicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(publicKey));
  return toHex(new Uint8Array(digest)).slice(0, 16);
}

async function deriveAesKey(sharedSecret: Uint8Array, variant: MLKEMVariant): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(sharedSecret),
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT,
      info: new TextEncoder().encode(`kyber-vault:${variant}`),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function hybridEncrypt(
  message: string,
  recipientPublicKey: Uint8Array,
  variant: MLKEMVariant,
): Promise<HybridEncryptResult> {
  const { sharedSecret, ciphertext } = await encapsulate(recipientPublicKey, variant);
  const aesKey = await deriveAesKey(sharedSecret, variant);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(message);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext),
  );

  const tagLength = 16;
  const aesCiphertext = encrypted.subarray(0, encrypted.length - tagLength);
  const aesTag = encrypted.subarray(encrypted.length - tagLength);

  return {
    mlkemCiphertext: bytesToBase64(ciphertext),
    aesCiphertext: bytesToBase64(aesCiphertext),
    aesIV: bytesToBase64(iv),
    aesTag: bytesToBase64(aesTag),
    variant,
    publicKeyFingerprint: await fingerprintPublicKey(recipientPublicKey),
  };
}

export async function hybridDecrypt(
  payload: HybridEncryptResult,
  recipientPrivateKey: Uint8Array,
): Promise<string> {
  const mlkemCiphertext = base64ToBytes(payload.mlkemCiphertext);
  const aesCiphertext = base64ToBytes(payload.aesCiphertext);
  const aesIV = base64ToBytes(payload.aesIV);
  const aesTag = base64ToBytes(payload.aesTag);

  const sharedSecret = await decapsulate(mlkemCiphertext, recipientPrivateKey, payload.variant);
  const aesKey = await deriveAesKey(sharedSecret, payload.variant);

  const combined = new Uint8Array(aesCiphertext.length + aesTag.length);
  combined.set(aesCiphertext, 0);
  combined.set(aesTag, aesCiphertext.length);

  try {
    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(aesIV) },
      aesKey,
      toArrayBuffer(combined),
    );
    return new TextDecoder('utf-8', { ignoreBOM: true }).decode(new Uint8Array(plaintextBuffer));
  } catch {
    throw new Error('Authentication failed');
  }
}

export function flipBase64Byte(base64Value: string, index = 0): string {
  const bytes = base64ToBytes(base64Value);
  if (bytes.length === 0) {
    return base64Value;
  }
  bytes[index % bytes.length] ^= 0xff;
  return bytesToBase64(bytes);
}
