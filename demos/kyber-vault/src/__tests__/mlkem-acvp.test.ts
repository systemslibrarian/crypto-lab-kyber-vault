import { ml_kem1024, ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';
import acvp from '../../test-vectors/nist-acvp-ml-kem.json';

const IMPLEMENTATIONS = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
} as const;

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('Invalid hex fixture');
  }
  return Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}

describe('NIST ACVP FIPS 203 known-answer vectors', () => {
  it('pins the vectors to an exact NIST source commit', () => {
    expect(acvp.source.repository).toBe('https://github.com/usnistgov/ACVP-Server');
    expect(acvp.source.commit).toBe('975de31eb83d87039ec88934fdc47d8c312b892d');
    expect(acvp.source.revision).toBe('FIPS203');
  });

  for (const vector of acvp.vectors) {
    const kem = IMPLEMENTATIONS[vector.parameterSet as keyof typeof IMPLEMENTATIONS];

    it(`${vector.parameterSet} KeyGen matches NIST tcId ${vector.keyGen.tcId} byte for byte`, () => {
      // FIPS 203 KeyGen consumes d || z; noble exposes that 64-byte input as
      // a deterministic hook specifically for known-answer testing.
      const seed = new Uint8Array([...fromHex(vector.keyGen.d), ...fromHex(vector.keyGen.z)]);
      const generated = kem.keygen(seed);

      expect(toHex(generated.publicKey)).toBe(vector.keyGen.ek);
      expect(toHex(generated.secretKey)).toBe(vector.keyGen.dk);
    });

    it(`${vector.parameterSet} encapsulation matches NIST tcId ${vector.encapsulation.tcId}`, () => {
      const result = kem.encapsulate(
        fromHex(vector.encapsulation.ek),
        fromHex(vector.encapsulation.m),
      );

      expect(toHex(result.cipherText)).toBe(vector.encapsulation.c);
      expect(toHex(result.sharedSecret)).toBe(vector.encapsulation.k);
    });

    it(`${vector.parameterSet} decapsulation matches NIST tcId ${vector.decapsulation.tcId}`, () => {
      const sharedSecret = kem.decapsulate(
        fromHex(vector.decapsulation.c),
        fromHex(vector.decapsulation.dk),
      );

      expect(toHex(sharedSecret)).toBe(vector.decapsulation.k);
    });

    it(`${vector.parameterSet} rejects NIST-invalid encapsulation key tcId ${vector.invalidEncapsulationKey.tcId}`, () => {
      expect(() =>
        kem.encapsulate(
          fromHex(vector.invalidEncapsulationKey.ek),
          new Uint8Array(32),
        ),
      ).toThrow();
    });

    it(`${vector.parameterSet} rejects NIST-invalid decapsulation key tcId ${vector.invalidDecapsulationKey.tcId}`, () => {
      expect(() =>
        kem.decapsulate(
          fromHex(vector.decapsulation.c),
          fromHex(vector.invalidDecapsulationKey.dk),
        ),
      ).toThrow();
    });
  }
});
