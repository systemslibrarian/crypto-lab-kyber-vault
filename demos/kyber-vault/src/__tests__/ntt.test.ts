import { describe, expect, it } from 'vitest';
import {
  Q,
  NTT_PRIMER_RING,
  NTT_PRIMER_SIZE,
  ZETA,
  nttForward,
  nttInverse,
  polyMultiplyNTT,
  polyMultiplySchoolbook,
  randomSmallPoly,
  rootOfUnity,
} from '../crypto/ntt';

describe('NTT', () => {
  it('labels the teaching transform as an 8-point cyclic primer', () => {
    expect(NTT_PRIMER_SIZE).toBe(8);
    expect(NTT_PRIMER_RING).toBe('Z_3329[X]/(X^8 - 1)');
  });
  it('ζ = 17 is a primitive 256th root of unity mod 3329', () => {
    // ζ^256 ≡ 1 mod q
    let z = 1;
    for (let i = 0; i < 256; i++) z = (z * ZETA) % Q;
    expect(z).toBe(1);

    // ζ^128 ≢ 1 (primitive check)
    let z128 = 1;
    for (let i = 0; i < 128; i++) z128 = (z128 * ZETA) % Q;
    expect(z128).not.toBe(1);
  });

  it('rootOfUnity(8) is an 8th root of unity', () => {
    const w = rootOfUnity(8);
    let acc = 1;
    for (let i = 0; i < 8; i++) acc = (acc * w) % Q;
    expect(acc).toBe(1);
  });

  it('NTT forward then inverse is identity', () => {
    const poly = [1, 2, 3, 4, 5, 6, 7, 8];
    const { result: nttPoly } = nttForward(poly);
    const recovered = nttInverse(nttPoly);
    expect(recovered).toEqual(poly);
  });

  it('NTT-based multiplication matches schoolbook', () => {
    const a = randomSmallPoly(8);
    const b = randomSmallPoly(8);
    const schoolbook = polyMultiplySchoolbook(a, b);
    const { result: nttResult } = polyMultiplyNTT(a, b);
    expect(nttResult).toEqual(schoolbook);
  });

  it('butterfly trace has the correct number of operations', () => {
    // n=8 → 3 layers, each with n/2 = 4 butterflies → 12 total
    const poly = [10, 20, 30, 40, 50, 60, 70, 80];
    const { butterflies } = nttForward(poly);
    expect(butterflies.length).toBe(12);
    expect(new Set(butterflies.map((b) => b.layer)).size).toBe(3);
  });
});
