import { describe, expect, it } from 'vitest';
import {
  Q,
  cleanB,
  gaussianSolve,
  generateLWEInstance,
  verifyLWE,
} from '../crypto/lwe';

describe('LWE arithmetic engine', () => {
  it('verifyLWE(generateLWEInstance(4, 6)) returns true', () => {
    expect(verifyLWE(generateLWEInstance(4, 6))).toBe(true);
  });

  it('b is always in [0, Q)', () => {
    const instance = generateLWEInstance(4, 6);
    for (const value of instance.b) {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(Q);
    }
  });

  it('CBD eta=2 samples stay small for s and e (|v| <= 3)', () => {
    const instance = generateLWEInstance(6, 4);
    for (const value of [...instance.s, ...instance.e]) {
      expect(Math.abs(value)).toBeLessThanOrEqual(3);
    }
  });

  it('Gaussian elimination recovers s exactly from the noiseless system b0 = A*s', () => {
    // Square, full-rank-with-high-probability system; retry to avoid the rare
    // singular draw so the test is deterministic in intent, not luck.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const inst = generateLWEInstance(5, 5);
      const solved = gaussianSolve(inst.A, cleanB(inst, Q), inst.s, Q);
      if (!solved.solvable) continue;
      expect(solved.correct).toBe(true);
      expect(solved.recovered).toEqual(inst.s.map((v) => ((v % Q) + Q) % Q));
      return;
    }
    throw new Error('expected at least one full-rank system in 8 draws');
  });

  it('the SAME elimination fails to recover s once noise e is added (b = A*s + e)', () => {
    // The noiseless case proves the machinery works; adding e must break the
    // recovered secret. e is tiny but nonzero, so the literal solution diverges.
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const inst = generateLWEInstance(5, 5);
      const solved = gaussianSolve(inst.A, inst.b, inst.s, Q);
      if (!solved.solvable) continue;
      // With any nonzero error the exact solve cannot return the true small s.
      if (inst.e.slice(0, 5).some((v) => v !== 0)) {
        expect(solved.correct).toBe(false);
      }
      return;
    }
    throw new Error('expected at least one full-rank system in 8 draws');
  });
});
