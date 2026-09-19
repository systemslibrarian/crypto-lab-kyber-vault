// Cyclic Number Theoretic Transform (NTT) primer — educational module.
// This is a standard radix-2 DIT NTT for small sizes. It is deliberately not
// FIPS 203's specialized incomplete negacyclic ML-KEM transform.

export const Q = 3329;

/** Kyber's primitive 256th root of unity ζ = 17 (mod 3329). */
export const ZETA = 17;
export const NTT_PRIMER_SIZE = 8;
export const NTT_PRIMER_RING = 'Z_3329[X]/(X^8 - 1)';

function mod(a: number, q: number): number {
  return ((a % q) + q) % q;
}

function modPow(base: number, exp: number, q: number): number {
  let result = 1;
  base = mod(base, q);
  while (exp > 0) {
    if (exp & 1) result = mod(result * base, q);
    exp >>= 1;
    base = mod(base * base, q);
  }
  return result;
}

function modInverse(a: number, q: number): number {
  return modPow(a, q - 2, q);
}

/** Compute the n-th root of unity mod q, derived from ζ = 17. */
export function rootOfUnity(n: number): number {
  if (256 % n !== 0) throw new Error(`n=${n} must divide 256`);
  return modPow(ZETA, 256 / n, Q);
}

/** One butterfly operation recorded for visualisation. */
export interface ButterflyOp {
  layer: number;
  i: number;
  j: number;
  twiddle: number;
  beforeI: number;
  beforeJ: number;
  afterI: number;
  afterJ: number;
}

/**
 * Forward NTT (Cooley-Tukey DIT) on `coeffs` mod q.
 * Returns the NTT result plus a trace of every butterfly operation.
 */
export function nttForward(coeffs: number[]): {
  result: number[];
  butterflies: ButterflyOp[];
} {
  const n = coeffs.length;
  if (n & (n - 1)) throw new Error('n must be a power of 2');

  const omega = rootOfUnity(n);
  const a = coeffs.slice();
  const butterflies: ButterflyOp[] = [];

  // Bit-reversal permutation
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) [a[i], a[j]] = [a[j], a[i]];
  }

  // Butterfly stages
  let layer = 0;
  for (let len = 2; len <= n; len <<= 1) {
    const w = modPow(omega, n / len, Q);
    for (let i = 0; i < n; i += len) {
      let tw = 1;
      for (let j = 0; j < len / 2; j++) {
        const u = a[i + j];
        const v = mod(a[i + j + len / 2] * tw, Q);
        const afterI = mod(u + v, Q);
        const afterJ = mod(u - v, Q);
        butterflies.push({
          layer,
          i: i + j,
          j: i + j + len / 2,
          twiddle: tw,
          beforeI: u,
          beforeJ: a[i + j + len / 2],
          afterI,
          afterJ,
        });
        a[i + j] = afterI;
        a[i + j + len / 2] = afterJ;
        tw = mod(tw * w, Q);
      }
    }
    layer++;
  }

  return { result: a, butterflies };
}

/** Inverse NTT. */
export function nttInverse(values: number[]): number[] {
  const n = values.length;
  if (n & (n - 1)) throw new Error('n must be a power of 2');

  const omega = rootOfUnity(n);
  const omegaInv = modInverse(omega, Q);
  const a = values.slice();

  // Bit-reversal permutation
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) [a[i], a[j]] = [a[j], a[i]];
  }

  for (let len = 2; len <= n; len <<= 1) {
    const w = modPow(omegaInv, n / len, Q);
    for (let i = 0; i < n; i += len) {
      let tw = 1;
      for (let j = 0; j < len / 2; j++) {
        const u = a[i + j];
        const v = mod(a[i + j + len / 2] * tw, Q);
        a[i + j] = mod(u + v, Q);
        a[i + j + len / 2] = mod(u - v, Q);
        tw = mod(tw * w, Q);
      }
    }
  }

  const nInv = modInverse(n, Q);
  for (let i = 0; i < n; i++) {
    a[i] = mod(a[i] * nInv, Q);
  }
  return a;
}

/**
 * Schoolbook polynomial multiplication mod (X^n − 1), mod q.
 * Cyclic convolution for this primer's X^n - 1 ring.
 */
export function polyMultiplySchoolbook(a: number[], b: number[]): number[] {
  const n = a.length;
  const c = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const idx = (i + j) % n;
      c[idx] = mod(c[idx] + a[i] * b[j], Q);
    }
  }
  return c;
}

/** Full NTT-based polynomial multiplication with intermediate values for visualisation. */
export function polyMultiplyNTT(a: number[], b: number[]): {
  result: number[];
  nttA: number[];
  nttB: number[];
  pointwise: number[];
  butterfliesA: ButterflyOp[];
  butterfliesB: ButterflyOp[];
} {
  const n = a.length;
  const { result: nttA, butterflies: butterfliesA } = nttForward(a);
  const { result: nttB, butterflies: butterfliesB } = nttForward(b);

  const pointwise = new Array<number>(n);
  for (let i = 0; i < n; i++) {
    pointwise[i] = mod(nttA[i] * nttB[i], Q);
  }

  const result = nttInverse(pointwise);
  return { result, nttA, nttB, pointwise, butterfliesA, butterfliesB };
}

/** Generate a random small-coefficient polynomial for the educational demo. */
export function randomSmallPoly(n: number, bound = 4): number[] {
  return Array.from({ length: n }, () =>
    mod(Math.floor(Math.random() * (2 * bound + 1)) - bound, Q),
  );
}
