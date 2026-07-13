// ML-KEM reference: NIST FIPS 203 (August 2024)
// https://csrc.nist.gov/pubs/fips/203/final

export const Q = 3329;

export interface LWEInstance {
  A: number[][];
  s: number[];
  e: number[];
  b: number[];
  n: number;
  m: number;
}

function mod(value: number, q: number): number {
  return ((value % q) + q) % q;
}

/** Modular inverse of a mod prime q via Fermat's little theorem (q must be prime). */
function modInverse(a: number, q: number): number {
  let result = 1;
  let base = mod(a, q);
  let exp = q - 2;
  while (exp > 0) {
    if (exp & 1) result = mod(result * base, q);
    exp >>= 1;
    base = mod(base * base, q);
  }
  return result;
}

/**
 * The noiseless right-hand side b0 = A·s (mod q), i.e. what the published vector
 * WOULD be if there were no error term. Contrasting this with b = A·s + e shows
 * exactly what the noise hides.
 */
export function cleanB(instance: LWEInstance, q: number): number[] {
  return instance.A.map((row) => dot(row, instance.s, q));
}

export interface GaussianSolveResult {
  /** The vector Gaussian elimination recovers as the "secret". */
  recovered: number[] | null;
  /** True iff every recovered entry equals the true secret s. */
  correct: boolean;
  /** True if the linear system was solvable (square, full rank). */
  solvable: boolean;
}

/**
 * Attempt to recover the secret s from (A, target) by exact Gaussian elimination
 * over the field Z_q (q prime). Uses the first n rows of A as a square system.
 *
 * With target = A·s (no noise) this recovers s EXACTLY — linear algebra is easy.
 * With target = A·s + e (LWE) the same elimination returns a wrong vector,
 * because the arithmetic has no notion of "small error": it solves the equations
 * literally and the noise corrupts the answer. That gap IS the LWE hardness.
 */
export function gaussianSolve(
  A: number[][],
  target: number[],
  s: number[],
  q: number,
): GaussianSolveResult {
  const n = A[0].length;
  if (A.length < n) {
    return { recovered: null, correct: false, solvable: false };
  }
  // Build an n×(n+1) augmented matrix from the first n rows.
  const M: number[][] = [];
  for (let i = 0; i < n; i += 1) {
    M.push([...A[i].slice(0, n).map((v) => mod(v, q)), mod(target[i], q)]);
  }

  for (let col = 0; col < n; col += 1) {
    // Find a pivot row with a nonzero entry in this column.
    let pivot = -1;
    for (let row = col; row < n; row += 1) {
      if (M[row][col] % q !== 0) {
        pivot = row;
        break;
      }
    }
    if (pivot === -1) {
      return { recovered: null, correct: false, solvable: false };
    }
    [M[col], M[pivot]] = [M[pivot], M[col]];
    const inv = modInverse(M[col][col], q);
    for (let k = col; k <= n; k += 1) {
      M[col][k] = mod(M[col][k] * inv, q);
    }
    for (let row = 0; row < n; row += 1) {
      if (row === col) continue;
      const factor = M[row][col];
      if (factor === 0) continue;
      for (let k = col; k <= n; k += 1) {
        M[row][k] = mod(M[row][k] - factor * M[col][k], q);
      }
    }
  }

  const recovered = M.map((row) => row[n]);
  const correct = recovered.every((v, i) => mod(v, q) === mod(s[i], q));
  return { recovered, correct, solvable: true };
}

function sampleUniformModQ(q: number): number {
  return Math.floor(Math.random() * q);
}

function sampleCBD(eta = 2): number {
  let heads = 0;
  let tails = 0;
  for (let i = 0; i < eta; i += 1) {
    heads += Math.random() < 0.5 ? 1 : 0;
    tails += Math.random() < 0.5 ? 1 : 0;
  }
  return heads - tails;
}

function dot(a: number[], b: number[], q: number): number {
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc = mod(acc + a[i] * b[i], q);
  }
  return acc;
}

export function generateLWEInstance(n: number, m: number): LWEInstance {
  if (n <= 0 || m <= 0) {
    throw new Error('LWE dimensions n and m must be positive');
  }
  const A: number[][] = Array.from({ length: m }, () =>
    Array.from({ length: n }, () => sampleUniformModQ(Q)),
  );
  const s: number[] = Array.from({ length: n }, () => sampleCBD(2));
  const e: number[] = Array.from({ length: m }, () => sampleCBD(2));
  const b: number[] = Array.from({ length: m }, (_, i) => mod(dot(A[i], s, Q) + e[i], Q));

  return { A, s, e, b, n, m };
}

export function verifyLWE(instance: LWEInstance): boolean {
  const { A, s, e, b, m } = instance;
  for (let i = 0; i < m; i += 1) {
    const expected = mod(dot(A[i], s, Q) + e[i], Q);
    if (b[i] !== expected) {
      return false;
    }
  }
  return true;
}

function formatBigInt(value: bigint): string {
  const str = value.toString();
  return str.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function bruteForceSearchSpace(n: number): string {
  if (n <= 0) {
    throw new Error('n must be positive');
  }
  const space = BigInt(Q) ** BigInt(n);
  return `For n=${n} and q=${Q}, brute-force secret search is q^n = ${formatBigInt(space)} candidates.`;
}

export function generateIllustrativeLWEInstance(n: number, m: number, q: number): LWEInstance {
  const A: number[][] = Array.from({ length: m }, () =>
    Array.from({ length: n }, () => sampleUniformModQ(q)),
  );
  const s: number[] = Array.from({ length: n }, () => sampleCBD(2));
  const e: number[] = Array.from({ length: m }, () => sampleCBD(2));
  const b: number[] = Array.from({ length: m }, (_, i) => mod(dot(A[i], s, q) + e[i], q));

  return { A, s, e, b, n, m };
}

export function verifyLWEWithQ(instance: LWEInstance, q: number): boolean {
  for (let i = 0; i < instance.m; i += 1) {
    const expected = mod(dot(instance.A[i], instance.s, q) + instance.e[i], q);
    if (instance.b[i] !== expected) {
      return false;
    }
  }
  return true;
}
