import { decapsulate, encapsulate, generateKeyPair, type MLKEMVariant } from './crypto/mlkem';
import { CRYPTO_IMPLEMENTATION } from './crypto/runtime';

export interface TimingStats {
  samplesMs: number[];
  medianMs: number;
  p95Ms: number;
  minMs: number;
  maxMs: number;
  medianOpsPerSecond: number | null;
}

export interface VariantBenchmarkRow {
  variant: MLKEMVariant;
  keygen: TimingStats;
  encaps: TimingStats;
  decaps: TimingStats;
}

export interface X25519BenchmarkRow {
  keygen: TimingStats;
  derive: TimingStats;
}

export interface BenchmarkEnvironment {
  generatedAt: string;
  userAgent: string;
  platform: string;
  hardwareConcurrency: number | null;
  crossOriginIsolated: boolean;
  timer: string;
  implementation: string;
  warmupIterations: number;
  measuredIterations: number;
}

export interface BenchmarkReport {
  environment: BenchmarkEnvironment;
  variants: VariantBenchmarkRow[];
  x25519: X25519BenchmarkRow | null;
}

type ProgressCallback = (message: string) => void;

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];
export const BENCHMARK_WARMUP_ITERATIONS = 10;
export const BENCHMARK_MEASURED_ITERATIONS = 50;

async function yieldToUI(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function percentile(sorted: number[], percentileValue: number): number {
  const index = Math.max(0, Math.ceil(percentileValue * sorted.length) - 1);
  return sorted[index];
}

export function summarizeSamples(samplesMs: number[]): TimingStats {
  if (samplesMs.length === 0 || samplesMs.some((sample) => !Number.isFinite(sample) || sample < 0)) {
    throw new Error('benchmark samples must contain finite, non-negative timings');
  }
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const medianMs =
    sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
  return {
    samplesMs: [...samplesMs],
    medianMs,
    p95Ms: percentile(sorted, 0.95),
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1],
    medianOpsPerSecond: medianMs === 0 ? null : 1000 / medianMs,
  };
}

async function measureOperation(
  label: string,
  progress: ProgressCallback,
  task: () => Promise<void>,
): Promise<TimingStats> {
  progress(`${label}: warming up 0/${BENCHMARK_WARMUP_ITERATIONS}`);
  for (let i = 0; i < BENCHMARK_WARMUP_ITERATIONS; i += 1) {
    await task();
    if ((i + 1) % 5 === 0) {
      progress(`${label}: warming up ${i + 1}/${BENCHMARK_WARMUP_ITERATIONS}`);
      await yieldToUI();
    }
  }

  const samplesMs: number[] = [];
  for (let i = 0; i < BENCHMARK_MEASURED_ITERATIONS; i += 1) {
    const start = performance.now();
    await task();
    samplesMs.push(performance.now() - start);
    if ((i + 1) % 10 === 0) {
      progress(`${label}: measured ${i + 1}/${BENCHMARK_MEASURED_ITERATIONS}`);
      await yieldToUI();
    }
  }
  return summarizeSamples(samplesMs);
}

async function benchmarkX25519(progress: ProgressCallback): Promise<X25519BenchmarkRow | null> {
  try {
    const stableAlice = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const stableBob = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const keygen = await measureOperation('X25519 keygen', progress, async () => {
      await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    });
    const derive = await measureOperation('X25519 deriveBits', progress, async () => {
      await crypto.subtle.deriveBits(
        { name: 'X25519', public: stableBob.publicKey },
        stableAlice.privateKey,
        256,
      );
    });
    return { keygen, derive };
  } catch {
    return null;
  }
}

function benchmarkEnvironment(): BenchmarkEnvironment {
  const navigatorWithHints = navigator as Navigator & {
    userAgentData?: { platform?: string };
  };
  return {
    generatedAt: new Date().toISOString(),
    userAgent: navigator.userAgent,
    platform: navigatorWithHints.userAgentData?.platform ?? navigator.platform ?? 'unknown',
    hardwareConcurrency: navigator.hardwareConcurrency || null,
    crossOriginIsolated: globalThis.crossOriginIsolated === true,
    timer: 'performance.now() wall-clock latency per awaited operation',
    implementation: `${CRYPTO_IMPLEMENTATION.library}@${CRYPTO_IMPLEMENTATION.version}`,
    warmupIterations: BENCHMARK_WARMUP_ITERATIONS,
    measuredIterations: BENCHMARK_MEASURED_ITERATIONS,
  };
}

export async function runBenchmark(progress: ProgressCallback): Promise<BenchmarkReport> {
  const rows: VariantBenchmarkRow[] = [];
  for (const variant of VARIANTS) {
    progress(`Preparing ${variant} benchmark...`);
    const stableKeyPair = await generateKeyPair(variant);
    const stableEncapsulation = await encapsulate(stableKeyPair.publicKey, variant);
    const keygen = await measureOperation(`${variant} keygen`, progress, async () => {
      await generateKeyPair(variant);
    });
    const encaps = await measureOperation(`${variant} encaps`, progress, async () => {
      await encapsulate(stableKeyPair.publicKey, variant);
    });
    const decaps = await measureOperation(`${variant} decaps`, progress, async () => {
      await decapsulate(stableEncapsulation.ciphertext, stableKeyPair.privateKey, variant);
    });
    rows.push({ variant, keygen, encaps, decaps });
  }

  progress('Running X25519 benchmark...');
  const x25519 = await benchmarkX25519(progress);
  progress('Benchmark complete');
  return { environment: benchmarkEnvironment(), variants: rows, x25519 };
}

function csvCell(value: string | number | boolean | null): string {
  const valueText = value === null ? '' : String(value);
  return /[",\n]/.test(valueText) ? `"${valueText.replaceAll('"', '""')}"` : valueText;
}

interface ExportRow {
  scheme: string;
  operation: string;
  stats: TimingStats;
}

function exportRows(report: BenchmarkReport): ExportRow[] {
  const rows: ExportRow[] = [];
  for (const variant of report.variants) {
    rows.push(
      { scheme: variant.variant, operation: 'keygen', stats: variant.keygen },
      { scheme: variant.variant, operation: 'encaps', stats: variant.encaps },
      { scheme: variant.variant, operation: 'decaps', stats: variant.decaps },
    );
  }
  if (report.x25519) {
    rows.push(
      { scheme: 'x25519', operation: 'keygen', stats: report.x25519.keygen },
      { scheme: 'x25519', operation: 'deriveBits', stats: report.x25519.derive },
    );
  }
  return rows;
}

export function benchmarkReportToJson(report: BenchmarkReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function benchmarkReportToCsv(report: BenchmarkReport): string {
  const header = [
    'generatedAt', 'implementation', 'userAgent', 'platform', 'hardwareConcurrency',
    'crossOriginIsolated', 'warmupIterations', 'measuredIterations', 'scheme', 'operation',
    'sampleIndex', 'latencyMs', 'medianMs', 'p95Ms',
  ];
  const lines = [header.join(',')];
  for (const row of exportRows(report)) {
    row.stats.samplesMs.forEach((latencyMs, index) => {
      lines.push(
        [
          report.environment.generatedAt,
          report.environment.implementation,
          report.environment.userAgent,
          report.environment.platform,
          report.environment.hardwareConcurrency,
          report.environment.crossOriginIsolated,
          report.environment.warmupIterations,
          report.environment.measuredIterations,
          row.scheme,
          row.operation,
          index + 1,
          latencyMs,
          row.stats.medianMs,
          row.stats.p95Ms,
        ].map(csvCell).join(','),
      );
    });
  }
  return `${lines.join('\n')}\n`;
}
