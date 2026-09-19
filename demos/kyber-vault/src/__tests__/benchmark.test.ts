import { describe, expect, it } from 'vitest';
import {
  benchmarkReportToCsv,
  benchmarkReportToJson,
  summarizeSamples,
  type BenchmarkReport,
} from '../benchmark';

const stats = summarizeSamples([1, 2, 3]);
const report: BenchmarkReport = {
  environment: {
    generatedAt: '2026-09-19T12:00:00.000Z',
    userAgent: 'Test Browser, 1.0',
    platform: 'test',
    hardwareConcurrency: 8,
    crossOriginIsolated: false,
    timer: 'performance.now()',
    implementation: '@noble/post-quantum@0.7.1',
    warmupIterations: 10,
    measuredIterations: 3,
  },
  variants: [{ variant: 'ml-kem-768', keygen: stats, encaps: stats, decaps: stats }],
  x25519: null,
};

describe('benchmark statistics and export', () => {
  it('computes an even-sample median and nearest-rank p95 without mutating raw samples', () => {
    const samples = Array.from({ length: 20 }, (_, index) => 20 - index);
    const summary = summarizeSamples(samples);
    expect(summary.medianMs).toBe(10.5);
    expect(summary.p95Ms).toBe(19);
    expect(summary.minMs).toBe(1);
    expect(summary.maxMs).toBe(20);
    expect(summary.samplesMs).toEqual(samples);
    expect(summary.samplesMs).not.toBe(samples);
    expect(summary.medianOpsPerSecond).not.toBeNull();
    expect(summary.medianOpsPerSecond!).toBeCloseTo(1000 / 10.5);
  });

  it('rejects empty, negative, and non-finite sample sets', () => {
    expect(() => summarizeSamples([])).toThrow(/finite, non-negative/);
    expect(() => summarizeSamples([1, -1])).toThrow(/finite, non-negative/);
    expect(() => summarizeSamples([Number.NaN])).toThrow(/finite, non-negative/);
  });

  it('exports full metadata and every raw sample to JSON and long-form CSV', () => {
    const json = JSON.parse(benchmarkReportToJson(report)) as BenchmarkReport;
    expect(json.environment.implementation).toBe('@noble/post-quantum@0.7.1');
    expect(json.variants[0].encaps.samplesMs).toEqual([1, 2, 3]);

    const csv = benchmarkReportToCsv(report);
    const lines = csv.trim().split('\n');
    expect(lines).toHaveLength(10);
    expect(lines[0]).toContain('sampleIndex,latencyMs,medianMs,p95Ms');
    expect(lines[1]).toContain('"Test Browser, 1.0"');
    expect(lines[1]).toContain('ml-kem-768,keygen,1,1,2,3');
    expect(lines.at(-1)).toContain('ml-kem-768,decaps,3,3,2,3');
  });
});
