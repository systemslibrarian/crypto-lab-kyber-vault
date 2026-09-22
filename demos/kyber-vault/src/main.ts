import './style.css';
import {
  BENCHMARK_MEASURED_ITERATIONS,
  BENCHMARK_WARMUP_ITERATIONS,
  benchmarkReportToCsv,
  benchmarkReportToJson,
  runBenchmark,
  type BenchmarkReport,
  type TimingStats,
} from './benchmark';
import { flipBase64Byte, hybridDecrypt, hybridEncrypt, type HybridEncryptResult } from './crypto/hybrid';
import {
  ML_KEM_PARAMS,
  decapsulate,
  encapsulate,
  generateKeyPair,
  type MLKEMEncapsResult,
  type MLKEMKeyPair,
  type MLKEMVariant,
} from './crypto/mlkem';
import { assertCryptographicRuntime, CRYPTO_IMPLEMENTATION } from './crypto/runtime';
import {
  Q,
  LWE_PRIMER_PARAMS,
  bruteForceSearchSpace,
  centeredRepresentative,
  cleanB,
  gaussianSolve,
  generateIllustrativeLWEInstance,
  type GaussianSolveResult,
  type LWEInstance,
  verifyLWEWithQ,
} from './crypto/lwe';
import {
  NTT_PRIMER_RING,
  NTT_PRIMER_SIZE,
  type ButterflyOp,
  polyMultiplyNTT,
  polyMultiplySchoolbook,
  randomSmallPoly,
} from './crypto/ntt';

type TabId = 'encaps' | 'lattice' | 'params' | 'compare' | 'how';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('App root not found');
}
const appRoot = app;

assertCryptographicRuntime();

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];
const ILLUSTRATIVE_Q = LWE_PRIMER_PARAMS.q;
// Square (n=m) so the noiseless system has a unique solution Gaussian
// elimination can recover — the contrast that teaches LWE hardness.
const LWE_DIM = LWE_PRIMER_PARAMS.n;

const TABS: { id: TabId; label: string }[] = [
  { id: 'encaps', label: 'Encapsulate / Decapsulate' },
  { id: 'lattice', label: 'Lattice visualizer' },
  { id: 'params', label: 'Parameter sets' },
  { id: 'compare', label: 'vs X25519 / RSA' },
  { id: 'how', label: 'How LWE works' },
];

// When a tab is changed via keyboard, move focus to it after the next render.
let pendingTabFocus = false;

const state: {
  activeTab: TabId;
  variant: MLKEMVariant;
  step: number;
  learnStep: number;
  keyPair: MLKEMKeyPair | null;
  encapsResult: MLKEMEncapsResult | null;
  bobSecret: Uint8Array | null;
  timings: { keygen?: number; encaps?: number; decaps?: number };
  status: string;
  message: string;
  hybridPayload: HybridEncryptResult | null;
  hybridDecrypted: string;
  hybridNotice: string;
  hybridError: string;
  lwe: LWEInstance;
  latticeMessage: string;
  latticeSolve: { mode: 'clean' | 'noisy'; result: GaussianSolveResult } | null;
  nttA: number[];
  nttB: number[];
  nttResult: {
    result: number[];
    nttA: number[];
    nttB: number[];
    pointwise: number[];
    butterfliesA: ButterflyOp[];
    butterfliesB: ButterflyOp[];
  } | null;
  nttSchoolbook: number[] | null;
  // Which butterfly (index into butterfliesA) is spotlighted in the dataflow view.
  nttButterflyStep: number;
  benchmark: BenchmarkReport | null;
  benchmarkProgress: string;
  benchmarkRunning: boolean;
} = {
  activeTab: 'encaps',
  variant: 'ml-kem-768',
  step: 1,
  learnStep: 1,
  keyPair: null,
  encapsResult: null,
  bobSecret: null,
  timings: {},
  status: 'Ready to run ML-KEM KeyGen for Bob.',
  message: 'Quantum-safe hello from kyber-vault.',
  hybridPayload: null,
  hybridDecrypted: '',
  hybridNotice: '',
  hybridError: '',
  lwe: generateIllustrativeLWEInstance(4, 4, ILLUSTRATIVE_Q),
  latticeMessage: 'Educational instance uses q=17. Core ML-KEM uses q=3329.',
  latticeSolve: null,
  nttA: randomSmallPoly(NTT_PRIMER_SIZE),
  nttB: randomSmallPoly(NTT_PRIMER_SIZE),
  nttResult: null,
  nttSchoolbook: null,
  nttButterflyStep: 0,
  benchmark: null,
  benchmarkProgress: '',
  benchmarkRunning: false,
};

function variantDisplay(variant: MLKEMVariant): string {
  if (variant === 'ml-kem-512') return 'ML-KEM-512';
  if (variant === 'ml-kem-768') return 'ML-KEM-768';
  return 'ML-KEM-1024';
}

function resetFlow(): void {
  state.step = 1;
  state.keyPair = null;
  state.encapsResult = null;
  state.bobSecret = null;
  state.timings = {};
  state.hybridPayload = null;
  state.hybridDecrypted = '';
  state.hybridNotice = '';
  state.hybridError = '';
  state.status = 'Variant changed. Run KeyGen to start a fresh session.';
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function hexPreview(bytes: Uint8Array | null, max = 24): string {
  if (!bytes) {
    return 'not generated';
  }
  const full = toHex(bytes);
  if (full.length <= max * 2) {
    return full;
  }
  return `${full.slice(0, max)}...${full.slice(-max)}`;
}

function formatMs(value: number | undefined): string {
  if (value === undefined) {
    return '--';
  }
  return `${value.toFixed(3)} ms`;
}

function formatOps(value: number | null): string {
  return value === null ? 'timer resolution limit' : `${value.toFixed(1)} ops/s`;
}

function renderTimingRow(scheme: string, operation: string, stats: TimingStats): string {
  return `<tr><th scope="row">${scheme}</th><td>${operation}</td><td>${stats.medianMs.toFixed(3)} ms</td><td>${stats.p95Ms.toFixed(3)} ms</td><td>${formatOps(stats.medianOpsPerSecond)}</td><td>${stats.samplesMs.length}</td></tr>`;
}

function downloadText(filename: string, contents: string, mimeType: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: mimeType }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Side-by-side byte-for-byte view of Alice's and Bob's recovered secrets.
 * The payoff of the whole KEM: the SAME 32 bytes appear on both ends although
 * only the ciphertext ever crossed the wire.
 */
function renderSecretComparison(alice: Uint8Array, bob: Uint8Array): string {
  const row = (bytes: Uint8Array, other: Uint8Array, who: string): string => {
    const cells = Array.from(bytes, (value, i) => {
      const eq = other[i] === value;
      return `<span class="ss-byte ${eq ? 'eq' : 'ne'}">${value.toString(16).padStart(2, '0')}</span>`;
    }).join('');
    return `<div class="ss-row"><span class="ss-who">${who}</span><span class="ss-bytes">${cells}</span></div>`;
  };
  const allEqual = alice.length === bob.length && alice.every((v, i) => v === bob[i]);
  return `
    <div class="secret-compare ${allEqual ? 'match-ok' : 'match-bad'}" role="group" aria-label="Byte-by-byte comparison of Alice's and Bob's 32-byte shared secrets">
      ${row(alice, bob, "Alice's secret")}
      ${row(bob, alice, "Bob's secret")}
      <p class="ss-verdict" role="alert">${
        allEqual
          ? `All ${alice.length} bytes match — Alice and Bob now hold the identical shared secret.`
          : 'Bytes differ — key agreement failed.'
      }</p>
      <p class="ss-caption">Neither party sent this secret over the wire — only the ciphertext traveled.</p>
    </div>`;
}

/**
 * A single NTT butterfly drawn as a dataflow diagram: two inputs u = a[i] and
 * v = a[j] cross, v is scaled by the twiddle ω, and the outputs are u+ωv and
 * u−ωv. Seeing one butterfly makes the O(n log n) reuse concrete.
 */
function renderButterflyDiagram(op: ButterflyOp, index: number, total: number): string {
  const scaledV = ((op.beforeJ * op.twiddle) % Q + Q) % Q;
  return `
    <div class="bf-diagram" role="img" aria-label="Butterfly ${index + 1} of ${total}, layer ${op.layer + 1}: inputs a[${op.i}]=${op.beforeI} and a[${op.j}]=${op.beforeJ}. The twiddle omega=${op.twiddle} scales a[${op.j}] to ${scaledV}. Outputs a[${op.i}]=${op.afterI} (which is u plus omega times v) and a[${op.j}]=${op.afterJ} (u minus omega times v), all mod ${Q}.">
      <svg viewBox="0 0 440 160" width="100%" preserveAspectRatio="xMidYMid meet" aria-hidden="true" focusable="false">
        <line x1="70" y1="40" x2="250" y2="40" class="bf-edge"/>
        <line x1="70" y1="120" x2="250" y2="40" class="bf-edge bf-edge-tw"/>
        <line x1="70" y1="40" x2="250" y2="120" class="bf-edge"/>
        <line x1="70" y1="120" x2="250" y2="120" class="bf-edge bf-edge-tw"/>
        <circle cx="70" cy="40" r="6" class="bf-node in"/>
        <circle cx="70" cy="120" r="6" class="bf-node in"/>
        <circle cx="250" cy="40" r="6" class="bf-node out"/>
        <circle cx="250" cy="120" r="6" class="bf-node out"/>
        <text x="58" y="44" text-anchor="end" class="bf-txt">u=${op.beforeI}</text>
        <text x="58" y="124" text-anchor="end" class="bf-txt">v=${op.beforeJ}</text>
        <text x="160" y="18" text-anchor="middle" class="bf-txt tw">×ω=${op.twiddle}</text>
        <text x="262" y="44" text-anchor="start" class="bf-txt out">u+ωv=${op.afterI}</text>
        <text x="262" y="124" text-anchor="start" class="bf-txt out">u−ωv=${op.afterJ}</text>
      </svg>
      <p class="bf-caption">Layer ${op.layer + 1} · a[${op.i}], a[${op.j}] → ωv = ${op.beforeJ}·${op.twiddle} mod ${Q} = ${scaledV}; then u±ωv. One multiply feeds <strong>two</strong> outputs — that reuse is why the NTT is O(n log n), not O(n²).</p>
    </div>`;
}

function renderButterflyTable(butterflies: ButterflyOp[]): string {
  const layers = new Map<number, ButterflyOp[]>();
  for (const op of butterflies) {
    const arr = layers.get(op.layer) ?? [];
    arr.push(op);
    layers.set(op.layer, arr);
  }
  let html = '';
  for (const [layer, ops] of layers) {
    html += `<div class="ntt-layer"><span class="ntt-layer-label">Layer ${layer + 1}</span>`;
    for (const op of ops) {
      html += `<span class="ntt-butterfly" title="ω=${op.twiddle}: a[${op.i}]=${op.beforeI}, a[${op.j}]=${op.beforeJ} → ${op.afterI}, ${op.afterJ}">[${op.i},${op.j}]</span>`;
    }
    html += '</div>';
  }
  return html;
}

function renderLweMatrix(instance: LWEInstance): string {
  // A is uniform-random: its magnitudes carry no structure, so we render it as a
  // plain grid of numbers. Colour is reserved for the noise vector e, which is
  // where the meaning actually lives.
  return instance.A
    .map(
      (row) =>
        `<div class="matrix-row">${row
          .map((value) => `<span class="cell" title="A[i][j] = ${value} mod ${ILLUSTRATIVE_Q}">${value}</span>`)
          .join('')}</div>`,
    )
    .join('');
}

/** Render the small noise vector e with per-entry colour emphasis (the point of LWE). */
function renderNoiseVector(e: number[]): string {
  const cells = e
    .map((value) => {
      const cls = value === 0 ? 'zero' : value > 0 ? 'pos' : 'neg';
      const sign = value > 0 ? `+${value}` : `${value}`;
      return `<span class="noise-cell ${cls}">${sign}</span>`;
    })
    .join('');
  return `<span class="noise-vec" role="img" aria-label="Noise vector e = [${e.join(', ')}], small values that hide the linear structure">${cells}</span>`;
}

/** Render b clean vs b published so the learner sees exactly what e adds. */
function renderBComparison(instance: LWEInstance): string {
  const clean = cleanB(instance, ILLUSTRATIVE_Q);
  const cell = (v: number, changed: boolean) =>
    `<span class="b-cell ${changed ? 'changed' : ''}">${v}</span>`;
  const cleanRow = clean.map((v) => cell(v, false)).join('');
  const noisyRow = instance.b.map((v, i) => cell(v, v !== clean[i])).join('');
  return `
    <div class="b-compare">
      <div class="b-row"><span class="b-label">b = A·s <em>(clean, no noise)</em></span><span class="b-cells">${cleanRow}</span></div>
      <div class="b-row published"><span class="b-label">b = A·s + e <em>(what gets published)</em></span><span class="b-cells">${noisyRow}</span></div>
    </div>`;
}

async function runNextStep(): Promise<void> {
  const params = ML_KEM_PARAMS[state.variant];
  if (state.step === 1) {
    const start = performance.now();
    state.keyPair = await generateKeyPair(state.variant);
    state.timings.keygen = performance.now() - start;
    state.status = `KeyGen complete (${params.publicKey}B public, ${params.privateKey}B private).`;
    state.step = 2;
    return;
  }

  if (state.step === 2) {
    if (!state.keyPair) {
      state.status = 'Run KeyGen first.';
      return;
    }
    const start = performance.now();
    state.encapsResult = await encapsulate(state.keyPair.publicKey, state.variant);
    state.timings.encaps = performance.now() - start;
    state.status = `Encaps complete (${params.ciphertext}B ciphertext).`;
    state.step = 3;
    return;
  }

  if (state.step === 3) {
    if (!state.keyPair || !state.encapsResult) {
      state.status = 'Run KeyGen and Encaps first.';
      return;
    }
    const start = performance.now();
    state.bobSecret = await decapsulate(
      state.encapsResult.ciphertext,
      state.keyPair.privateKey,
      state.variant,
    );
    state.timings.decaps = performance.now() - start;
    state.status = 'Decaps complete. Shared secret recovered by Bob.';
    state.step = 4;
    return;
  }

  state.status = 'Key agreement complete.';
}

function render(): void {
  const params = ML_KEM_PARAMS[state.variant];
  const stepDescriptions = [
    '1. KeyGen (Bob) - Bob creates ML-KEM keypair.',
    '2. Encaps (Alice) - Alice derives shared secret + ciphertext.',
    '3. Decaps (Bob) - Bob recovers shared secret from ciphertext.',
    '4. Key agreement complete - secrets must match exactly.',
  ];

  appRoot.innerHTML = `
  <main class="shell">
    <header class="cl-hero" role="group">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">ML-KEM</h1>
        <p class="cl-hero-sub">ML-KEM · Final FIPS 203 standard</p>
        <p class="cl-hero-desc">Steps through KeyGen, Encaps, and Decaps on real ML-KEM, then chains the shared secret into an AES-256-GCM hybrid while visualizing the Learning-With-Errors lattice and the NTT behind fast polynomial math.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">A future quantum computer would break the RSA and elliptic-curve key exchange securing the internet today. ML-KEM is NIST's standardized lattice-based replacement, chosen to keep shared secrets safe against quantum attackers.</p>
      </aside>
    </header>

    <nav class="tabs" role="tablist" aria-label="Demo sections">
      ${TABS.map(
        (tab) =>
          `<button class="tab ${state.activeTab === tab.id ? 'active' : ''}" data-tab="${tab.id}" role="tab" aria-selected="${state.activeTab === tab.id}" aria-controls="panel-${tab.id}" id="tab-${tab.id}" tabindex="${state.activeTab === tab.id ? '0' : '-1'}">${tab.label}</button>`,
      ).join('')}
    </nav>

    <section class="panel ${state.activeTab === 'encaps' ? 'visible' : ''}" id="panel-encaps" role="tabpanel" aria-labelledby="tab-encaps" ${state.activeTab !== 'encaps' ? 'hidden' : ''}>
      <div class="card intro-card">
        <h2>What is a KEM?</h2>
        <p class="intro-lead">Alice wants to send Bob a secret over a wire an eavesdropper can read. <strong>Encapsulation</strong> generates a fresh random shared secret <em>plus</em> a ciphertext; only Bob's private key can turn that ciphertext back into the same secret.</p>
        <p class="intro-note">That is what makes a <abbr title="Key Encapsulation Mechanism: a public-key scheme whose job is to establish one random shared secret, not to encrypt a chosen message.">KEM</abbr> different from ordinary public-key encryption: you don't <em>choose</em> the secret and encrypt it — the KEM <em>manufactures</em> a random one and hands you a matching capsule. The stepper below runs each stage on real ML-KEM and shows the exact bytes it produces.</p>
        <div class="kem-flow" role="img" aria-label="Diagram: Alice runs Encapsulate on Bob's public key to produce a shared secret and a ciphertext. Only the ciphertext travels across the untrusted wire to Bob, who runs Decapsulate with his private key to recover the identical shared secret.">
          <div class="kem-actor">
            <span class="kem-name">Alice</span>
            <span class="kem-op">Encaps(pk)</span>
            <span class="kem-artifact secret">shared secret</span>
          </div>
          <div class="kem-wire">
            <span class="kem-wire-label">untrusted wire</span>
            <span class="kem-wire-cargo">ciphertext →</span>
            <span class="kem-wire-eaves">eavesdropper sees only this</span>
          </div>
          <div class="kem-actor">
            <span class="kem-name">Bob</span>
            <span class="kem-op">Decaps(sk)</span>
            <span class="kem-artifact secret">same shared secret</span>
          </div>
        </div>
      </div>

      <div class="pill-row" role="group" aria-label="Choose an ML-KEM parameter set">
        ${VARIANTS.map(
          (variant) =>
            `<button id="variant-${variant}" class="pill ${state.variant === variant ? 'active' : ''}" data-variant="${variant}" aria-pressed="${state.variant === variant}">${variantDisplay(variant)}</button>`,
        ).join('')}
      </div>

      <section class="card parameter-choice" aria-labelledby="selected-profile-title">
        <p class="parameter-kicker">Selected parameter set</p>
        <div class="parameter-heading">
          <h2 id="selected-profile-title">${variantDisplay(state.variant)}</h2>
          <span class="category-badge">NIST category ${params.securityCategory}</span>
        </div>
        <p class="parameter-guidance"><strong>${params.profile}.</strong> ${params.guidance}</p>
        <p class="muted">${params.tradeoff}</p>
        <div class="sizes" aria-label="Selected parameter-set artifact sizes">
          <span>Public key ${params.publicKey} B</span>
          <span>Private key ${params.privateKey} B</span>
          <span>Ciphertext ${params.ciphertext} B</span>
          <span>Shared secret ${params.sharedSecret} B</span>
        </div>
        <p class="category-note"><strong>Read the category correctly:</strong> NIST security categories are comparison targets, not exact classical or quantum bit-strength measurements. Choose the category your protocol and threat model require—not simply the largest number.</p>
      </section>

      <div class="card">
        <h2>ML-KEM stepper</h2>
        <div class="stepper" role="list" aria-label="ML-KEM protocol steps">${stepDescriptions
          .map((step, index) => {
            const stepNo = index + 1;
            const status = stepNo < state.step ? 'done' : stepNo === state.step ? 'current' : 'todo';
            const ariaCurrent = status === 'current' ? ' aria-current="step"' : '';
            return `<div class="step ${status}" role="listitem"${ariaCurrent}>${step}</div>`;
          })
          .join('')}</div>
        <p id="kem-status" class="status" role="status" aria-live="polite">${escapeHtml(state.status)}</p>
        <div class="controls">
          <button id="prev-step" ${state.step === 1 ? 'disabled' : ''}>Prev</button>
          <button id="next-step">${state.step === 4 ? 'Run again' : 'Next'}</button>
        </div>
      </div>

      <div class="card grid-two">
        <div>
          <h3>Artifacts</h3>
          <p><strong>Public key</strong>: <code>${hexPreview(state.keyPair?.publicKey ?? null)}</code></p>
          <p><strong>Private key</strong>: <code>${hexPreview(state.keyPair?.privateKey ?? null)}</code></p>
          <p><strong>Ciphertext</strong>: <code>${hexPreview(state.encapsResult?.ciphertext ?? null)}</code></p>
          <p><strong>Alice secret</strong>: <code>${hexPreview(state.encapsResult?.sharedSecret ?? null)}</code></p>
          <p><strong>Bob secret</strong>: <code>${hexPreview(state.bobSecret)}</code></p>
        </div>
        <div>
          <h3>Timing</h3>
          <p>KeyGen: ${formatMs(state.timings.keygen)}</p>
          <p>Encaps: ${formatMs(state.timings.encaps)}</p>
          <p>Decaps: ${formatMs(state.timings.decaps)}</p>
        </div>
      </div>

      ${
        state.step === 4 && state.encapsResult && state.bobSecret
          ? `<div class="card">
              <h3>The payoff: the same secret on both ends</h3>
              ${renderSecretComparison(state.encapsResult.sharedSecret, state.bobSecret)}
            </div>`
          : ''
      }

      <div class="card">
        <h2>Full hybrid encryption (ML-KEM + AES-256-GCM)</h2>
        <p class="intro-note"><strong>Hybrid</strong> here means the KEM establishes a shared secret, then a fast symmetric cipher (AES-256-GCM) uses that secret to actually encrypt your message — a KEM alone only agrees a key, it does not encrypt data.</p>
        <p>Flow: Encaps -> <abbr title="HMAC-based Key Derivation Function (RFC 5869): derives a variant-bound AES key and gives this demo an explicit key schedule.">HKDF-SHA256</abbr>(salt=kyber-vault-v1) -> AES-256-GCM encrypt/decrypt.</p>
        <label for="hybrid-message" class="sr-only">Message to encrypt</label>
        <textarea id="hybrid-message" rows="4" placeholder="Enter a message to encrypt" aria-label="Message to encrypt"></textarea>
        <div class="controls">
          <button id="hybrid-encrypt">Encrypt message</button>
          <button id="hybrid-decrypt" ${state.hybridPayload ? '' : 'disabled'}>Decrypt message</button>
          <button id="hybrid-tamper" ${state.hybridPayload ? '' : 'disabled'}>Tamper with ML-KEM ciphertext</button>
        </div>
        <p><strong>Public key fingerprint</strong>: ${state.hybridPayload?.publicKeyFingerprint ?? '--'}</p>
        <p><strong>ML-KEM ciphertext</strong>: <code>${state.hybridPayload?.mlkemCiphertext.slice(0, 64) ?? '--'}</code></p>
        <p><strong>AES ciphertext</strong>: <code>${state.hybridPayload?.aesCiphertext.slice(0, 64) ?? '--'}</code></p>
        <p><strong>IV</strong>: <code>${state.hybridPayload?.aesIV ?? '--'}</code></p>
        <p><strong>Tag</strong>: <code>${state.hybridPayload?.aesTag ?? '--'}</code></p>
        <p class="ok-text" aria-live="polite">${state.hybridDecrypted ? `Decrypted plaintext: ${escapeHtml(state.hybridDecrypted)}` : ''}</p>
        <p id="hybrid-status" class="status" role="status" aria-live="polite">${escapeHtml(state.hybridNotice)}</p>
        <p class="bad-text" role="alert" aria-live="assertive">${escapeHtml(state.hybridError)}</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'lattice' ? 'visible' : ''}" id="panel-lattice" role="tabpanel" aria-labelledby="tab-lattice" ${state.activeTab !== 'lattice' ? 'hidden' : ''}>
      <div class="card model-boundary" aria-labelledby="model-boundary-heading">
        <p class="parameter-kicker">Model boundary</p>
        <h2 id="model-boundary-heading">Two primers, one real implementation</h2>
        <p>The KeyGen/Encaps/Decaps tab runs real FIPS 203 ML-KEM. The visualizations on this tab are deliberately tiny concept models; they do not execute ML-KEM's internal algorithms.</p>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Toy visualization and real ML-KEM parameter comparison">
          <table class="boundary-table">
            <thead><tr><th scope="col">Property</th><th scope="col">Scalar LWE primer</th><th scope="col">Cyclic NTT primer</th><th scope="col">Real FIPS 203 ML-KEM</th></tr></thead>
            <tbody>
              <tr><th scope="row">Algebra</th><td>Plain scalar equations A·s+e</td><td>${NTT_PRIMER_RING}</td><td>Module-LWE over Z<sub>3329</sub>[X]/(X<sup>256</sup>+1)</td></tr>
              <tr><th scope="row">Modulus q</th><td>${LWE_PRIMER_PARAMS.q}</td><td>${Q}</td><td>3329</td></tr>
              <tr><th scope="row">Dimension</th><td>${LWE_PRIMER_PARAMS.m}×${LWE_PRIMER_PARAMS.n} scalar matrix</td><td>${NTT_PRIMER_SIZE} coefficients</td><td>256 coefficients per polynomial</td></tr>
              <tr><th scope="row">Module rank k</th><td>Not applicable</td><td>Not applicable</td><td>2 / 3 / 4 for ML-KEM-512 / 768 / 1024</td></tr>
              <tr><th scope="row">Sampling</th><td>s,e use CBD η=${LWE_PRIMER_PARAMS.eta}</td><td>Display coefficients sampled from −4…4</td><td>CBD η<sub>1</sub>=3/2/2 and η<sub>2</sub>=2</td></tr>
              <tr><th scope="row">Random source</th><td><code>Math.random</code> for visualization only</td><td><code>Math.random</code> for visualization only</td><td>Browser <code>crypto.getRandomValues</code> in this implementation</td></tr>
              <tr><th scope="row">Purpose</th><td>Show why noise breaks exact solving</td><td>Show radix-2 butterflies and cyclic convolution</td><td>Actual standardized key encapsulation</td></tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <h2>Learning With Errors: the noise is the whole point</h2>
        <p>At an intuition level, ML-KEM relies on Module-LWE: structured polynomial equations hide a small secret behind noise. This scalar primer strips away the module and polynomial structure to show one idea only: exact linear algebra recovers s from <strong>b₀ = A·s</strong>, but the published <strong>b = A·s + e</strong> includes tiny noise <strong>e</strong>.</p>
        <p class="muted">Core ML-KEM modulus is q=${Q}; this panel uses q=${ILLUSTRATIVE_Q} and a ${LWE_DIM}×${LWE_DIM} system for readability only.</p>

        <h3>Public matrix A <span class="muted">(uniform random — no structure to see)</span></h3>
        <div class="matrix" role="img" aria-label="LWE public matrix A, ${state.lwe.m} rows by ${state.lwe.n} columns, uniform-random values mod ${ILLUSTRATIVE_Q}">${renderLweMatrix(state.lwe)}</div>

        <h3>Secret s <span class="muted">(what an attacker wants)</span></h3>
        <p class="vec-line"><code>s = [${state.lwe.s.join(', ')}]</code></p>

        <h3>Noise e <span class="muted">(small, and it changes everything)</span></h3>
        ${renderNoiseVector(state.lwe.e)}

        <h3>What the noise does to b</h3>
        ${renderBComparison(state.lwe)}
        <p class="muted">Cells highlighted in the published row are the ones e nudged away from the clean value.</p>
        <p>Verification: ${verifyLWEWithQ(state.lwe, ILLUSTRATIVE_Q) ? 'b = As + e (mod q) holds' : 'verification failed'}</p>

        <h3>Try to solve it by Gaussian elimination</h3>
        <p>Exact linear algebra over Z<sub>${ILLUSTRATIVE_Q}</sub> can invert A and recover s <em>if</em> the right-hand side is clean. Add the noise and the very same procedure returns garbage.</p>
        <div class="controls">
          <button id="solve-clean">Solve A·s = b₀ (clean)</button>
          <button id="solve-noisy">Solve A·s = b (published noisy)</button>
        </div>
        ${
          state.latticeSolve
            ? `<div class="solve-result ${state.latticeSolve.result.correct ? 'ok' : 'bad'}" role="status" aria-live="polite">
                ${
                  !state.latticeSolve.result.solvable
                    ? 'This random A was singular over the field — press "New random instance" and try again.'
                    : state.latticeSolve.mode === 'clean'
                      ? `Recovered s = [${state.latticeSolve.result.recovered!.map((value) => centeredRepresentative(value, ILLUSTRATIVE_Q)).join(', ')}] (Z₁₇ residues converted to centered representatives). ${
                          state.latticeSolve.result.correct
                            ? 'Exactly the true secret — with no noise, LWE is just linear algebra and falls instantly.'
                            : 'Unexpected mismatch on the clean system.'
                        }`
                      : `Recovered "s" = [${state.latticeSolve.result.recovered!.map((value) => centeredRepresentative(value, ILLUSTRATIVE_Q)).join(', ')}] (centered representatives). ${
                          state.latticeSolve.result.correct
                            ? '(This draw happened to survive — try a new instance.)'
                            : `The true secret was [${state.lwe.s.join(', ')}]. Exact elimination no longer recovers it; this illustrates the intuition behind LWE, not a security proof.`
                        }`
                }
              </div>`
            : ''
        }

        <div class="controls controls-spaced">
          <button id="new-lwe">New random instance</button>
          <button id="bruteforce">Count this toy search space</button>
        </div>
        <p class="status" role="status" aria-live="polite">${escapeHtml(state.latticeMessage)}</p>
      </div>

      <div class="card">
        <p class="standard-status standard-status-legacy">Concept primer · not ML-KEM's transform</p>
        <h2>Cyclic NTT polynomial multiplication</h2>
        <p>This panel computes an ${NTT_PRIMER_SIZE}-point radix-2 transform and cyclic convolution in ${NTT_PRIMER_RING}. It uses ML-KEM's modulus q=${Q} and a root derived from ζ=17 only to make the arithmetic recognizable.</p>
        <p class="honesty-note"><strong>Boundary:</strong> FIPS 203 uses a specialized incomplete transform for the negacyclic ring Z<sub>3329</sub>[X]/(X<sup>256</sup>+1), with 128 coefficient pairs and base-case polynomial multiplication. This primer's full transform plus scalar pointwise products is not Algorithms 9–11 of FIPS 203.</p>
        <div class="grid-two">
          <div>
            <h3>a(x)</h3>
            <code>[${state.nttA.join(', ')}]</code>
          </div>
          <div>
            <h3>b(x)</h3>
            <code>[${state.nttB.join(', ')}]</code>
          </div>
        </div>
        <div class="controls controls-spaced">
          <button id="ntt-run">Run cyclic NTT primer</button>
          <button id="ntt-new">New random polynomials</button>
        </div>
        ${state.nttResult ? `
        <div class="ntt-butterfly-walk">
          <h3>One butterfly at a time</h3>
          <p>The transform is nothing but this operation repeated. Step through NTT(a)'s butterflies and watch a single input pair combine into two outputs.</p>
          ${renderButterflyDiagram(
            state.nttResult.butterfliesA[
              Math.min(state.nttButterflyStep, state.nttResult.butterfliesA.length - 1)
            ],
            Math.min(state.nttButterflyStep, state.nttResult.butterfliesA.length - 1),
            state.nttResult.butterfliesA.length,
          )}
          <div class="controls">
            <button id="bf-prev" ${state.nttButterflyStep === 0 ? 'disabled' : ''}>Prev butterfly</button>
            <button id="bf-next" ${state.nttButterflyStep >= state.nttResult.butterfliesA.length - 1 ? 'disabled' : ''}>Next butterfly</button>
            <span class="bf-progress" aria-live="polite">Butterfly ${Math.min(state.nttButterflyStep, state.nttResult.butterfliesA.length - 1) + 1} of ${state.nttResult.butterfliesA.length}</span>
          </div>
        </div>
        <div class="ntt-result-grid">
          <div>
            <h3>NTT(a)</h3>
            <code>[${state.nttResult.nttA.join(', ')}]</code>
            <div class="ntt-butterflies" role="img" aria-label="All butterfly index pairs for polynomial a, grouped by layer">${renderButterflyTable(state.nttResult.butterfliesA)}</div>
          </div>
          <div>
            <h3>NTT(b)</h3>
            <code>[${state.nttResult.nttB.join(', ')}]</code>
            <div class="ntt-butterflies" role="img" aria-label="All butterfly index pairs for polynomial b, grouped by layer">${renderButterflyTable(state.nttResult.butterfliesB)}</div>
          </div>
        </div>
        <div>
          <h3>Pointwise NTT(a) ⊙ NTT(b)</h3>
          <code>[${state.nttResult.pointwise.join(', ')}]</code>
        </div>
        <div>
          <h3>INTT → product</h3>
          <code>[${state.nttResult.result.join(', ')}]</code>
        </div>
        <div class="match ${state.nttSchoolbook && state.nttResult.result.every((v, i) => v === state.nttSchoolbook![i]) ? 'ok' : 'bad'}" role="alert">
          Schoolbook check: [${(state.nttSchoolbook ?? []).join(', ')}]
          — ${state.nttSchoolbook && state.nttResult.result.every((v, i) => v === state.nttSchoolbook![i]) ? 'Results match (NTT = schoolbook)' : 'Mismatch'}
        </div>
        <p>NTT uses <strong>${state.nttResult.butterfliesA.length}</strong> butterfly ops per polynomial (O(n log n)) vs <strong>${state.nttA.length * state.nttA.length}</strong> multiplications for schoolbook (O(n²)).</p>
        <p class="honesty-note"><strong>What the match proves:</strong> this cyclic transform agrees with schoolbook multiplication in X<sup>${NTT_PRIMER_SIZE}</sup>−1. It does not validate ML-KEM's incomplete negacyclic NTT or its base-case multiplication.</p>
        ` : ''}
      </div>
    </section>

    <section class="panel ${state.activeTab === 'params' ? 'visible' : ''}" id="panel-params" role="tabpanel" aria-labelledby="tab-params" ${state.activeTab !== 'params' ? 'hidden' : ''}>
      <div class="grid-three">
        ${VARIANTS.map((variant) => {
          const p = ML_KEM_PARAMS[variant];
          return `<article class="card clickable ${state.variant === variant ? 'selected-parameter' : ''}" data-go-variant="${variant}" role="button" tabindex="0" aria-label="Select ${variantDisplay(variant)} and go to Encapsulate tab">
            <h3>${variantDisplay(variant)}</h3>
            <p class="parameter-profile"><strong>${p.profile}</strong></p>
            <p>NIST security category ${p.securityCategory}</p>
            <p>Public key: ${p.publicKey} bytes</p>
            <p>Private key: ${p.privateKey} bytes</p>
            <p>Ciphertext: ${p.ciphertext} bytes</p>
            <p class="muted">${p.guidance}</p>
            <div class="bar bar-${variant}" role="img" aria-label="Relative key size: ${Math.round((p.publicKey / 1568) * 100)}%"></div>
          </article>`;
        }).join('')}
      </div>
      <div class="card category-explainer">
        <h3>Category is a requirement, not a scoreboard</h3>
        <p>FIPS 203 assigns categories 1, 3, and 5 as standardized comparison targets. They are not exact bit-strength claims. A higher category increases keys and ciphertexts, so select the smallest profile that satisfies the protocol, data lifetime, and compliance requirement.</p>
      </div>
      <div class="card provenance-card">
        <div class="provenance-heading">
          <div>
            <p class="parameter-kicker">Primary-source evidence</p>
            <h3>Deployment examples: final ML-KEM vs earlier Kyber</h3>
          </div>
          <p class="review-date"><strong>Last reviewed</strong><time datetime="2026-09-19">September 19, 2026</time></p>
        </div>
        <div class="deployment-grid">
          <section class="deployment-example">
            <p class="standard-status standard-status-final">Final standard</p>
            <h4>ML-KEM (FIPS 203)</h4>
            <p><a href="https://www.openssh.com/releasenotes.html#9.9" target="_blank" rel="noopener noreferrer">OpenSSH 9.9 release notes</a> document the hybrid <code>mlkem768x25519-sha256</code> key exchange, combining FIPS 203 ML-KEM with X25519. OpenSSH 10.0 made it the default.</p>
          </section>
          <section class="deployment-example">
            <p class="standard-status standard-status-legacy">Pre-standard lineage</p>
            <h4>CRYSTALS-Kyber variants</h4>
            <p><a href="https://security.apple.com/blog/imessage-pq3/" target="_blank" rel="noopener noreferrer">Apple's PQ3 design</a> specifies Kyber-1024, while the <a href="https://signal.org/docs/specifications/pqxdh/" target="_blank" rel="noopener noreferrer">Signal PQXDH specification</a> gives CRYSTALS-KYBER-1024 as its concrete example.</p>
          </section>
        </div>
        <p class="honesty-note"><strong>Names are not interchangeable:</strong> final FIPS 203 ML-KEM changed details from the pre-standard CRYSTALS-Kyber lineage. Do not assume their keys, ciphertexts, or protocol encodings are byte-compatible.</p>
      </div>
      <div class="card source-status" aria-labelledby="source-status-heading">
        <div class="provenance-heading">
          <div>
            <p class="parameter-kicker">Provenance &amp; freshness</p>
            <h3 id="source-status-heading">Standards status</h3>
          </div>
          <p class="review-date"><strong>Last reviewed</strong><time datetime="2026-09-19">September 19, 2026</time></p>
        </div>
        <p class="errata-notice"><strong>Open errata notice:</strong> NIST's November 17, 2025 planning note says an issue in FIPS 203 will be corrected in a future update or revision. This demo tracks the currently published final standard and links the live notice so readers can verify its status.</p>
        <ul class="source-list">
          <li><a href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank" rel="noopener noreferrer">NIST FIPS 203 publication and current errata notice</a></li>
          <li><a href="https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files" target="_blank" rel="noopener noreferrer">Pinned NIST ACVP known-answer source at commit <code>975de31…</code></a></li>
          <li><a href="https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html" target="_blank" rel="noopener noreferrer">NIST ACVP ML-KEM test specification</a></li>
        </ul>
      </div>
      <div class="card implementation-card" aria-labelledby="implementation-heading">
        <p class="parameter-kicker">Runtime disclosure</p>
        <h3 id="implementation-heading">What exactly runs here</h3>
        <dl class="implementation-grid">
          <div>
            <dt>ML-KEM library</dt>
            <dd><a href="https://github.com/paulmillr/noble-post-quantum" target="_blank" rel="noopener noreferrer"><code>${CRYPTO_IMPLEMENTATION.library}@${CRYPTO_IMPLEMENTATION.version}</code></a>, exactly pinned by the lockfile</dd>
          </div>
          <div>
            <dt>Execution backend</dt>
            <dd>${CRYPTO_IMPLEMENTATION.backend}</dd>
          </div>
          <div>
            <dt>Entropy</dt>
            <dd>Key generation, encapsulation, and IV creation use the browser CSPRNG through <code>crypto.getRandomValues</code>. The app fails closed when Web Crypto is unavailable.</dd>
          </div>
          <div>
            <dt>Network boundary</dt>
            <dd>Cryptographic operations happen locally. CSP <code>connect-src 'none'</code> blocks runtime network requests; generated keys remain in this page's JavaScript memory.</dd>
          </div>
        </dl>
        <div class="assurance-limits" aria-label="Implementation assurance limits">
          <p><strong>No independent audit:</strong> upstream reports a self-audit at version 0.6.1 in April 2026, not an independent audit. This site ships 0.7.1, which includes later changes.</p>
          <p><strong>No constant-time claim:</strong> JavaScript engines, JIT compilation, garbage collection, and browser scheduling prevent a formal constant-time guarantee.</p>
          <p><strong>No guaranteed secret erasure:</strong> upstream wipes selected temporary arrays, but this demo retains working keys in application state and cannot guarantee removal of copies from a garbage-collected browser heap.</p>
          <p><strong>No peer authentication:</strong> this teaching flow does not authenticate Bob's public key or Alice's identity. A real protocol must bind keys to identities to prevent active key-substitution attacks.</p>
          <p><strong>No certification:</strong> pinned NIST vectors demonstrate tested behavior; they do not make the library, browser, or demo a FIPS-validated cryptographic module.</p>
        </div>
        <details class="integrity-receipt">
          <summary>Show the locked npm artifact receipt</summary>
          <p><code>${CRYPTO_IMPLEMENTATION.integrity}</code></p>
        </details>
        <p class="production-warning"><strong>Educational use only:</strong> use a reviewed, supported, side-channel-hardened implementation and an authenticated protocol design for production systems.</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'compare' ? 'visible' : ''}" id="panel-compare" role="tabpanel" aria-labelledby="tab-compare" ${state.activeTab !== 'compare' ? 'hidden' : ''}>
      <div class="card">
        <h2>KEM vs key exchange</h2>
        <p>X25519 is classical ECDH, while ML-KEM is a post-quantum key encapsulation mechanism. Hybrid migration combines X25519 + ML-KEM to hedge against both quantum and implementation risk.</p>
      </div>
      <div class="card wire-cost-card">
        <p class="parameter-kicker">Comparable payload accounting</p>
        <h3>Fresh key-establishment wire cost</h3>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Fresh key establishment wire cost comparison">
        <table>
          <thead>
            <tr><th scope="col">Construction</th><th scope="col">Recipient advertisement</th><th scope="col">Initiator response</th><th scope="col">Total key material</th><th scope="col">Security role</th></tr>
          </thead>
          <tbody>
            <tr><th scope="row">X25519 ephemeral ECDH</th><td>32 B public share</td><td>32 B public share</td><td><strong>64 B</strong></td><td>Classical only</td></tr>
            ${VARIANTS.map((variant) => {
              const p = ML_KEM_PARAMS[variant];
              return `<tr><th scope="row">${variantDisplay(variant)}</th><td>${p.publicKey} B encapsulation key</td><td>${p.ciphertext} B ciphertext</td><td><strong>${p.publicKey + p.ciphertext} B</strong></td><td>NIST category ${p.securityCategory}</td></tr>`;
            }).join('')}
            <tr><th scope="row">X25519 + ML-KEM-768</th><td>1216 B (32 + 1184)</td><td>1120 B (32 + 1088)</td><td><strong>2336 B</strong></td><td>Hybrid classical + category 3</td></tr>
          </tbody>
        </table>
        </div>
        <p class="muted">Construction-level bytes only: one fresh public contribution from each side, excluding protocol framing, algorithm identifiers, certificates, signatures, record headers, and retransmission. With a cached ML-KEM public key, the online payload is only the ciphertext column.</p>
      </div>
      <div class="card benchmark-card">
        <p class="parameter-kicker">Reproducible local measurement</p>
        <h3>Browser benchmark</h3>
        <p>Each operation gets ${BENCHMARK_WARMUP_ITERATIONS} unmeasured warm-up runs followed by ${BENCHMARK_MEASURED_ITERATIONS} individually timed samples. The summary reports median and nearest-rank p95 wall-clock latency; raw samples and environment metadata are exportable.</p>
        <button id="run-benchmark" ${state.benchmarkRunning ? 'disabled' : ''}>Run benchmark</button>
        <p class="benchmark-progress" aria-live="polite">${escapeHtml(state.benchmarkProgress)}</p>
        ${
          state.benchmark
            ? `<div class="benchmark-environment" aria-label="Benchmark environment">
                <p><strong>Captured</strong><time datetime="${state.benchmark.environment.generatedAt}">${escapeHtml(state.benchmark.environment.generatedAt)}</time></p>
                <p><strong>Implementation</strong><code>${escapeHtml(state.benchmark.environment.implementation)}</code></p>
                <p><strong>Platform</strong>${escapeHtml(state.benchmark.environment.platform)}</p>
                <p><strong>Logical CPUs</strong>${state.benchmark.environment.hardwareConcurrency ?? 'not reported'}</p>
                <p><strong>Cross-origin isolated</strong>${state.benchmark.environment.crossOriginIsolated ? 'yes' : 'no'}</p>
              </div>
              <div class="table-scroll" tabindex="0" role="region" aria-label="Benchmark latency results">
              <table class="benchmark-results">
          <thead>
            <tr><th scope="col">Scheme</th><th scope="col">Operation</th><th scope="col">Median</th><th scope="col">p95</th><th scope="col">Median rate</th><th scope="col">Samples</th></tr>
          </thead>
          <tbody>
            ${state.benchmark.variants
              .flatMap((row) => [
                renderTimingRow(variantDisplay(row.variant), 'KeyGen', row.keygen),
                renderTimingRow(variantDisplay(row.variant), 'Encaps', row.encaps),
                renderTimingRow(variantDisplay(row.variant), 'Decaps', row.decaps),
              ])
              .join('')}
            ${state.benchmark.x25519
              ? `${renderTimingRow('X25519 Web Crypto', 'KeyGen', state.benchmark.x25519.keygen)}${renderTimingRow('X25519 Web Crypto', 'deriveBits', state.benchmark.x25519.derive)}`
              : '<tr><th scope="row">X25519 Web Crypto</th><td colspan="5">Not available in this browser runtime</td></tr>'}
          </tbody>
        </table></div>
        <div class="controls controls-spaced">
          <button id="download-benchmark-json">Download raw JSON</button>
          <button id="download-benchmark-csv">Download raw CSV</button>
        </div>
        <details class="benchmark-method">
          <summary>Method and interpretation limits</summary>
          <p>The timer wraps each awaited operation with <code>performance.now()</code>. Setup data is prepared outside measured regions. ML-KEM reuses one key/ciphertext per operation class; X25519 separately measures native key generation and <code>deriveBits</code>.</p>
          <p>User agent: <code>${escapeHtml(state.benchmark.environment.userAgent)}</code></p>
          <p>These are measurements of this browser session, not portable algorithm rankings. CPU power state, JIT, browser load, timer precision, and the pure-JavaScript versus native Web Crypto backends all affect results.</p>
        </details>`
            : ''
        }
        <p class="honesty-note"><strong>Interpret carefully:</strong> ML-KEM runs here as portable JavaScript while X25519 runs in the browser's native Web Crypto backend. Compare operations within this session; do not generalize this chart to optimized native libraries or other devices.</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'how' ? 'visible' : ''}" id="panel-how" role="tabpanel" aria-labelledby="tab-how" ${state.activeTab !== 'how' ? 'hidden' : ''}>
      <div class="card">
        <h2>How LWE works</h2>
        <p>Five steps take you from "noisy equations" to a quantum-safe KEM. Each step below can be expanded for a plain-English explanation of the jargon.</p>
        <div class="stepper" role="list" aria-label="LWE concept steps">
          <div class="step ${state.learnStep === 1 ? 'current' : ''}" role="listitem"${state.learnStep === 1 ? ' aria-current="step"' : ''}>
            <span class="step-head">1. LWE setup: publish A and b = A·s + e (mod q).</span>
            <details><summary>What this means</summary><p>You reveal a random matrix A and a vector b. Anyone can see them. The secret s is hidden inside b, but b has been blurred by a small noise vector e. Recovering s from (A, b) is the Learning-With-Errors problem — believed hard even for quantum computers.</p></details>
          </div>
          <div class="step ${state.learnStep === 2 ? 'current' : ''}" role="listitem"${state.learnStep === 2 ? ' aria-current="step"' : ''}>
            <span class="step-head">2. Noise masks the linear structure and blocks direct solving.</span>
            <details><summary>What this means</summary><p>Without e, solving A·s = b is high-school linear algebra (Gaussian elimination). The tiny errors in e mean no exact solution matches, and rounding to "the nearest small s" is exactly the hard lattice problem. The Lattice tab lets you run this and watch it fail.</p></details>
          </div>
          <div class="step ${state.learnStep === 3 ? 'current' : ''}" role="listitem"${state.learnStep === 3 ? ' aria-current="step"' : ''}>
            <span class="step-head">3. Build public-key encryption by hiding message bits in noisy equations.</span>
            <details><summary>What this means</summary><p>To encrypt a bit, you add it (scaled by q/2) to a fresh noisy LWE sample. The holder of s can subtract the predictable part and read the bit through the noise; an attacker cannot. This is the LPR/Regev public-key encryption scheme underneath Kyber.</p></details>
          </div>
          <div class="step ${state.learnStep === 4 ? 'current' : ''}" role="listitem"${state.learnStep === 4 ? ' aria-current="step"' : ''}>
            <span class="step-head">4. <abbr title="Module Learning With Errors">Module-LWE</abbr> upgrades scalars to polynomials in Z<sub>q</sub>[X]/(X<sup>256</sup>+1), q=3329.</span>
            <details><summary>What this means</summary><p>Instead of vectors of numbers, Kyber works with small vectors (a "module") of degree-256 polynomials. This keeps keys small and lets the NTT multiply them fast, while a structured-lattice hardness assumption still holds. <abbr title="Centered Binomial Distribution">CBD</abbr> sampling is how the small noise polynomials are drawn.</p></details>
          </div>
          <div class="step ${state.learnStep === 5 ? 'current' : ''}" role="listitem"${state.learnStep === 5 ? ' aria-current="step"' : ''}>
            <span class="step-head">5. The Fujisaki-Okamoto transform upgrades the PKE to an IND-CCA2 KEM.</span>
            <details><summary>What this means</summary><p>The raw encryption is only safe against a passive attacker. The FO transform re-encrypts during decapsulation and rejects anything that doesn't match, closing off chosen-ciphertext attacks — the IND-CCA2 security level a real KEM needs.</p></details>
          </div>
        </div>
        <div class="controls">
          <button id="learn-prev" ${state.learnStep === 1 ? 'disabled' : ''}>Prev concept</button>
          <button id="learn-next" ${state.learnStep === 5 ? 'disabled' : ''}>Next concept</button>
        </div>

        <h3>Jargon, unpacked</h3>
        <div class="glossary">
          <details><summary>HKDF-SHA256</summary><p>HMAC-based Key Derivation Function (RFC 5869). ML-KEM already outputs 32 bytes of shared secret; this demo runs it through HKDF to give the AES key an explicit, variant-bound context and a clear key schedule. That is protocol domain separation, not a claim that ML-KEM's output lacks uniformity.</p></details>
          <details><summary>IND-CCA2</summary><p>Indistinguishability under adaptive Chosen-Ciphertext Attack — the gold-standard security goal. It means that even an attacker allowed to submit crafted ciphertexts to a decryption oracle learns nothing about a target message. ML-KEM targets this level; the FO transform is how it gets there.</p></details>
          <details><summary>Fujisaki-Okamoto (FO) transform</summary><p>A generic recipe that turns a merely-passively-secure public-key encryption scheme into an actively-secure KEM by making decapsulation re-encrypt and verify. If verification fails it returns a pseudorandom secret ("implicit rejection") instead of an error, so failures leak nothing.</p></details>
          <details><summary>Module-LWE</summary><p>The specific hardness assumption Kyber rests on: LWE where the entries are small polynomials in a ring, arranged in a low-dimensional module. It sits between plain LWE (very conservative, big keys) and Ring-LWE (compact, more structure), trading a little structure for much smaller keys.</p></details>
        </div>

        <blockquote>
          "ML-KEM is intended to provide protection for sensitive information that may be at risk from a future quantum computer." - NIST FIPS 203
        </blockquote>
        <p>Attribution: CRYSTALS-Kyber authors, standardized by NIST in August 2024.</p>
        <p>Portfolio link: ML-KEM for key agreement + iron-serpent (Serpent-256-CTR) for data encryption forms a complete hybrid encryption system.</p>
      </div>
    </section>
  </main>
  `;

  const textarea = appRoot.querySelector<HTMLTextAreaElement>('#hybrid-message');
  if (textarea) {
    textarea.value = state.message;
    textarea.addEventListener('input', () => {
      state.message = textarea.value;
    });
  }

  appRoot.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      state.activeTab = button.dataset.tab as TabId;
      render();
    });
  });

  // ARIA tablist keyboard support: Arrow keys, Home, and End move between tabs.
  const tablist = appRoot.querySelector<HTMLElement>('.tabs');
  if (tablist) {
    tablist.addEventListener('keydown', (event: KeyboardEvent) => {
      const currentIndex = TABS.findIndex((tab) => tab.id === state.activeTab);
      let nextIndex = currentIndex;
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        nextIndex = (currentIndex + 1) % TABS.length;
      } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        nextIndex = (currentIndex - 1 + TABS.length) % TABS.length;
      } else if (event.key === 'Home') {
        nextIndex = 0;
      } else if (event.key === 'End') {
        nextIndex = TABS.length - 1;
      } else {
        return;
      }
      event.preventDefault();
      state.activeTab = TABS[nextIndex].id;
      pendingTabFocus = true;
      render();
    });
  }

  appRoot.querySelectorAll<HTMLButtonElement>('[data-variant]').forEach((button) => {
    button.addEventListener('click', () => {
      const nextVariant = button.dataset.variant as MLKEMVariant;
      if (nextVariant !== state.variant) {
        state.variant = nextVariant;
        resetFlow();
      }
      render();
    });
  });

  appRoot.querySelectorAll<HTMLElement>('[data-go-variant]').forEach((card) => {
    const handler = () => {
      const nextVariant = card.dataset.goVariant as MLKEMVariant;
      state.variant = nextVariant;
      state.activeTab = 'encaps';
      resetFlow();
      render();
    };
    card.addEventListener('click', handler);
    card.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler();
      }
    });
  });

  const nextStepButton = appRoot.querySelector<HTMLButtonElement>('#next-step');
  if (nextStepButton) {
    nextStepButton.addEventListener('click', async () => {
      try {
        if (state.step === 4) {
          resetFlow();
        } else {
          await runNextStep();
        }
      } catch (error) {
        state.status = `Operation failed: ${(error as Error).message}`;
      }
      render();
    });
  }

  const prevStepButton = appRoot.querySelector<HTMLButtonElement>('#prev-step');
  if (prevStepButton) {
    prevStepButton.addEventListener('click', () => {
      if (state.step === 4) {
        state.bobSecret = null;
        state.timings.decaps = undefined;
      } else if (state.step === 3) {
        state.encapsResult = null;
        state.bobSecret = null;
        state.timings.encaps = undefined;
        state.timings.decaps = undefined;
      } else if (state.step === 2) {
        state.keyPair = null;
        state.encapsResult = null;
        state.bobSecret = null;
        state.timings = {};
      }
      state.step = Math.max(1, state.step - 1);
      state.status = `Moved to step ${state.step}.`;
      render();
    });
  }

  const encryptButton = appRoot.querySelector<HTMLButtonElement>('#hybrid-encrypt');
  if (encryptButton) {
    encryptButton.addEventListener('click', async () => {
      try {
        if (!state.keyPair) {
          const t0 = performance.now();
          state.keyPair = await generateKeyPair(state.variant);
          state.timings.keygen = performance.now() - t0;
          state.step = Math.max(state.step, 2);
        }
        state.hybridPayload = await hybridEncrypt(state.message, state.keyPair.publicKey, state.variant);
        state.hybridDecrypted = '';
        state.hybridNotice = 'Fresh ciphertext created. Decrypt to run authentication.';
        state.hybridError = '';
      } catch (error) {
        state.hybridNotice = '';
        state.hybridError = (error as Error).message;
      }
      render();
    });
  }

  const decryptButton = appRoot.querySelector<HTMLButtonElement>('#hybrid-decrypt');
  if (decryptButton) {
    decryptButton.addEventListener('click', async () => {
      try {
        if (!state.hybridPayload || !state.keyPair) {
          throw new Error('Generate keys and encrypt first');
        }
        state.hybridDecrypted = await hybridDecrypt(state.hybridPayload, state.keyPair.privateKey);
        state.hybridNotice = 'Authentication passed during this decryption.';
        state.hybridError = '';
      } catch (error) {
        state.hybridNotice = '';
        state.hybridError = (error as Error).message;
        state.hybridDecrypted = '';
      }
      render();
    });
  }

  const tamperButton = appRoot.querySelector<HTMLButtonElement>('#hybrid-tamper');
  if (tamperButton) {
    tamperButton.addEventListener('click', () => {
      if (!state.hybridPayload) {
        return;
      }
      state.hybridPayload = {
        ...state.hybridPayload,
        mlkemCiphertext: flipBase64Byte(state.hybridPayload.mlkemCiphertext, 3),
      };
      state.hybridNotice = 'Ciphertext changed. Authentication has not run yet; click Decrypt message to test it.';
      state.hybridError = '';
      state.hybridDecrypted = '';
      render();
    });
  }

  const newLweButton = appRoot.querySelector<HTMLButtonElement>('#new-lwe');
  if (newLweButton) {
    newLweButton.addEventListener('click', () => {
      state.lwe = generateIllustrativeLWEInstance(LWE_DIM, LWE_DIM, ILLUSTRATIVE_Q);
      state.latticeSolve = null;
      state.latticeMessage = 'Generated a new random A, s, e, and b over q=17.';
      render();
    });
  }

  const solveCleanButton = appRoot.querySelector<HTMLButtonElement>('#solve-clean');
  if (solveCleanButton) {
    solveCleanButton.addEventListener('click', () => {
      const result = gaussianSolve(state.lwe.A, cleanB(state.lwe, ILLUSTRATIVE_Q), state.lwe.s, ILLUSTRATIVE_Q);
      state.latticeSolve = { mode: 'clean', result };
      render();
    });
  }

  const solveNoisyButton = appRoot.querySelector<HTMLButtonElement>('#solve-noisy');
  if (solveNoisyButton) {
    solveNoisyButton.addEventListener('click', () => {
      const result = gaussianSolve(state.lwe.A, state.lwe.b, state.lwe.s, ILLUSTRATIVE_Q);
      state.latticeSolve = { mode: 'noisy', result };
      render();
    });
  }

  const bruteForceButton = appRoot.querySelector<HTMLButtonElement>('#bruteforce');
  if (bruteForceButton) {
    bruteForceButton.addEventListener('click', () => {
      state.latticeMessage = bruteForceSearchSpace(
        LWE_DIM,
        ILLUSTRATIVE_Q,
        LWE_PRIMER_PARAMS.eta,
      );
      render();
    });
  }

  const nttRunButton = appRoot.querySelector<HTMLButtonElement>('#ntt-run');
  if (nttRunButton) {
    nttRunButton.addEventListener('click', () => {
      state.nttResult = polyMultiplyNTT(state.nttA, state.nttB);
      state.nttSchoolbook = polyMultiplySchoolbook(state.nttA, state.nttB);
      state.nttButterflyStep = 0;
      render();
    });
  }

  const nttNewButton = appRoot.querySelector<HTMLButtonElement>('#ntt-new');
  if (nttNewButton) {
    nttNewButton.addEventListener('click', () => {
      state.nttA = randomSmallPoly(NTT_PRIMER_SIZE);
      state.nttB = randomSmallPoly(NTT_PRIMER_SIZE);
      state.nttResult = null;
      state.nttSchoolbook = null;
      state.nttButterflyStep = 0;
      render();
    });
  }

  const bfPrevButton = appRoot.querySelector<HTMLButtonElement>('#bf-prev');
  if (bfPrevButton) {
    bfPrevButton.addEventListener('click', () => {
      state.nttButterflyStep = Math.max(0, state.nttButterflyStep - 1);
      render();
    });
  }

  const bfNextButton = appRoot.querySelector<HTMLButtonElement>('#bf-next');
  if (bfNextButton) {
    bfNextButton.addEventListener('click', () => {
      const max = (state.nttResult?.butterfliesA.length ?? 1) - 1;
      state.nttButterflyStep = Math.min(max, state.nttButterflyStep + 1);
      render();
    });
  }

  const runBenchmarkButton = appRoot.querySelector<HTMLButtonElement>('#run-benchmark');
  if (runBenchmarkButton) {
    runBenchmarkButton.addEventListener('click', async () => {
      state.benchmarkRunning = true;
      state.benchmarkProgress = 'Starting benchmark...';
      state.benchmark = null;
      render();
      try {
        state.benchmark = await runBenchmark((progress) => {
          state.benchmarkProgress = progress;
          const progressNode = appRoot.querySelector('section.panel.visible #run-benchmark + p');
          if (progressNode) {
            progressNode.textContent = progress;
          }
        });
      } catch (error) {
        state.benchmarkProgress = `Benchmark failed: ${(error as Error).message}`;
      }
      state.benchmarkRunning = false;
      render();
    });
  }

  const downloadBenchmarkJson = appRoot.querySelector<HTMLButtonElement>('#download-benchmark-json');
  if (downloadBenchmarkJson && state.benchmark) {
    downloadBenchmarkJson.addEventListener('click', () => {
      downloadText(
        'kyber-vault-benchmark.json',
        benchmarkReportToJson(state.benchmark!),
        'application/json',
      );
    });
  }

  const downloadBenchmarkCsv = appRoot.querySelector<HTMLButtonElement>('#download-benchmark-csv');
  if (downloadBenchmarkCsv && state.benchmark) {
    downloadBenchmarkCsv.addEventListener('click', () => {
      downloadText(
        'kyber-vault-benchmark.csv',
        benchmarkReportToCsv(state.benchmark!),
        'text/csv',
      );
    });
  }

  const learnPrev = appRoot.querySelector<HTMLButtonElement>('#learn-prev');
  if (learnPrev) {
    learnPrev.addEventListener('click', () => {
      state.learnStep = Math.max(1, state.learnStep - 1);
      render();
    });
  }

  const learnNext = appRoot.querySelector<HTMLButtonElement>('#learn-next');
  if (learnNext) {
    learnNext.addEventListener('click', () => {
      state.learnStep = Math.min(5, state.learnStep + 1);
      render();
    });
  }

  if (pendingTabFocus) {
    pendingTabFocus = false;
    appRoot.querySelector<HTMLButtonElement>(`#tab-${state.activeTab}`)?.focus();
  }
}

render();
