import './style.css';
import { runBenchmark, type BenchmarkReport } from './benchmark';
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
import {
  Q,
  bruteForceSearchSpace,
  generateIllustrativeLWEInstance,
  type LWEInstance,
  verifyLWEWithQ,
} from './crypto/lwe';
import {
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

const VARIANTS: MLKEMVariant[] = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];
const ILLUSTRATIVE_Q = 17;

const TABS: { id: TabId; label: string }[] = [
  { id: 'encaps', label: 'Encapsulate / Decapsulate' },
  { id: 'lattice', label: 'Lattice visualizer' },
  { id: 'params', label: 'Parameter sets' },
  { id: 'compare', label: 'vs X25519 / RSA' },
  { id: 'how', label: 'How LWE works' },
];

// When a tab is changed via keyboard, move focus to it after the next render.
let pendingTabFocus = false;

type Theme = 'dark' | 'light';

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
  hybridError: string;
  lwe: LWEInstance;
  latticeMessage: string;
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
  hybridError: '',
  lwe: generateIllustrativeLWEInstance(6, 4, ILLUSTRATIVE_Q),
  latticeMessage: 'Educational instance uses q=17. Core ML-KEM uses q=3329.',
  nttA: randomSmallPoly(8),
  nttB: randomSmallPoly(8),
  nttResult: null,
  nttSchoolbook: null,
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

function formatOps(value: number): string {
  return `${value.toFixed(1)} ops/s`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getTheme(): Theme {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function setTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  const themeColor = document.querySelector<HTMLMetaElement>('#theme-color-meta');
  if (themeColor) {
    themeColor.content = theme === 'light' ? '#f3f8ff' : '#06090f';
  }
}

function getThemeToggleMeta(theme: Theme): { icon: string; label: string } {
  if (theme === 'dark') {
    return { icon: '🌙', label: 'Switch to light mode' };
  }
  return { icon: '☀️', label: 'Switch to dark mode' };
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
  return instance.A
    .map(
      (row) =>
        `<div class="matrix-row">${row
          .map((value) => {
            const intensity = Math.round((value / ILLUSTRATIVE_Q) * 100);
            return `<span class="cell" title="A[i][j] = ${value} mod ${ILLUSTRATIVE_Q}" style="--intensity:${intensity}%">${value}</span>`;
          })
          .join('')}</div>`,
    )
    .join('');
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
  const theme = getTheme();
  const themeToggle = getThemeToggleMeta(theme);
  const sharedSecretsMatch =
    state.encapsResult && state.bobSecret
      ? toHex(state.encapsResult.sharedSecret) === toHex(state.bobSecret)
      : false;
  const stepDescriptions = [
    '1. KeyGen (Bob) - Bob creates ML-KEM keypair.',
    '2. Encaps (Alice) - Alice derives shared secret + ciphertext.',
    '3. Decaps (Bob) - Bob recovers shared secret from ciphertext.',
    '4. Key agreement complete - secrets must match exactly.',
  ];

  appRoot.innerHTML = `
  <main class="shell">
    <header class="hero-header">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="${themeToggle.label}">${themeToggle.icon}</button>
      <p class="eyebrow">crypto-compare demo</p>
      <h1>ML-KEM (CRYSTALS-Kyber) vault</h1>
      <p class="subhead">NIST FIPS 203 standardizes post-quantum key encapsulation for real-world deployment.</p>
    </header>

    <nav class="tabs" role="tablist" aria-label="Demo sections">
      ${TABS.map(
        (tab) =>
          `<button class="tab ${state.activeTab === tab.id ? 'active' : ''}" data-tab="${tab.id}" role="tab" aria-selected="${state.activeTab === tab.id}" aria-controls="panel-${tab.id}" id="tab-${tab.id}" tabindex="${state.activeTab === tab.id ? '0' : '-1'}">${tab.label}</button>`,
      ).join('')}
    </nav>

    <section class="panel ${state.activeTab === 'encaps' ? 'visible' : ''}" id="panel-encaps" role="tabpanel" aria-labelledby="tab-encaps" ${state.activeTab !== 'encaps' ? 'hidden' : ''}>
      <div class="pill-row">
        ${VARIANTS.map(
          (variant) =>
            `<button class="pill ${state.variant === variant ? 'active' : ''}" data-variant="${variant}" aria-pressed="${state.variant === variant}">${variantDisplay(variant)}</button>`,
        ).join('')}
      </div>

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
        <p class="status" role="status" aria-live="polite">${escapeHtml(state.status)}</p>
        <div class="controls">
          <button id="prev-step" ${state.step === 1 ? 'disabled' : ''}>Prev</button>
          <button id="next-step">${state.step === 4 ? 'Run again' : 'Next'}</button>
        </div>
        <div class="sizes">
          <span>PK ${params.publicKey} B</span>
          <span>SK ${params.privateKey} B</span>
          <span>CT ${params.ciphertext} B</span>
          <span>SS ${params.sharedSecret} B</span>
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
          ${
            state.step === 4
              ? `<div class="match ${sharedSecretsMatch ? 'ok' : 'bad'}" role="alert">${
                  sharedSecretsMatch ? 'Shared secrets match' : 'Shared secrets differ'
                }</div>`
              : ''
          }
        </div>
      </div>

      <div class="card">
        <h2>Full hybrid encryption (ML-KEM + AES-256-GCM)</h2>
        <p>Flow: Encaps -> HKDF-SHA256(salt=kyber-vault-v1) -> AES-256-GCM encrypt/decrypt.</p>
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
        <p class="bad-text" role="alert" aria-live="assertive">${escapeHtml(state.hybridError)}</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'lattice' ? 'visible' : ''}" id="panel-lattice" role="tabpanel" aria-labelledby="tab-lattice" ${state.activeTab !== 'lattice' ? 'hidden' : ''}>
      <div class="card">
        <h2>Lattice visualizer (illustrative)</h2>
        <p>${escapeHtml(state.latticeMessage)}</p>
        <p>Core ML-KEM modulus is q=${Q}; this panel uses q=${ILLUSTRATIVE_Q} for readability only.</p>
        <div class="matrix" role="img" aria-label="LWE public matrix A, ${state.lwe.m} rows by ${state.lwe.n} columns, values mod ${ILLUSTRATIVE_Q}">${renderLweMatrix(state.lwe)}</div>
        <p><strong>s</strong> = [${state.lwe.s.join(', ')}]</p>
        <p><strong>e</strong> = [${state.lwe.e.join(', ')}]</p>
        <p><strong>b</strong> = [${state.lwe.b.join(', ')}]</p>
        <p>Verification: ${verifyLWEWithQ(state.lwe, ILLUSTRATIVE_Q) ? 'b = As + e (mod q) holds' : 'verification failed'}</p>
        <div class="controls">
          <button id="new-lwe">New random instance</button>
          <button id="bruteforce">Show why brute force fails</button>
        </div>
      </div>

      <div class="card">
        <h2>NTT polynomial multiplication</h2>
        <p>Kyber multiplies polynomials in Z<sub>${Q}</sub>[X]/(X<sup>256</sup>+1) using the <strong>Number Theoretic Transform</strong> — an FFT over a finite field.</p>
        <p>This demo uses n=8 coefficients (mod ${Q}) so the butterfly structure is visible. Full Kyber uses n=256.</p>
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
        <div class="controls" style="margin-top:0.7rem">
          <button id="ntt-run">Run NTT multiply</button>
          <button id="ntt-new">New random polynomials</button>
        </div>
        ${state.nttResult ? `
        <div class="ntt-result-grid">
          <div>
            <h3>NTT(a)</h3>
            <code>[${state.nttResult.nttA.join(', ')}]</code>
            <div class="ntt-butterflies" role="img" aria-label="Butterfly operations for polynomial a">${renderButterflyTable(state.nttResult.butterfliesA)}</div>
          </div>
          <div>
            <h3>NTT(b)</h3>
            <code>[${state.nttResult.nttB.join(', ')}]</code>
            <div class="ntt-butterflies" role="img" aria-label="Butterfly operations for polynomial b">${renderButterflyTable(state.nttResult.butterfliesB)}</div>
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
        ` : ''}
      </div>
    </section>

    <section class="panel ${state.activeTab === 'params' ? 'visible' : ''}" id="panel-params" role="tabpanel" aria-labelledby="tab-params" ${state.activeTab !== 'params' ? 'hidden' : ''}>
      <div class="grid-three">
        ${VARIANTS.map((variant) => {
          const p = ML_KEM_PARAMS[variant];
          return `<article class="card clickable" data-go-variant="${variant}" role="button" tabindex="0" aria-label="Select ${variantDisplay(variant)} and go to Encapsulate tab">
            <h3>${variantDisplay(variant)}</h3>
            <p>Security category ${p.securityCategory}</p>
            <p>Public key: ${p.publicKey} bytes</p>
            <p>Private key: ${p.privateKey} bytes</p>
            <p>Ciphertext: ${p.ciphertext} bytes</p>
            <div class="bar" style="--w:${Math.round((p.publicKey / 1568) * 100)}%" role="img" aria-label="Relative key size: ${Math.round((p.publicKey / 1568) * 100)}%"></div>
          </article>`;
        }).join('')}
      </div>
      <div class="card">
        <h3>Where ML-KEM / Kyber is deployed today</h3>
        <p><strong>ML-KEM-768</strong> (hybrid with X25519): Chrome &amp; Google services, Cloudflare, AWS, OpenSSH 9.9+.</p>
        <p><strong>Kyber-1024</strong> (category 5): Apple iMessage PQ3, Signal PQXDH.</p>
        <p class="muted">Most TLS/SSH deployments pair the KEM with X25519 so a break in either primitive alone is not fatal.</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'compare' ? 'visible' : ''}" id="panel-compare" role="tabpanel" aria-labelledby="tab-compare" ${state.activeTab !== 'compare' ? 'hidden' : ''}>
      <div class="card">
        <h2>KEM vs key exchange</h2>
        <p>X25519 is classical ECDH, while ML-KEM is a post-quantum key encapsulation mechanism. Hybrid migration combines X25519 + ML-KEM to hedge against both quantum and implementation risk.</p>
      </div>
      <div class="card">
        <h3>Size comparison</h3>
        <table>
          <thead>
            <tr><th scope="col">Scheme</th><th scope="col">Public key / payload</th><th scope="col">Notes</th></tr>
          </thead>
          <tbody>
            <tr><td>RSA-2048</td><td>256 B modulus</td><td>Classical, no PQ security</td></tr>
            <tr><td>X25519</td><td>32 B public key</td><td>Fast classical ECDH</td></tr>
            <tr><td>ML-KEM-512</td><td>800 B public key</td><td>PQ category 1</td></tr>
            <tr><td>ML-KEM-768</td><td>1184 B public key</td><td>PQ category 3</td></tr>
            <tr><td>ML-KEM-1024</td><td>1568 B public key</td><td>PQ category 5</td></tr>
          </tbody>
        </table>
      </div>
      <div class="card">
        <h3>Benchmark</h3>
        <p>Run 100 iterations each for KeyGen, Encaps, Decaps and compare to X25519 ECDH.</p>
        <button id="run-benchmark" ${state.benchmarkRunning ? 'disabled' : ''}>Run benchmark</button>
        <p aria-live="polite">${escapeHtml(state.benchmarkProgress)}</p>
        ${
          state.benchmark
            ? `<table>
          <thead>
            <tr><th scope="col">Variant</th><th scope="col">KeyGen</th><th scope="col">Encaps</th><th scope="col">Decaps</th></tr>
          </thead>
          <tbody>
            ${state.benchmark.variants
              .map(
                (row) =>
                  `<tr><td>${variantDisplay(row.variant)}</td><td>${formatOps(
                    row.keygenOpsPerSecond,
                  )}</td><td>${formatOps(row.encapsOpsPerSecond)}</td><td>${formatOps(
                    row.decapsOpsPerSecond,
                  )}</td></tr>`,
              )
              .join('')}
            <tr><td>X25519 ECDH</td><td colspan="3">${
              state.benchmark.x25519OpsPerSecond === null
                ? 'Not available in this browser runtime'
                : formatOps(state.benchmark.x25519OpsPerSecond)
            }</td></tr>
          </tbody>
        </table>`
            : ''
        }
        <p>ML-KEM is typically 5-10x slower than X25519 in software. Hardware implementations close this gap significantly.</p>
      </div>
    </section>

    <section class="panel ${state.activeTab === 'how' ? 'visible' : ''}" id="panel-how" role="tabpanel" aria-labelledby="tab-how" ${state.activeTab !== 'how' ? 'hidden' : ''}>
      <div class="card">
        <h2>How LWE works</h2>
        <div class="stepper" role="list" aria-label="LWE concept steps">
          <div class="step ${state.learnStep === 1 ? 'current' : ''}" role="listitem"${state.learnStep === 1 ? ' aria-current="step"' : ''}>1. LWE setup: publish A and b = As + e (mod q).</div>
          <div class="step ${state.learnStep === 2 ? 'current' : ''}" role="listitem"${state.learnStep === 2 ? ' aria-current="step"' : ''}>2. Noise masks linear structure and blocks direct solving.</div>
          <div class="step ${state.learnStep === 3 ? 'current' : ''}" role="listitem"${state.learnStep === 3 ? ' aria-current="step"' : ''}>3. Build PKE by embedding message bits in noisy equations.</div>
          <div class="step ${state.learnStep === 4 ? 'current' : ''}" role="listitem"${state.learnStep === 4 ? ' aria-current="step"' : ''}>4. Module-LWE upgrades to polynomials in Zq[X]/(X^256 + 1), q=3329.</div>
          <div class="step ${state.learnStep === 5 ? 'current' : ''}" role="listitem"${state.learnStep === 5 ? ' aria-current="step"' : ''}>5. Fujisaki-Okamoto transform upgrades PKE to IND-CCA2 KEM.</div>
        </div>
        <div class="controls">
          <button id="learn-prev" ${state.learnStep === 1 ? 'disabled' : ''}>Prev concept</button>
          <button id="learn-next" ${state.learnStep === 5 ? 'disabled' : ''}>Next concept</button>
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

  const themeToggleButton = appRoot.querySelector<HTMLButtonElement>('#theme-toggle');
  if (themeToggleButton) {
    themeToggleButton.addEventListener('click', () => {
      const nextTheme: Theme = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(nextTheme);
      const nextMeta = getThemeToggleMeta(nextTheme);
      themeToggleButton.textContent = nextMeta.icon;
      themeToggleButton.setAttribute('aria-label', nextMeta.label);
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
        state.hybridError = '';
      } catch (error) {
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
        state.hybridError = '';
      } catch (error) {
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
      state.hybridError = 'Ciphertext tampered. Decryption should fail authentication.';
      state.hybridDecrypted = '';
      render();
    });
  }

  const newLweButton = appRoot.querySelector<HTMLButtonElement>('#new-lwe');
  if (newLweButton) {
    newLweButton.addEventListener('click', () => {
      state.lwe = generateIllustrativeLWEInstance(6, 4, ILLUSTRATIVE_Q);
      state.latticeMessage = 'Generated new random A, s, e, and b over q=17.';
      render();
    });
  }

  const bruteForceButton = appRoot.querySelector<HTMLButtonElement>('#bruteforce');
  if (bruteForceButton) {
    bruteForceButton.addEventListener('click', () => {
      state.latticeMessage = bruteForceSearchSpace(6);
      render();
    });
  }

  const nttRunButton = appRoot.querySelector<HTMLButtonElement>('#ntt-run');
  if (nttRunButton) {
    nttRunButton.addEventListener('click', () => {
      state.nttResult = polyMultiplyNTT(state.nttA, state.nttB);
      state.nttSchoolbook = polyMultiplySchoolbook(state.nttA, state.nttB);
      render();
    });
  }

  const nttNewButton = appRoot.querySelector<HTMLButtonElement>('#ntt-new');
  if (nttNewButton) {
    nttNewButton.addEventListener('click', () => {
      state.nttA = randomSmallPoly(8);
      state.nttB = randomSmallPoly(8);
      state.nttResult = null;
      state.nttSchoolbook = null;
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
