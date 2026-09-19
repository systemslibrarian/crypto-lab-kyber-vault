import { defineConfig } from 'vite';
import { lockedImplementation } from './locked-implementation.ts';

function normalizeBasePath(basePath: string): string {
  const trimmed = basePath.trim();
  if (trimmed === '' || trimmed === '/') {
    return '/';
  }
  return `/${trimmed.replace(/^\/+|\/+$/g, '')}/`;
}

export default defineConfig(({ mode }) => {
  const configuredBase = process.env.VITE_BASE_PATH;
  const fallbackBase = mode === 'production' ? '/crypto-lab-kyber-vault/' : '/';

  return {
    base: normalizeBasePath(configuredBase ?? fallbackBase),
    define: {
      __NOBLE_POST_QUANTUM_VERSION__: JSON.stringify(lockedImplementation.version),
      __NOBLE_POST_QUANTUM_INTEGRITY__: JSON.stringify(lockedImplementation.integrity),
    },
  };
});
