import { defineConfig } from 'vitest/config';
import { lockedImplementation } from './locked-implementation.ts';

export default defineConfig({
  define: {
    __NOBLE_POST_QUANTUM_VERSION__: JSON.stringify(lockedImplementation.version),
    __NOBLE_POST_QUANTUM_INTEGRITY__: JSON.stringify(lockedImplementation.integrity),
  },
  test: {
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts'],
  },
});
