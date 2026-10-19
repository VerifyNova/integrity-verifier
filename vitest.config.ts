import { defineConfig } from 'vitest/config';

// The verifier's own suites, runnable from this package alone (and from the public repository).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
