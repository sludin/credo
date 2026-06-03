import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['server/**/*.test.ts'],
    setupFiles: ['./server/tests/setup.ts'],
  },
});
