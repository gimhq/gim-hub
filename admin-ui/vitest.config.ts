import { mergeConfig } from 'vite'
import { defineConfig } from 'vitest/config'
import viteConfig from './vite.config.ts'

export default mergeConfig(viteConfig, defineConfig({
  test: {
    environment: 'happy-dom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/app/routeTree.gen.ts', 'src/test/**', 'src/**/*.test.{ts,tsx}'],
      thresholds: { lines: 80, statements: 80 },
    },
  },
}))
