import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  base: '/admin/',
  plugins: [
    // tanstackRouter must come before react().
    tanstackRouter({
      target: 'react',
      routesDirectory: 'src/app/routes',
      generatedRouteTree: 'src/app/routeTree.gen.ts',
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  resolve: { tsconfigPaths: true },
  server: { host: '0.0.0.0' },
  build: { outDir: 'dist', emptyOutDir: true },
})
