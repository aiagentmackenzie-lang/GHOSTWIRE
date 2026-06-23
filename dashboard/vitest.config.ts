// Vitest config (test-only). Kept separate from vite.config.ts so the
// dashboard build (`tsc -b && vite build`) never type-checks the `test` field
// against vite's UserConfig - and so vitest's bundled-vite types do not clash
// with the project's vite 8 (rolldown) types. Discovered automatically by
// `vitest`; excluded from the build tsconfig (tsconfig.node.json includes only
// vite.config.ts).
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    css: true,
  },
})