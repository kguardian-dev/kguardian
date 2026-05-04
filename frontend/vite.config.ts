import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'fs'

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },

  // Development server configuration
  server: {
    allowedHosts: true,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:9090',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/llm-api': {
        target: process.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llm-api/, ''),
      },
    },
  },

  // Production build configuration
  build: {
    // Output directory for production build
    outDir: 'dist',

    // Generate sourcemaps for production debugging (optional, disable for smaller builds)
    sourcemap: false,

    // Target modern browsers for smaller bundles
    target: 'esnext',

    // Optimize chunk splitting
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) {
            return 'react-vendor'
          }
          if (id.includes('node_modules/reactflow/') || id.includes('node_modules/@reactflow/')) {
            return 'react-flow-vendor'
          }
        },
      },
    },

    // Chunk size warning limit (500 KB)
    chunkSizeWarningLimit: 500,

    // Minification
    minify: 'esbuild',

    // Asset optimization
    assetsInlineLimit: 4096, // 4kb - inline assets smaller than this
  },

  // Preview server configuration (for production)
  preview: {
    port: 5173,
    host: '0.0.0.0',
    strictPort: true,
    allowedHosts: true,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:9090',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/llm-api': {
        target: process.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llm-api/, ''),
      },
    },
  },
})
