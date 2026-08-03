import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '::',
    allowedHosts: true,
    proxy: {
      "/api": "http://localhost:4000",
    },
  },
})
