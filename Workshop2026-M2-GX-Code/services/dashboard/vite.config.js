import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/v1': process.env.VITE_API || 'http://127.0.0.1:18000' } },
  test: { environment: 'node' },
})
