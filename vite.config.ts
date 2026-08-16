import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      /* Never watch the Rust side. Cargo rewrites files under src-tauri/target
       * constantly while it builds, and on Windows those .exe files are locked
       * while in use — the watcher hits EBUSY and takes the dev server down
       * with it. Nothing there is a frontend source anyway. */
      ignored: ['**/src-tauri/**'],
    },
  },
});
