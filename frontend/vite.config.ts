import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api and /health to the FastAPI backend so the SPA
// and API share an origin during development (no CORS surprises).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    chunkSizeWarningLimit: 3000,
    rollupOptions: {
      output: {
        // Split the heavy editor away from the app shell so the dashboard and
        // tables stay lightweight; Monaco loads only when a code view opens.
        manualChunks: {
          monaco: ["monaco-editor/esm/vs/editor/editor.api"],
          vendor: ["react", "react-dom", "react-router-dom", "@tanstack/react-query"],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
