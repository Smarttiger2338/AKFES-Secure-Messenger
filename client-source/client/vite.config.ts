import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  build: {
    // Keep the emitted syntax inside the oldest browser range that can run
    // AKFES's required WebCrypto algorithms. Runtime feature detection still
    // fails closed when Ed25519/X25519 are unavailable.
    target: ["chrome111", "edge111", "firefox115", "safari16.4"],
  },
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:18001",
      "/health": "http://127.0.0.1:18001",
      "/ws": {
        target: "ws://127.0.0.1:18001",
        ws: true,
      },
    },
  },
});
