import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Строгий CSP из ТЗ, 6.9. Используется и для preview в e2e-тестах;
// в продукте заголовок выставляет aisec-server.
export const csp =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    // react-remove-scroll вставляет <style>, несовместимый со строгим CSP (ADR-0010).
    alias: { "react-remove-scroll": fileURLToPath(new URL("./src/shims/remove-scroll.tsx", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: false, // в dist/ лежит .gitkeep для go:embed
    sourcemap: false,
    // Никаких встроенных скриптов и стилей: CSP без 'unsafe-inline'.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    cssCodeSplit: false,
  },
  preview: { host: "127.0.0.1", port: 4173, strictPort: true, headers: { "Content-Security-Policy": csp } },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
