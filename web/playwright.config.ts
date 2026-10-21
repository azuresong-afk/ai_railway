import { defineConfig } from "@playwright/test";

// Браузер — из PLAYWRIGHT_BROWSERS_PATH (сборочный образ) либо явный путь в
// AISEC_CHROMIUM; загрузок нет.
const executablePath = process.env.AISEC_CHROMIUM || undefined;

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:4173", launchOptions: { executablePath } },
  webServer: {
    command: "npx vite preview",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
