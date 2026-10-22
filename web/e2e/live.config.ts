import { defineConfig } from "@playwright/test";

// Сквозной сценарий на настоящем aisec-server (H-Р7, задача 2.28). Запускает
// его Go-тест TestE2EStage2_ConsoleLive (test/e2e): сервер, БД и учётные
// данные — его; vite preview здесь не нужен. Сертификат сервера выпущен
// тестовым УЦ, поэтому ошибки сертификата игнорируются только здесь.
const executablePath = process.env.AISEC_CHROMIUM || undefined;

export default defineConfig({
  testDir: ".",
  testMatch: "live.spec.ts",
  workers: 1,
  reporter: "list",
  use: { ignoreHTTPSErrors: true, launchOptions: { executablePath } },
});
