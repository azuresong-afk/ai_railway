import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

// Синтетический псевдоним: произвольный hex, не от реального логина.
const alias = "0123456789abcdef0123456789abcdef";
const limits = { max_connections: 256, max_connections_per_address: 16, max_frame_bytes: 16384, lines_per_second: 5000, idle_timeout_seconds: 300, frame_timeout_seconds: 30 };

async function mockShadow(page: Page): Promise<{ imports: { url: string; type: string | undefined; size: number }[] }> {
  const seen = { imports: [] as { url: string; type: string | undefined; size: number }[] };
  await page.route("**/api/v1/shadow-ai/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    switch (`${req.method()} ${url.pathname}`) {
      case "GET /api/v1/shadow-ai/catalog":
        return json({ loaded: true, valid: true, version: 3, date: "2026-10-01", services: [{ id: "chatgpt", name: "ChatGPT", vendor: "OpenAI", category: "chat", domains: ["chatgpt.com"], suffixes: [] }] });
      case "GET /api/v1/shadow-ai/settings":
        return json({ retention_days: 365, users_pseudonymized: true });
      case "GET /api/v1/shadow-ai/services":
        return json({ items: [{ id: "chatgpt", name: "ChatGPT", vendor: "OpenAI", category: "chat", requests: 1200, bytes: 4096, users: 2, first_seen: "2026-10-20T09:00:00Z", last_seen: "2026-10-27T15:00:00Z" }] });
      case "GET /api/v1/shadow-ai/users":
        return json({ items: [{ alias, kind: "user", requests: 40, bytes: 100, services: ["chatgpt"], last_seen: "2026-10-27T15:00:00Z" }] });
      case "GET /api/v1/shadow-ai/timeline":
        return json({ step: "day", items: [
          { bucket: "2026-10-26T00:00:00Z", requests: 500, bytes: 1000, users: 1, services: 1 },
          { bucket: "2026-10-27T00:00:00Z", requests: 700, bytes: 3096, users: 2, services: 1 },
        ] });
      case "GET /api/v1/shadow-ai/imports":
        return json({ items: [] });
      case "POST /api/v1/shadow-ai/imports":
        seen.imports.push({ url: url.search, type: req.headers()["content-type"], size: req.postDataBuffer()?.length ?? 0 });
        return json({ id: "i-1", created_at: "2026-10-28T10:00:00Z", created_by: "user:u1", catalog_version: 3, format: "squid", lines: 3, matched: 2, unmatched: 0,
          errors: 1, outdated: 0, excluded: 0, error_lines: [3], users_pseudonymized: true, sha256: "ab", services: 1 }, 201);
      case "GET /api/v1/shadow-ai/exclusions":
        return json({ items: [] });
      case "GET /api/v1/shadow-ai/syslog":
        return json({ enabled: true, running: true, accept_errors: 0, address: "0.0.0.0:6514", format: "cef", tls: true, client_cert_required: false, allowed_networks: [], connections: 1, limits,
          accepted: 3, rejected_network: 0, rejected_limit: 0, tls_failed: 1, frame_too_large: 0, bad_frame: 0, idle_timeouts: 0, read_timeouts: 0, lines: 10,
          matched: 5, unmatched: 5, errors: 0, excluded: 0, outdated: 0, no_catalog: 0, dropped: 0, throttled: 0, pending: 1, flush_failures: 0, last_flush_failed: false });
      default:
        return route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
    }
  });
  return seen;
}

test("теневой ИИ: сервисы, график при строгом CSP, импорт файлом и состояние syslog", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "shadow_ai.read", "shadow_ai.manage", "events.read"]) });
  const seen = await mockShadow(page);
  await page.goto("/");
  await page.getByRole("link", { name: "Теневой ИИ" }).click();
  await expect(page.getByRole("heading", { name: "Теневой ИИ", level: 1 })).toBeVisible();
  await expect(page.getByRole("table", { name: "Сервисы за период" })).toContainText("ChatGPT");
  await expect(page.getByRole("img", { name: /Обращения к ИИ-сервисам/ }).locator("svg")).toBeVisible();
  await expect(page.getByRole("link", { name: `События пользователя ${alias}` })).toBeVisible();

  await page.getByRole("tab", { name: "Импорт и каталог" }).click();
  await page.getByLabel("Файл журнала").setInputFiles({ name: "access.log", mimeType: "text/plain", buffer: Buffer.from("1730000000.000 1 10.0.0.1 TCP_TUNNEL/200 1 CONNECT chatgpt.com:443 u HIER_DIRECT/203.0.113.1 -\n") });
  await page.getByRole("button", { name: "Импортировать журнал" }).click();
  await expect(page.getByText(/Журнал импортирован: строк 3/)).toBeVisible();
  await expect(page.getByText(/Ошибочные строки: 3/)).toBeVisible();
  expect(seen.imports).toEqual([{ url: "?format=squid", type: "text/plain", size: 95 }]);

  await page.getByRole("tab", { name: "Приём по syslog" }).click();
  await expect(page.getByText("0.0.0.0:6514")).toBeVisible();
  await expect(page.getByRole("table", { name: "Соединения syslog" })).toContainText("Рукопожатие TLS не удалось");
  done();
});

test("теневой ИИ: без shadow_ai.read раздела нет в меню, прямой адрес — отказ", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "system.read"]) });
  await page.goto("/#/shadow-ai");
  await expect(page.getByText("Нет доступа: теневой ИИ")).toBeVisible();
  await expect(page.getByRole("link", { name: "Теневой ИИ" })).toHaveCount(0);
  done();
});
