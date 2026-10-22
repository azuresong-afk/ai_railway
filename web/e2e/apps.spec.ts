import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const SECRET = "aisec_abcd1234_SECRETSECRETSECRETSECRETSECRETSECRETSECRET1";
const app = {
  id: "a-1", slug: "support-bot", name: "Бот поддержки", description: "", department: "", owner_id: "u1", env: "prod", provider_id: "p-1",
  models: ["gpt-4o"], aliases: {}, policy: "base", policy_mode: "enforce", storage: "masked", fail_mode: "fail_closed", user_from: "none",
  quotas: {}, lists: [], exfil_allow_domains: [], status: "active", created_at: "2026-10-01T10:00:00Z", updated_at: "2026-10-01T10:00:00Z",
};
const key = { id: "k-1", application_id: "a-1", name: "основной", prefix: "aisec_abcd1234", status: "active", allowed_cidrs: [], expires_at: "2027-10-01T00:00:00Z", created_at: "2026-10-01T10:00:00Z" };
const provider = { id: "p-1", slug: "main", name: "Основной", type: "openai", base_url: "https://llm.example", ca_pem: "", timeouts: {}, external: false, credential_set: true, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" };
const perms = ["session", "self", "applications.read", "applications.manage", "app_keys.manage", "providers.read"];

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}

// Подмена API приложений поверх общей подмены входа.
async function mockApps(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  await page.route(/\/api\/v1\/(applications|app-keys|providers|policies)/, async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    let body: unknown;
    try {
      body = req.postDataJSON();
    } catch {
      body = undefined;
    }
    seen.calls.push({ method: req.method(), path: url.pathname, body });
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p === "/api/v1/applications" && req.method() === "GET") return json({ items: [app] });
    if (p === "/api/v1/applications" && req.method() === "POST") {
      const b = body as { slug: string; name: string };
      return json({ ...app, id: "a-2", slug: b.slug, name: b.name }, 201);
    }
    if (p === "/api/v1/applications/a-1/keys") return json({ items: [key] });
    if (p === "/api/v1/applications/a-2/keys") return req.method() === "POST" ? json({ app_key: key, key: SECRET }, 201) : json({ items: [] });
    if (p === "/api/v1/app-keys/k-1/revoke") return json({ ...key, status: "revoked" });
    if (p === "/api/v1/providers") return json({ items: [provider] });
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("приложения: мастер подключения, ключ показывается один раз и стирается", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockApps(page);
  await page.goto("/#/apps");
  await expect(page.getByRole("heading", { name: "Приложения" })).toBeVisible();
  await expect(page.getByText("Бот поддержки")).toBeVisible();

  await page.getByRole("button", { name: "Подключить приложение" }).click();
  const dlg = page.getByRole("dialog", { name: "Подключение приложения" });
  await dlg.getByLabel("Название").fill("Помощник HR");
  await expect(dlg.getByLabel("ID приложения")).toHaveValue("pomoshchnik-hr");
  await dlg.getByRole("button", { name: "Далее: провайдер и политика" }).click();
  await dlg.getByLabel("Провайдер").selectOption("p-1");
  await dlg.getByLabel("Разрешённые модели").fill("gpt-4o");
  await dlg.getByRole("button", { name: "Далее: ключ" }).click();
  await dlg.getByRole("button", { name: "Создать приложение и выпустить ключ" }).click();

  await expect(dlg.getByLabel("Ключ приложения")).toHaveValue(SECRET);
  await expect(dlg.getByRole("region", { name: "Пример запроса" })).toContainText("$AISEC_KEY");
  await dlg.getByRole("button", { name: "Я сохранил ключ" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  // После закрытия ключа нет ни в тексте страницы, ни в полях.
  await expect(page.getByText(SECRET)).toHaveCount(0);
  await expect(page.locator(`input[value='${SECRET}']`)).toHaveCount(0);
  expect(seen.calls.find((c) => c.method === "POST" && c.path === "/api/v1/applications")?.body).toEqual({
    slug: "pomoshchnik-hr", name: "Помощник HR", env: "prod", provider_id: "p-1", models: ["gpt-4o"], user_from: "none",
  });
  done();
});

test("приложения: отзыв ключа через диалог подтверждения", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockApps(page);
  await page.goto("/#/apps");
  await page.getByRole("button", { name: "Ключи приложения Бот поддержки" }).click();
  await page.getByRole("button", { name: "Отозвать ключ основной" }).click();
  expect(seen.calls.some((c) => c.path.endsWith("/revoke"))).toBe(false);
  const dlg = page.getByRole("alertdialog", { name: "Отозвать ключ" });
  await dlg.getByRole("button", { name: "Отозвать ключ" }).click();
  await expect.poll(() => seen.calls.some((c) => c.path === "/api/v1/app-keys/k-1/revoke" && c.method === "POST")).toBe(true);
  done();
});

test("приложения: владелец без права управления не видит кнопок", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "applications.read"]) });
  await mockApps(page);
  await page.goto("/#/apps");
  await expect(page.getByText("Бот поддержки")).toBeVisible();
  await expect(page.getByRole("button", { name: "Подключить приложение" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /В архив/ })).toHaveCount(0);
  done();
});
