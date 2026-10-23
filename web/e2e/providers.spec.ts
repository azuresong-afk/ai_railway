import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const PEM = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----";
const provider = {
  id: "p-1", slug: "main", name: "Основной", type: "openai", base_url: "https://llm.example/v1", ca_pem: PEM, timeouts: {},
  external: true, credential_set: true, credential_set_at: "2026-10-01T10:00:00Z", created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z",
};
const perms = ["session", "self", "providers.read", "providers.manage"];

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}

async function mockProviders(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  const items: Record<string, unknown>[] = [provider];
  await page.route(/\/api\/v1\/providers/, async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    let body: unknown;
    try {
      body = req.postDataJSON();
    } catch {
      body = undefined;
    }
    seen.calls.push({ method: req.method(), path: url.pathname, body });
    const json = (b: unknown, code = 200) => route.fulfill({ status: code, contentType: "application/json", body: JSON.stringify(b) });
    if (url.pathname === "/api/v1/providers" && req.method() === "GET") return json({ items });
    if (url.pathname === "/api/v1/providers" && req.method() === "POST") {
      const b = body as { slug: string; name: string };
      const created = { ...provider, id: "p-2", slug: b.slug, name: b.name, credential_set: false, credential_set_at: undefined };
      items.push(created);
      return json(created, 201);
    }
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("провайдеры: создать провайдера", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockProviders(page);
  await page.goto("/#/providers");
  await expect(page.getByRole("heading", { name: "Провайдеры" })).toBeVisible();
  await expect(page.getByText("Основной")).toBeVisible();

  await page.getByRole("button", { name: "Создать провайдера" }).click();
  const dlg = page.getByRole("dialog", { name: "Новый провайдер" });
  await dlg.getByLabel("Название").fill("Локальная модель");
  await expect(dlg.getByLabel("ID провайдера")).toHaveValue("lokalnaya-model");
  await dlg.getByLabel("Адрес API").fill("https://llm.corp.example/v1");
  await dlg.getByLabel(/Корневые сертификаты/).fill(PEM);
  await dlg.getByRole("button", { name: "Создать провайдера" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText("Локальная модель")).toBeVisible();
  await expect(page.getByText("Не заданы")).toBeVisible();

  const posted = seen.calls.find((c) => c.method === "POST")?.body;
  expect(posted).toMatchObject({ slug: "lokalnaya-model", name: "Локальная модель", type: "openai", base_url: "https://llm.corp.example/v1" });
  done();
});

test("провайдеры: без права управления кнопок нет", async ({ page }) => {
  await mockApi(page, { me: meOf("active", ["session", "self", "providers.read"]) });
  await mockProviders(page);
  await page.goto("/#/providers");
  await expect(page.getByText("Основной")).toBeVisible();
  await expect(page.getByRole("button", { name: "Создать провайдера" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Учётные данные/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Признак «внешний»/ })).toHaveCount(0);
});
