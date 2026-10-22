import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const rule = { id: "pii-ru", detector: "pii.ru", action: "redact", severity: "high" };
const spec = { name: "Моя политика", mode: "enforce", non_text: "allow_inline", response_check: "incremental", rules: [rule] };
const mine = { id: "mine", name: "Моя политика", mode: "enforce", template: false, current_version: 2, updated_at: "2026-10-02T10:00:00Z" };
const versions = [
  { version: 2, hash: "bb", hash_alg: "sha256", source: "api", comment: "строже", created_at: "2026-10-02T10:00:00Z", created_by: "boss" },
  { version: 1, hash: "aa", hash_alg: "sha256", source: "template", comment: "", created_at: "2026-10-01T10:00:00Z", created_by: "boss" },
];
const perms = ["session", "self", "policies.read", "policies.manage", "policies.test"];

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}

async function mockPolicies(page: Page, testStatus = 200): Promise<Seen> {
  const seen: Seen = { calls: [] };
  await page.route(/\/api\/v1\/(policies|applications)/, async (route) => {
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
    if (p === "/api/v1/policies") return json({ items: [{ id: "base", name: "Базовая защита", mode: "enforce", template: true }, mine] });
    if (p === "/api/v1/policies/mine") return json({ ...mine, spec });
    if (p === "/api/v1/policies/mine/versions") return json({ items: versions });
    if (p === "/api/v1/policies/mine/export") return route.fulfill({ status: 200, contentType: "application/yaml", body: "name: Моя политика\n" });
    if (p === "/api/v1/policies/test") {
      if (testStatus !== 200) {
        return json({ type: "urn:aisec:problem:unprocessable", title: "unprocessable", status: 422, code: "unprocessable", detail: "Категория lists.vip: словаря нет у приложения." }, 422);
      }
      return json({
        policy_id: "mine", draft: false, direction: "input", mode: "enforce", decision: "block", action: "block", blocked: true, fail_block: false,
        incomplete: false, unchecked: false, failures: [], findings: [], texts: [],
      });
    }
    if (p === "/api/v1/policies/mine/diff") {
      return json({
        from: 2, to: 1, fields: [], rules_added: [], rules_removed: [rule], rules_changed: [], reordered: false,
        weakening: true, weakening_reasons: [{ kind: "rule_removed", rule: "pii-ru" }],
        exceptions_added: [], exceptions_removed: [], exceptions_changed: [],
      });
    }
    // Откат с ослаблением: без пароля сервер просит подтверждение (В23 ревью 2.r5).
    if (p === "/api/v1/policies/mine/rollback") {
      const b = body as { password?: string };
      if (!b.password) {
        return json({ type: "urn:aisec:problem:invalid_request", title: "invalid", status: 400, code: "invalid_request", detail: "Проверьте введённые данные.",
          errors: [{ field: "password", detail: "Введите текущий пароль или код из приложения-аутентификатора." }] }, 400);
      }
      return json({ ...mine, current_version: 3, spec });
    }
    if (p === "/api/v1/applications") return json({ items: [] });
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("политики: версии, выгрузка и песочница", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockPolicies(page);
  await page.goto("/#/policies");
  await expect(page.getByRole("heading", { name: "Политики" })).toBeVisible();
  await page.getByRole("button", { name: "Открыть политику Моя политика" }).click();
  await expect(page.getByRole("heading", { name: /Моя политика/ })).toBeVisible();
  await page.getByRole("tab", { name: "Версии" }).click();
  await expect(page.getByRole("button", { name: "Откатить к версии 1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Откатить к версии 2" })).toHaveCount(0);

  await page.getByRole("tab", { name: "Песочница" }).click();
  await page.getByLabel("Проверяемый текст").fill("тестовый текст");
  await page.getByRole("button", { name: "Проверить текст" }).click();
  await expect(page.getByRole("region", { name: "Результат проверки" })).toContainText("Заблокирован");
  expect(seen.calls.find((c) => c.path === "/api/v1/policies/test")?.body).toEqual({
    policy_id: "mine", request: { direction: "input", text: "тестовый текст" },
  });
  done();
});

test("политики: 422 песочницы по словарю показан подсказкой", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  await mockPolicies(page, 422);
  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Открыть политику Моя политика" }).click();
  await page.getByRole("tab", { name: "Песочница" }).click();
  await page.getByLabel("Проверяемый текст").fill("текст");
  await page.getByRole("button", { name: "Проверить текст" }).click();
  await expect(page.getByText(/словаря нет у приложения/)).toBeVisible();
  await expect(page.getByRole("link", { name: "разделе «Приложения»" })).toHaveAttribute("href", "#/apps");
  done();
});

test("политики: откат с ослаблением защиты требует пароль", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockPolicies(page);
  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Открыть политику Моя политика" }).click();
  await page.getByRole("tab", { name: "Версии" }).click();
  await page.getByRole("button", { name: "Откатить к версии 1" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Откатить к версии 1" }).click();
  await expect(dialog.getByText(/Подтвердите, что это вы/)).toBeVisible();
  const confirm = dialog.getByRole("button", { name: "Откатить к версии 1" });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel("Текущий пароль").fill("Пароль-для-проверки-1");
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  const calls = seen.calls.filter((c) => c.path === "/api/v1/policies/mine/rollback");
  expect(calls.map((c) => c.body)).toEqual([
    { version: 1, base_version: 2 },
    { version: 1, base_version: 2, password: "Пароль-для-проверки-1" },
  ]);
  done();
});
