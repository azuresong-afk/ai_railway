import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi, user } from "./mock-api";
import { watch } from "./watch";

const u = (id: string, login: string, role = "analyst") => ({
  id,
  login,
  display_name: `Имя ${login}`,
  role,
  status: "active",
  locked: false,
  must_change_password: false,
  password_changed_at: "2026-10-01T00:00:00Z",
  created_at: "2026-10-01T00:00:00Z",
});
const role = (id: string, perms: string[], builtin = true) => ({
  id,
  display_name: id === "analyst" ? "Аналитик" : "Администратор безопасности",
  description: "",
  builtin,
  mfa_required: false,
  users: 1,
  permissions: perms.map((permission) => ({ permission, scope: "all" })),
});

const perms = ["session", "self", "users.read", "users.manage", "roles.read", "roles.manage", "sessions.read", "sessions.manage", "events.read"];

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}

// Подмена API администрирования поверх общей подмены входа.
async function mockAdmin(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  await page.route(/\/api\/v1\/(users|roles|permissions|auth\/policy|api-tokens)/, async (route) => {
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
    if (p === "/api/v1/users" && req.method() === "GET") return json({ items: [{ ...u(user.id, user.login, "security_admin") }, u("u-2", "petrov")] });
    if (p === "/api/v1/users" && req.method() === "POST") {
      const b = body as { login: string; role: string };
      return json({ user: u("u-3", b.login, b.role), temporary_password: "Tmp-Pass-123456" }, 201);
    }
    if (p === "/api/v1/users/u-2/role") return json({ user: u("u-2", "petrov", "security_admin"), revoked_sessions: 2 });
    if (p === "/api/v1/roles") {
      return json({ items: [role("analyst", ["events.read"]), role("security_admin", ["events.read", "roles.manage"])] });
    }
    if (p === "/api/v1/permissions") {
      return json({
        items: [
          { name: "events.read", title: "Просмотр событий", group: "События", security: false, ownable: false },
          { name: "roles.manage", title: "Управление ролями", group: "Роли", security: true, ownable: false },
        ],
      });
    }
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("администрирование: пользователи, создание с одноразовым паролем, смена роли", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockAdmin(page);
  await page.goto("/#/admin");
  await expect(page.getByRole("heading", { name: "Администрирование" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Токены API" })).toHaveCount(0);

  // Себя менять нельзя: разделение обязанностей видно в интерфейсе.
  await expect(page.getByRole("button", { name: "Сменить роль: ivanov" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Деактивировать: ivanov" })).toBeDisabled();

  // Создание: временный пароль показывается один раз.
  await page.getByRole("button", { name: "Создать пользователя" }).click();
  const form = page.getByRole("dialog", { name: "Создать пользователя" });
  await form.getByLabel("Логин").fill("sidorov");
  await form.getByLabel("Имя для показа").fill("Сидоров");
  await form.getByLabel("Роль").selectOption("analyst");
  await form.getByRole("button", { name: "Создать пользователя" }).click();
  const secret = page.getByRole("dialog", { name: /Временный пароль: sidorov/ });
  await expect(secret.getByLabel("Временный пароль")).toHaveValue("Tmp-Pass-123456");
  await secret.getByRole("button", { name: "Я сохранил значение" }).click();
  await expect(page.getByText("Tmp-Pass-123456")).toHaveCount(0);
  await expect(page.locator("input[value='Tmp-Pass-123456']")).toHaveCount(0);
  expect(seen.calls.find((c) => c.method === "POST")?.body).toEqual({ login: "sidorov", display_name: "Сидоров", role: "analyst" });

  // Смена роли — через диалог с подтверждением.
  await page.getByRole("button", { name: "Сменить роль: petrov" }).click();
  const dlg = page.getByRole("dialog", { name: /Сменить роль: petrov/ });
  await dlg.getByLabel("Новая роль").selectOption("security_admin");
  await dlg.getByRole("button", { name: "Назначить роль и завершить сессии" }).click();
  await expect.poll(() => seen.calls.find((c) => c.method === "PUT")?.body).toEqual({ role: "security_admin" });
  done();
});

test("администрирование: матрица разрешений строится из ответа API", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  await mockAdmin(page);
  await page.goto("/#/admin");
  await page.getByRole("tab", { name: "Роли и разрешения" }).click();
  const matrix = page.getByRole("table", { name: "Разрешения по ролям" });
  await expect(matrix).toBeVisible();
  await expect(matrix.getByRole("row", { name: /Управление ролями/ })).toContainText("нет");
  await expect(matrix.getByRole("row", { name: /Управление ролями/ })).toContainText("да");
  await expect(matrix.getByRole("row", { name: /Управление ролями/ })).toContainText("безопасность");
  // Предустановленные роли не изменяются: кнопок нет.
  await expect(page.getByRole("button", { name: /Изменить роль/ })).toHaveCount(0);
  done();
});
