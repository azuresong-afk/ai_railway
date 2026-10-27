import { expect, test } from "@playwright/test";
import { CSRF, meOf, mockApi } from "./mock-api";
import { watch } from "./watch";


test("вход с паролем и TOTP; неверный код отклоняется; CSRF уходит в заголовке", async ({ page }) => {
  const done = watch(page);
  const st = await mockApi(page, { me: null, afterLogin: meOf("mfa_pending"), goodCode: "123456" });
  await page.goto("/");
  await page.getByLabel("Логин").fill("ivanov");
  await page.getByLabel("Пароль").fill("wrong");
  await page.getByRole("button", { name: "Войти" }).click();
  await expect(page.getByRole("alert")).toContainText("Неверный логин или пароль");

  await page.getByLabel("Пароль").fill("Correct-Horse-1");
  await page.getByRole("button", { name: "Войти" }).click();
  await expect(page.getByRole("heading", { name: "Второй фактор" })).toBeVisible();

  await page.getByLabel("Код из приложения").fill("000000");
  await page.getByRole("button", { name: "Подтвердить" }).click();
  await expect(page.getByRole("alert")).toContainText("Код не подошёл");

  await page.getByLabel("Код из приложения").fill("123456");
  await page.getByRole("button", { name: "Подтвердить" }).click();
  await expect(page.getByRole("navigation", { name: "Разделы" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Состояние системы" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Администрирование" })).toHaveCount(0);

  const verify = st.calls.find((c) => c.path === "/api/v1/auth/mfa/verify");
  expect(verify?.csrf).toBe(CSRF);
  done();
});

test("смена временного пароля открывает консоль", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("password_change") });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Смена пароля" })).toBeVisible();
  await page.getByLabel("Текущий пароль").fill("Temp-pass-1");
  await page.getByLabel("Новый пароль", { exact: true }).fill("Brand-New-Pass-9");
  await page.getByLabel("Новый пароль ещё раз").fill("Brand-New-Pass-9");
  await page.getByRole("button", { name: "Сменить пароль" }).click();
  await expect(page.getByRole("navigation", { name: "Разделы" })).toBeVisible();
  done();
});

test("первичная настройка создаёт администратора и ведёт ко входу", async ({ page }) => {
  const done = watch(page);
  const st = await mockApi(page, { me: null, setupRequired: true });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Первичная настройка" })).toBeVisible();
  await page.getByLabel("Токен настройки").fill("aisec_setup_x");
  await page.getByLabel("Логин").fill("admin");
  await page.getByLabel("Имя в интерфейсе").fill("Администратор");
  await page.getByLabel("Пароль", { exact: true }).fill("Brand-New-Pass-9");
  await page.getByLabel("Пароль ещё раз").fill("Brand-New-Pass-9");
  // Умолчания по ТЗ 6.4: Москва и маскированное хранение; меняем оба поля.
  await expect(page.getByLabel("Часовой пояс")).toHaveValue("Europe/Moscow");
  await expect(page.getByLabel("Хранение содержимого по умолчанию")).toHaveValue("masked");
  await page.getByLabel("Часовой пояс").selectOption("Asia/Yekaterinburg");
  await page.getByLabel("Хранение содержимого по умолчанию").selectOption("none");
  await page.getByRole("button", { name: "Создать администратора" }).click();
  await expect(page.getByRole("heading", { name: "Вход в AISec" })).toBeVisible();
  await expect(page.getByText("Администратор создан")).toBeVisible();
  const post = st.calls.find((c) => c.path === "/api/v1/auth/setup" && c.method === "POST");
  expect(post?.body).toMatchObject({ timezone: "Asia/Yekaterinburg", retention_mode: "none" });
  done();
});

test("каркас: тема, свёртка панели, выход", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "system.read"]) });
  await page.goto("/");
  await page.getByLabel("Тема").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByLabel("Тема").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByRole("button", { name: "Свернуть панель разделов" }).click();
  await expect(page.getByRole("button", { name: "Развернуть панель разделов" })).toBeVisible();
  // «Отчёты» готовы с этапа 3; заглушка — у раздела, которого ещё нет.
  await page.getByRole("link", { name: "Теневой ИИ" }).click();
  await expect(page.getByText("раздел в разработке")).toBeVisible();
  await page.keyboard.press("?");
  await expect(page.getByRole("heading", { name: "Горячие клавиши" })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Выйти" }).click();
  await expect(page.getByRole("heading", { name: "Вход в AISec" })).toBeVisible();
  done();
});
