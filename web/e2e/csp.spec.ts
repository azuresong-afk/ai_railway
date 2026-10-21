import { expect, test } from "@playwright/test";
import { mockApi } from "./mock-api";
import { watch } from "./watch";

// ТЗ, 6.9: интерфейс работает при строгом CSP, без нарушений и внешних запросов.
test("консоль открывается при строгом CSP без нарушений", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: null });
  const resp = await page.goto("/");
  expect(resp?.headers()["content-security-policy"]).toContain("script-src 'self'");
  await expect(page.getByRole("heading", { name: "Вход в AISec" })).toBeVisible();
  done();
});
