import { expect, test } from "@playwright/test";

// ТЗ, 6.9: интерфейс работает при строгом CSP, без нарушений и внешних запросов.
test("консоль открывается при строгом CSP без нарушений", async ({ page }) => {
  const problems: string[] = [];
  const external: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(e.message));
  page.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1:4173/")) external.push(r.url());
  });
  const resp = await page.goto("/");
  expect(resp?.headers()["content-security-policy"]).toContain("script-src 'self'");
  await expect(page.getByRole("heading", { name: "AISec" })).toBeVisible();
  expect(problems).toEqual([]);
  expect(external).toEqual([]);
});
