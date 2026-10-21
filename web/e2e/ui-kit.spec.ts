import { expect, test } from "@playwright/test";

// ТЗ 6.2, 6.9: страница /dev/ui-kit работает в обеих темах при строгом CSP, шрифты локальные.
test("ui-kit открывается в обеих темах и плотностях без нарушений CSP", async ({ page }) => {
  const problems: string[] = [];
  const external: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") problems.push(`${m.type()}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(e.message));
  page.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1:4173/")) external.push(r.url());
  });
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      console.error(`CSP: ${e.violatedDirective} ${e.blockedURI} ${e.sample}`);
    });
  });

  await page.goto("/#/dev/ui-kit");
  await expect(page.getByRole("heading", { name: "Дизайн-система консоли" })).toBeVisible();

  // Шрифты Onest (кириллица) и JetBrains Mono загружены из своего источника.
  const fonts = await page.evaluate(async () => {
    await document.fonts.load('14px "Onest"', "Запрос");
    await document.fonts.load('14px "JetBrains Mono"', "Запрос");
    return [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family.replaceAll('"', ""));
  });
  expect(fonts).toContain("Onest");
  expect(fonts).toContain("JetBrains Mono");

  for (const theme of ["Светлая", "Тёмная"]) {
    await page.getByLabel("Тема").selectOption({ label: theme });
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe(theme === "Светлая" ? "rgb(238, 241, 244)" : "rgb(22, 32, 43)");
    for (const density of ["Компактно", "Удобно"]) {
      await page.getByLabel("Плотность").selectOption({ label: density });
    }
    // У каждого уровня серьёзности и каждого решения есть подпись и значок.
    for (const label of ["Критическая", "Высокая", "Средняя", "Низкая", "Информация"]) {
      await expect(page.getByLabel("Серьёзность и решения").getByText(label)).toBeVisible();
    }
    for (const label of ["Пропущен", "Замаскирован", "Заблокирован", "Заблокировал бы"]) {
      await expect(page.getByLabel("Серьёзность и решения").getByText(label)).toBeVisible();
    }
  }

  // Диалог открывается и закрывается; страница не сдвигается на ширину полосы прокрутки.
  const widthBefore = await page.evaluate(() => document.querySelector("main")!.getBoundingClientRect().left);
  await page.getByRole("button", { name: "Открыть карточку" }).click();
  await expect(page.getByRole("dialog", { name: "Карточка события" })).toBeVisible();
  const widthOpen = await page.evaluate(() => document.querySelector("main")!.getBoundingClientRect().left);
  expect(widthOpen).toBe(widthBefore);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // Подтверждение и уведомление.
  await page.getByRole("button", { name: "Удалить политику" }).click();
  await page.getByRole("button", { name: "Удалить", exact: true }).click();
  await expect(page.getByText("Опубликовано")).toBeVisible();

  // Нет вставленных <style> (атрибуты style, выставленные через CSSOM, CSP допускает).
  expect(await page.locator("style").count()).toBe(0);
  expect(problems).toEqual([]);
  expect(external).toEqual([]);
});
