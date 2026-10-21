import { expect, test } from "@playwright/test";

// ТЗ, 6.9: Radix UI проверяется макетом при строгом CSP (задача 2.22, Р13).
// Любое нарушение CSP, ошибка консоли, <style> или style="" в разметке — провал.
test("примитивы Radix UI работают при строгом CSP без нарушений", async ({ page }) => {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") problems.push(`${m.type()}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(e.message));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      console.error(`CSP: ${e.violatedDirective} ${e.blockedURI} ${e.sample}`);
    });
  });

  await page.goto("/#/dev/radix");
  await expect(page.getByRole("heading", { name: "Макет Radix UI" })).toBeVisible();

  // Диалог
  await page.getByRole("button", { name: "Открыть карточку" }).click();
  await expect(page.getByRole("dialog", { name: "Карточка события" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // Диалог подтверждения
  await page.getByRole("button", { name: "Принять оповещения" }).click();
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await page.getByRole("button", { name: "Отменить" }).click();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);

  // Меню
  await page.getByRole("button", { name: "Колонки" }).click();
  await expect(page.getByRole("menu")).toBeVisible();
  await page.keyboard.press("Escape");

  // Всплывающее окно
  await page.getByRole("button", { name: "Фильтр" }).click();
  await expect(page.getByText("Фильтр по решению")).toBeVisible();
  await page.keyboard.press("Escape");

  // Подсказка
  await page.getByRole("button", { name: "3 мин назад" }).hover();
  await expect(page.getByRole("tooltip")).toBeVisible();

  // Выпадающий список — родной select (Radix Select несовместим, ADR-0010)
  await page.getByLabel("Режим", { exact: true }).selectOption("mask");
  await expect(page.getByLabel("Режим", { exact: true })).toHaveValue("mask");

  // Флажок, переключатель, радиокнопки
  await page.getByRole("checkbox", { name: "Выбрать строку" }).click();
  await expect(page.getByRole("checkbox", { name: "Выбрать строку" })).toBeChecked();
  await page.getByRole("switch", { name: "Включить правило" }).click();
  await expect(page.getByRole("switch", { name: "Включить правило" })).toBeChecked();
  await page.getByRole("radio", { name: "Полное" }).click();
  await expect(page.getByRole("radio", { name: "Полное" })).toBeChecked();

  // Вкладки и раскрытие
  await page.getByRole("tab", { name: "Исключения" }).click();
  await expect(page.getByText("Исключения со сроками")).toBeVisible();
  await page.getByRole("button", { name: "Трассировка решения" }).click();
  await expect(page.getByText("Детекторы и оценки")).toBeVisible();

  // Область прокрутки
  await expect(page.getByText("Длинное содержимое запроса")).toBeVisible();

  // Уведомление
  await page.getByRole("button", { name: "Опубликовать" }).click();
  await expect(page.getByText("Опубликовано", { exact: true }).first()).toBeVisible();

  // В разметке нет вставленных <style> и атрибутов style (кроме выставленных через CSSOM).
  const styleElements = await page.locator("style").count();
  expect(styleElements).toBe(0);
  expect(problems).toEqual([]);
});
