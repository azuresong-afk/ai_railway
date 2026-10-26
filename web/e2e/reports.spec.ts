import { expect, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const page_html = "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><title>Сводный отчёт</title></head><body><h1>Сводный отчёт</h1></body></html>";

// Отчёты при строгом CSP консоли: страница отчёта открывается в рамке без скриптов и без нарушений.
test("отчёты: предпросмотр в рамке sandbox при строгом CSP", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "reports.read", "applications.read"]) });
  await page.route(/\/api\/v1\/(reports|applications)/, (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith("/api/v1/reports/")) {
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: page_html });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [], next_cursor: "" }) });
  });
  await page.goto("/#/reports");
  await expect(page.getByRole("heading", { name: "Отчёты", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Показать отчёт" }).click();
  const frame = page.frameLocator("iframe[title='Предпросмотр отчёта']");
  await expect(frame.getByRole("heading", { name: "Сводный отчёт" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Скачать XLSX" })).toHaveAttribute("href", /format=xlsx/);
  done();
});
