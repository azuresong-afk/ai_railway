import { expect, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const item = {
  id: "f117.p60.filter", source: "fstec-117", source_title: "Приказ ФСТЭК № 117", clause: "п. 60", title: "Фильтрация входа и выхода", summary: "Пересказ требования",
  applies: ["gis"], draft: false, manual: false, status: "partial",
  checks: [{ name: "filter_enforced", title: "Фильтрация включена", status: "partial", detail: "5 из 7 приложений промышленной среды" }],
  evidence: [{ kind: "screen", title: "Приложения: политика и режим", path: "/apps" }],
};

test("соответствие: процент, пункт с доказательствами при строгом CSP", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "compliance.read"]) });
  await page.route("**/api/v1/compliance**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        generated_at: "2026-10-28T10:00:00Z", base: { version: 1, date: "2026-10-28", origin: "builtin", requirements: 1 },
        sources: [{ id: "fstec-117", title: "Приказ ФСТЭК № 117" }],
        summary: { percent: 50, counts: { met: 0, partial: 1, not_met: 0, not_applicable: 0, manual: 0 }, counted: 1, drafts: 0 },
        items: [item], unavailable: [],
      }),
    }),
  );
  await page.goto("/");
  await page.getByRole("link", { name: "Соответствие" }).click();
  await expect(page.getByRole("heading", { name: "Соответствие требованиям", level: 1 })).toBeVisible();
  await expect(page.getByText("50 %")).toBeVisible();
  await page.getByRole("button", { name: /Показать подробности: Фильтрация входа и выхода/ }).click();
  await expect(page.getByText(/5 из 7 приложений промышленной среды/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Поставить отметку" })).toHaveCount(0);
  done();
});

test("соответствие: без compliance.read раздела нет в меню, прямой адрес — отказ", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "system.read"]) });
  await page.goto("/#/compliance");
  await expect(page.getByText("Нет доступа: соответствие")).toBeVisible();
  await expect(page.getByRole("link", { name: "Соответствие" })).toHaveCount(0);
  done();
});
