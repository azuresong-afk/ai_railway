import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

// Настоящие графики ECharts при строгом CSP (ТЗ 6.9, 6.6): SVG-рендерер не должен нарушать политику.
const period = { name: "24h", from: "2026-10-21T10:00:00Z", to: "2026-10-22T10:00:00Z", unit: "hour", timezone: "Europe/Moscow", aggregates_ready: true };
const totals = { requests: 1200, with_findings: 300, non_text_unchecked: 4, blocked: 20, would_block: 5, masked: 70, tokens_prompt: 5000, tokens_completion: 7000, cost: "12.5000000", unpriced_requests: 3 };
const overview = {
  period,
  totals,
  latency: { p95_ms: 25, overflow: false, requests: 1200 },
  decisions: [
    { bucket: "2026-10-22T08:00:00Z", key: "allowed", value: 90 },
    { bucket: "2026-10-22T08:00:00Z", key: "blocked", value: 10 },
    { bucket: "2026-10-22T09:00:00Z", key: "masked", value: 30 },
  ],
  top_detectors: [{ key: "pii.regex", value: 40 }],
  apps: [{ key: "support-bot", requests: 900, with_findings: 200, blocked: 15, would_block: 0, masked: 50, tokens_prompt: 1, tokens_completion: 1, cost: "1", unpriced_requests: 0 }],
  feed: [{ id: "6f1c0000-0000-4000-8000-000000000001", time: "2026-10-22T09:30:00Z", app: "support-bot", model: "gpt-x", action: "block", policy_mode: "enforce", severity: "high", rule: "R-1", threats: ["DM-01"] }],
};
const row = (key: string) => ({ key, requests: 10, with_findings: 1, blocked: 0, would_block: 0, masked: 0, tokens_prompt: 100, tokens_completion: 200, cost: "1.5000000", unpriced_requests: 0 });
const consumption = {
  period: { ...period, name: "30d", unit: "day" },
  totals,
  series: [
    { bucket: "2026-10-20T00:00:00Z", requests: 50, tokens: 3000, cost: "7.0000000" },
    { bucket: "2026-10-21T00:00:00Z", requests: 70, tokens: 4000, cost: "9.0000000" },
  ],
  by_app: [row("support-bot")], by_model: [row("gpt-x")], by_provider: [], by_department: [], by_user: [],
  forecast: { month: "2026-10", spent: "16.0000000", projected: "40.0000000", enough: true, month_elapsed: 0.7 },
  budgets: [],
};

async function mockDash(page: Page) {
  await page.route(/\/api\/v1\/dashboards\//, (route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    if (url.pathname === "/api/v1/dashboards/overview") return json(overview);
    if (url.pathname === "/api/v1/dashboards/consumption") return json(consumption);
    if (url.pathname === "/api/v1/dashboards/stream") {
      return route.fulfill({ status: 200, contentType: "text/event-stream", body: `event: snapshot\ndata: ${JSON.stringify({ ...overview, totals: { ...totals, requests: 1300 } })}\n\n` });
    }
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ code: "not_found", detail: "Нет маршрута." }) });
  });
}

test("обзор: график рисуется при строгом CSP, данные доступны таблицей", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "dashboards.read", "events.read"]) });
  await mockDash(page);
  await page.goto("/#/");
  await expect(page.getByText("1 200", { exact: true })).toBeVisible();
  // ECharts в режиме SVG кладёт в контейнер элемент svg.
  const chart = page.getByRole("img", { name: /запросы по решениям политики/ });
  await expect(chart.locator("svg").first()).toBeVisible();
  // Подсказка при наведении (3Н45 ревью 3.r3): в режиме HTML ECharts пишет style через innerHTML,
  // и watch() ловит нарушение CSP; в режиме richText подсказка — текст внутри SVG.
  await chart.hover();
  await page.mouse.move(0, 0);
  await chart.hover({ position: { x: 120, y: 120 } });
  await page.waitForTimeout(300);
  await page.getByRole("button", { name: "Показать данные таблицей" }).first().click();
  await expect(page.getByRole("table", { name: "Данные: Запросы по решениям" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Лента решений" }).getByText("R-1")).toBeVisible();
  done();
});

test("обзор: режим реального времени подменяет данные снимком потока", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "dashboards.read", "events.read"]) });
  await mockDash(page);
  await page.goto("/#/");
  await expect(page.getByText("1 200", { exact: true })).toBeVisible();
  await page.getByRole("checkbox", { name: "Обновлять в реальном времени" }).click();
  await expect(page.getByText("1 300", { exact: true })).toBeVisible();
  done();
});

test("потребление: расход, прогноз и график при строгом CSP", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "dashboards.read"]) });
  await mockDash(page);
  await page.goto("/#/usage");
  await expect(page.getByRole("heading", { name: "Потребление", exact: true })).toBeVisible();
  await expect(page.getByText("Прогноз на 2026-10")).toBeVisible();
  await expect(page.getByRole("img", { name: /запросы и токены во времени/ }).locator("svg").first()).toBeVisible();
  await expect(page.getByRole("tab", { name: "Цены моделей" })).toHaveCount(0);
  done();
});
