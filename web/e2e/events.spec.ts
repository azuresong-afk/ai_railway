import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const TOTAL = 5000;
const eid = (i: number) => `0190f3a2-0000-7000-8000-${String(i).padStart(12, "0")}`;
const event = (i: number) => ({
  id: eid(i),
  time: new Date(Date.now() - i * 1000).toISOString(),
  received_at: new Date(Date.now() - i * 1000 + 500).toISOString(),
  gateway_id: "0190f3a2-0000-7000-8000-0000000000aa",
  type: "gateway_request",
  app: i % 2 === 0 ? "crm-bot" : "helpdesk",
  action: i % 5 === 0 ? "block" : "allow",
  severity: i % 5 === 0 ? "high" : "info",
  storage: "masked",
  threats: i % 5 === 0 ? ["DM-01"] : [],
  stream: false,
  non_text_unchecked: false,
  has_content: true,
});

interface Seen {
  lists: URLSearchParams[];
  content: { id: string; reason: string }[];
}

// Подмена API событий поверх общей подмены входа: 5 000 событий страницами по 200 с курсором.
async function mockEvents(page: Page): Promise<Seen> {
  const seen: Seen = { lists: [], content: [] };
  await page.route("**/api/v1/events**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body), headers });
    if (url.pathname === "/api/v1/events" && req.method() === "GET") {
      seen.lists.push(url.searchParams);
      const filter = url.searchParams.get("filter") ?? "";
      const total = filter.includes("nothing") ? 0 : TOTAL;
      const start = Number(url.searchParams.get("cursor") ?? 0);
      const end = Math.min(start + 200, total);
      const items = Array.from({ length: end - start }, (_, k) => event(start + k));
      return json({ items, ...(end < total ? { next_cursor: String(end) } : {}) });
    }
    if (url.pathname === "/api/v1/events/filters") return json({ items: [] });
    if (url.pathname === "/api/v1/events/export") {
      return route.fulfill({
        status: 200,
        contentType: "text/csv",
        headers: { "X-Export-Rows": "5000", "Content-Disposition": 'attachment; filename="events.csv"' },
        body: "id,time\n",
      });
    }
    const m = /^\/api\/v1\/events\/([^/]+)(\/content)?$/.exec(url.pathname);
    if (m && m[2] && req.method() === "POST") {
      const reason = (req.postDataJSON() as { reason: string }).reason;
      seen.content.push({ id: m[1]!, reason });
      return json({ event_id: m[1], storage: "masked", request: "Запрос: <b>жирный</b> [СНИЛС]", response: "Ответ модели" });
    }
    if (m) {
      return json({
        ...event(0),
        id: m[1],
        details: {
          decision: {
            action: "block",
            applied: ["block"],
            rule: "pii-block",
            severity: "high",
            trace: [{ rule: "pii-block", detector: "pii.snils", matched: true, action: "block" }],
          },
          findings: [{ detector: "pii.snils", category: "pii", score: 0.97, start: 0, end: 11, location: "messages[0].content", threat: "DM-01" }],
        },
      });
    }
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

const perms = ["session", "events.read", "events.export", "events.content.read"];

test("события: виртуализация, подгрузка по курсору, чипы фильтра", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockEvents(page);
  await page.goto("/#/events");
  await expect(page.getByRole("heading", { name: "События" })).toBeVisible();
  const scroll = page.getByTestId("events-scroll");
  await expect(scroll.locator("tbody tr[data-index]").first()).toBeVisible();
  // В DOM только видимые строки, а не все загруженные.
  expect(await scroll.locator("tbody tr[data-index]").count()).toBeLessThan(80);

  // Прокрутка к концу подгружает следующие страницы по курсору.
  await scroll.evaluate((el) => el.scrollTo(0, el.scrollHeight));
  await expect.poll(() => seen.lists.length).toBeGreaterThan(1);
  expect(seen.lists[1]?.get("cursor")).toBe("200");
  expect(seen.lists[0]?.get("limit")).toBe("200");

  // Условие становится чипом и уходит в запрос; снимается одним кликом.
  await page.getByLabel("Поле").selectOption("app");
  await page.getByLabel("Значение").fill("crm-bot");
  await page.getByRole("button", { name: "Добавить условие" }).click();
  await expect(page.getByRole("list", { name: "Условия фильтра" })).toContainText("Приложение = crm-bot");
  await expect.poll(() => seen.lists.at(-1)?.get("filter")).toBe('app = "crm-bot"');
  await page.getByRole("button", { name: /Снять условие: Приложение/ }).click();
  await expect(page.getByRole("list", { name: "Условия фильтра" })).not.toContainText("crm-bot");
  // Результат без фильтра уже в кэше запросов, повторный запрос не нужен.
  await expect(scroll.locator("tbody tr[data-index]").first()).toBeVisible();
  done();
});

test("события: пустой результат предлагает снять условие", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  await mockEvents(page);
  await page.goto("/#/events?f=" + encodeURIComponent('app = "nothing"'));
  await expect(page.getByText("По этим условиям событий за период нет")).toBeVisible();
  await page.getByRole("button", { name: /^Снять: Приложение/ }).click();
  await expect(page.getByTestId("events-scroll")).toBeVisible();
  done();
});

test("события: карточка, содержимое по причине и выгрузка", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockEvents(page);
  await page.goto("/#/events");
  await page.getByRole("button", { name: /^Открыть событие/ }).first().click();
  const card = page.getByRole("complementary", { name: "Карточка события" });
  await expect(card.getByRole("heading", { name: "Почему принято решение" })).toBeVisible();
  await expect(card.getByRole("table", { name: "Находки" })).toContainText("DM-01");
  expect(seen.content).toEqual([]);

  await card.getByRole("button", { name: "Показать содержимое" }).click();
  await page.getByLabel("Причина просмотра").fill("Разбор инцидента 42");
  await page.getByRole("dialog").getByRole("button", { name: "Показать содержимое" }).click();
  // HTML из содержимого выводится как текст.
  await expect(card.getByText("<b>жирный</b>", { exact: false })).toBeVisible();
  await expect(card.locator("b")).toHaveCount(0);
  expect(seen.content).toHaveLength(1);
  expect(seen.content[0]?.reason).toBe("Разбор инцидента 42");

  await card.getByRole("button", { name: "Скрыть содержимое" }).click();
  await expect(card.getByText("Ответ модели")).toHaveCount(0);

  const dl = page.waitForEvent("download");
  await page.getByRole("button", { name: "Выгрузить CSV" }).click();
  expect((await dl).suggestedFilename()).toMatch(/^events-\d+\.csv$/);
  await expect(page.getByText("5 000 строк", { exact: false })).toBeVisible();
  done();
});

test("события: без прав на содержимое и выгрузку кнопок нет", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "events.read"]) });
  await mockEvents(page);
  await page.goto("/#/events");
  await page.getByRole("button", { name: /^Открыть событие/ }).first().click();
  const card = page.getByRole("complementary", { name: "Карточка события" });
  await expect(card.getByRole("heading", { name: "Почему принято решение" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Показать содержимое" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Выгрузить/ })).toHaveCount(0);

  done();
});

test("события: без events.read раздела нет", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session"]) });
  await mockEvents(page);
  await page.goto("/#/events");
  await expect(page.getByRole("link", { name: "События" })).toHaveCount(0);
  await expect(page.getByText("Нет доступа к событиям")).toBeVisible();
  done();
});
