import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const NOW = new Date().toISOString();
const alert = {
  id: "al-1", rule_id: "r-1", rule_name: "Всплеск блокировок", kind: "threshold", severity: "high", title: "Много блокировок инъекций",
  status: "new", group: { app: "support-bot" }, count: 7, suppressed: 0, first_event_at: NOW, last_event_at: NOW, created_at: NOW,
  last_triggered_at: NOW, updated_at: NOW,
};
const perms = ["session", "self", "alerts.read", "alerts.manage", "events.read"];

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}

// Подмена API оповещений поверх общей подмены входа; статус хранится между запросами.
async function mockAlerts(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  let status = "new";
  await page.route(/\/api\/v1\/(alerts|alert-rules|events)/, async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    let body: unknown;
    try {
      body = req.postDataJSON();
    } catch {
      body = undefined;
    }
    seen.calls.push({ method: req.method(), path: url.pathname, body });
    const json = (b: unknown, code = 200) => route.fulfill({ status: code, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p === "/api/v1/alerts") return json({ items: [{ ...alert, status }] });
    if (p === "/api/v1/alerts/al-1/status") {
      status = (body as { status: string }).status;
      return json({ ...alert, status });
    }
    if (p === "/api/v1/alerts/al-1") {
      return json({
        ...alert, status, events: [{ id: "ev-1", ts: NOW }], events_truncated: false, details: {},
        history: status === "new" ? [] : [{ at: NOW, actor: "ivanov", from: "new", to: status, comment: "" }],
      });
    }
    if (p === "/api/v1/events") return json({ items: [] });
    // Экран «События» при переходе из карточки загружает сохранённые фильтры.
    if (p === "/api/v1/events/filters") return json({ items: [] });
    return json({ code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("оповещения: оповещение → карточка → в работе → закрыто", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", perms) });
  const seen = await mockAlerts(page);
  await page.goto("/#/alerts");
  await expect(page.getByRole("heading", { name: "Оповещения" })).toBeVisible();
  await page.getByRole("button", { name: "Открыть оповещение: Много блокировок инъекций" }).click();
  const card = page.getByRole("complementary", { name: "Карточка оповещения" });
  await expect(card.getByText("support-bot")).toBeVisible();

  await card.getByRole("button", { name: "Принять в работу" }).click();
  await page.getByRole("dialog", { name: "Принять оповещение в работу" }).getByRole("button", { name: "Принять в работу" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(card.getByText(/Новое → В работе/)).toBeVisible();

  await card.getByRole("button", { name: "Закрыть оповещение" }).click();
  await page.getByRole("dialog", { name: "Закрыть оповещение" }).getByRole("button", { name: "Закрыть", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Закрыть оповещение" })).toHaveCount(0);

  const sent = seen.calls.filter((c) => c.path.endsWith("/status")).map((c) => c.body);
  expect(sent).toEqual([{ status: "in_progress" }, { status: "closed" }]);

  // Переход к событиям: экран «События» открывается с фильтром по значениям группировки.
  await card.getByRole("link", { name: "Открыть события с этими значениями" }).click();
  await expect(page.getByRole("heading", { name: "События" })).toBeVisible();
  await expect(page).toHaveURL(/#\/events\?.*f=app/);
  done();
});

test("оповещения: без права управления кнопок статуса нет", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "alerts.read"]) });
  await mockAlerts(page);
  await page.goto("/#/alerts");
  await page.getByRole("button", { name: /Открыть оповещение/ }).click();
  await expect(page.getByRole("complementary", { name: "Карточка оповещения" }).getByText("support-bot")).toBeVisible();
  await expect(page.getByRole("button", { name: "Принять в работу" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Закрыть оповещение" })).toHaveCount(0);
  done();
});
