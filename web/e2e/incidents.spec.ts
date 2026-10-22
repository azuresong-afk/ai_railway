import { expect, type Page, test } from "@playwright/test";
import { meOf, mockApi } from "./mock-api";
import { watch } from "./watch";

const NOW = new Date().toISOString();
const EVENT_ID = "0190f3a2-0000-7000-8000-000000000001";
const alert = {
  id: "al-1", rule_id: "r-1", rule_name: "Утечка канарейки", kind: "threshold", severity: "critical", title: "Утечка системного промпта",
  status: "new", group: { app: "support-bot" }, count: 3, suppressed: 0, first_event_at: NOW, last_event_at: NOW, created_at: NOW,
  last_triggered_at: NOW, updated_at: NOW,
};
const event = {
  id: EVENT_ID, time: NOW, received_at: NOW, gateway_id: "0190f3a2-0000-7000-8000-0000000000aa", type: "gateway_request", app: "support-bot",
  action: "block", severity: "critical", storage: "none", threats: ["DM-08"], stream: false, non_text_unchecked: false, has_content: false,
};

interface Seen {
  calls: { method: string; path: string; body: unknown }[];
}
const json = (route: import("@playwright/test").Route, b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
const bodyOf = (req: import("@playwright/test").Request): unknown => {
  try {
    return req.postDataJSON();
  } catch {
    return undefined;
  }
};

// Путь S8 «оповещение → события → инцидент → закрытие»: состояние инцидента хранится между запросами.
async function mockS8(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  const inc: Record<string, unknown> = {
    id: "inc-1", number: 7, title: alert.title, severity: "critical", category: "system_prompt_leak", status: "new", source: "alert",
    reaction_due_at: new Date(Date.now() + 3_600_000).toISOString(), overdue: false, created_at: NOW, created_by: "system", updated_at: NOW, updated_by: "system", version: 1,
  };
  let created = false;
  const timeline: unknown[] = [{ at: NOW, actor: "system", kind: "created", details: {} }];
  await page.route(/\/api\/v1\/(alerts|incidents|incident-categories|events)/, async (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const body = bodyOf(req);
    seen.calls.push({ method: req.method(), path: p, body });
    if (p === "/api/v1/alerts") return json(route, { items: [{ ...alert, ...(created ? { incident_id: "inc-1" } : {}) }] });
    if (p === "/api/v1/alerts/al-1") return json(route, { ...alert, ...(created ? { incident_id: "inc-1" } : {}), events: [{ id: EVENT_ID, ts: NOW }], events_truncated: false, history: [], details: {} });
    if (p === "/api/v1/incidents" && req.method() === "POST") {
      created = true;
      return json(route, inc, 201);
    }
    if (p === "/api/v1/incidents") return json(route, { items: created ? [inc] : [] });
    if (p === "/api/v1/incident-categories") return json(route, { items: [{ id: "system_prompt_leak", title: "Утечка системного промпта", rows: ["DM-08"], instruction: { category: "system_prompt_leak", body: "Смените системный промпт.", version: 1, default: true } }] });
    if (p === "/api/v1/incidents/inc-1/status") {
      const b = body as { status: string; resolution?: string };
      Object.assign(inc, { status: b.status, ...(b.resolution ? { resolution: b.resolution, closed_at: NOW, closed_by: "ivanov" } : {}) });
      timeline.push({ at: NOW, actor: "ivanov", kind: "status_changed", details: { from: "new", to: b.status, ...(b.resolution ? { resolution: b.resolution } : {}) } });
      return json(route, inc);
    }
    if (p === "/api/v1/incidents/inc-1") {
      return json(route, {
        ...inc, category_title: "Утечка системного промпта",
        stages: [{ key: "intake", title: "Приём сообщения" }, { key: "triage", title: "Сбор первичных сведений" }, { key: "containment", title: "Локализация" }, { key: "investigation", title: "Сбор сведений для расследования" }],
        timeline, comments: [],
        alerts: [{ id: "al-1", rule_id: "r-1", rule_name: alert.rule_name, title: alert.title, severity: "critical", status: "new", count: 3, created_at: NOW }],
        events: [{ id: EVENT_ID, ts: NOW }], events_truncated: false,
        instruction: { category: "system_prompt_leak", body: "Смените системный промпт.", version: 1, default: true },
      });
    }
    if (p === "/api/v1/events") return json(route, { items: [event] });
    if (p === "/api/v1/events/filters") return json(route, { items: [] });
    if (p === `/api/v1/events/${EVENT_ID}`) return json(route, { ...event, details: {} });
    return json(route, { code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("инциденты: оповещение → события → инцидент → закрытие (S8)", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "alerts.read", "alerts.manage", "events.read", "incidents.read", "incidents.manage"]) });
  const seen = await mockS8(page);

  await page.goto("/#/alerts");
  await page.getByRole("button", { name: "Открыть оповещение: Утечка системного промпта" }).click();
  const alertCard = page.getByRole("complementary", { name: "Карточка оповещения" });
  // Переход к событиям оповещения и возврат.
  await alertCard.getByRole("link", { name: /Событие от/ }).click();
  await expect(page.getByRole("heading", { name: "События" })).toBeVisible();
  await expect(page).toHaveURL(/#\/events\?.*event=0190f3a2/);
  await page.goBack();

  await page.getByRole("button", { name: "Открыть оповещение: Утечка системного промпта" }).click();
  await page.getByRole("complementary", { name: "Карточка оповещения" }).getByRole("button", { name: "Создать инцидент" }).click();

  // Открылась карточка нового инцидента.
  await expect(page).toHaveURL(/#\/incidents\?id=inc-1/);
  const card = page.getByRole("complementary", { name: "Карточка инцидента" });
  await expect(card.getByText("Инцидент № 7: Утечка системного промпта")).toBeVisible();
  await expect(card.getByRole("region", { name: "Инструкция реагирования" })).toContainText("Смените системный промпт.");

  await card.getByRole("button", { name: "Взять в работу" }).click();
  await page.getByRole("dialog", { name: "Взять в работу" }).getByRole("button", { name: "Взять в работу" }).click();
  await expect(card.getByRole("button", { name: "Отметить локализованным" })).toBeVisible();

  await card.getByRole("button", { name: "Отметить локализованным" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Отметить локализованным" }).click();

  // Закрытие без резолюции невозможно, с резолюцией — уходит на сервер.
  await card.getByRole("button", { name: "Закрыть инцидент" }).click();
  const dlg = page.getByRole("dialog", { name: "Закрыть инцидент" });
  await expect(dlg.getByRole("button", { name: "Закрыть инцидент" })).toBeDisabled();
  await dlg.getByLabel("Резолюция").selectOption("resolved");
  await dlg.getByRole("button", { name: "Закрыть инцидент" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(card.getByText(/Закрыт: Устранён/)).toBeVisible();
  await expect(card.getByRole("button", { name: "Закрыть инцидент" })).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Открыть заново" })).toBeVisible();

  const statuses = seen.calls.filter((c) => c.path.endsWith("/status")).map((c) => c.body);
  expect(statuses).toEqual([{ status: "in_progress" }, { status: "contained" }, { status: "closed", resolution: "resolved" }]);
  expect(seen.calls.find((c) => c.method === "POST" && c.path === "/api/v1/incidents")?.body).toEqual({ alert_id: "al-1" });

  // Доска: закрытый инцидент в колонке «Закрыт».
  await page.getByRole("button", { name: "Доска" }).click();
  await expect(page.getByRole("region", { name: "Статус: Закрыт" }).getByText("Утечка системного промпта")).toBeVisible();
  done();
});

test("инциденты: без права управления кнопок изменения нет", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "incidents.read"]) });
  await mockS8(page);
  // Инцидент появляется в списке только после создания; для чтения открываем его прямой ссылкой.
  await page.goto("/#/incidents?id=inc-1");
  const card = page.getByRole("complementary", { name: "Карточка инцидента" });
  await expect(card.getByText("Инцидент № 7: Утечка системного промпта")).toBeVisible();
  await expect(card.getByRole("button", { name: "Взять в работу" })).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Добавить комментарий" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Создать инцидент" })).toHaveCount(0);
  done();
});

const rule = { id: "pii-ru", detector: "pii.snils", action: "block", severity: "high" };
const policy = { id: "mine", name: "Моя политика", mode: "enforce", template: false, current_version: 2, updated_at: NOW };

// Путь «ложное срабатывание → исключение»: отметка и исключение хранятся между запросами.
async function mockFalsePositive(page: Page): Promise<Seen> {
  const seen: Seen = { calls: [] };
  let mark: unknown;
  let version = 2;
  const exceptions: unknown[] = [];
  await page.route(/\/api\/v1\/(events|policies)/, async (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const body = bodyOf(req);
    seen.calls.push({ method: req.method(), path: p, body });
    if (p === "/api/v1/events") return json(route, { items: [{ ...event, ...(mark ? { mark } : {}) }] });
    if (p === "/api/v1/events/filters") return json(route, { items: [] });
    if (p === `/api/v1/events/${EVENT_ID}/mark`) {
      const b = body as { mark: string; comment?: string };
      mark = { mark: b.mark, ...(b.comment ? { comment: b.comment } : {}), marked_at: NOW, marked_by: "user:u1", marked_by_name: "Иван Иванов" };
      return json(route, { event_id: EVENT_ID, mark });
    }
    if (p === `/api/v1/events/${EVENT_ID}/exception-draft`) {
      return json(route, {
        event_id: EVENT_ID, policy: "mine", policy_version: version, base_version: version, template: false,
        items: [{ detector: "pii.snils", category: "pii.snils", pattern: "snils-rule", fragment: "abcdef0123456789", app: "support-bot" }],
      });
    }
    if (p === `/api/v1/events/${EVENT_ID}`) return json(route, { ...event, ...(mark ? { mark } : {}), details: {} });
    if (p === "/api/v1/policies/mine/exceptions" && req.method() === "POST") {
      const b = body as Record<string, unknown>;
      if (b.password !== "Correct-Horse-1") return json(route, { code: "reauthentication_failed", detail: "Неверный пароль." }, 422);
      version += 1;
      exceptions.push({ id: "exc-1", detector: b.detector, pattern: b.pattern, app: b.app, reason: b.reason, author: "ivanov", expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(), status: "active", event_id: b.event_id });
      return json(route, { policy: { ...policy, current_version: version, spec: { name: policy.name, mode: "enforce", rules: [rule] } } });
    }
    if (p === "/api/v1/policies/mine/exceptions") return json(route, { policy: "mine", version, items: exceptions });
    if (p === "/api/v1/policies") return json(route, { items: [{ ...policy, current_version: version }] });
    if (p === "/api/v1/policies/mine/versions") return json(route, { items: [] });
    if (p === "/api/v1/policies/mine") return json(route, { ...policy, current_version: version, spec: { name: policy.name, mode: "enforce", rules: [rule] } });
    return json(route, { code: "not_found", detail: "Нет такого маршрута." }, 404);
  });
  return seen;
}

test("события: ложное срабатывание → исключение → экран исключений", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "events.read", "events.mark", "policies.read", "policies.manage"]) });
  const seen = await mockFalsePositive(page);

  await page.goto(`/#/events?event=${EVENT_ID}`);
  const card = page.getByRole("complementary", { name: "Карточка события" });
  await card.getByRole("button", { name: "Ложное срабатывание" }).click();
  const markDlg = page.getByRole("dialog");
  await markDlg.getByLabel("Комментарий").fill("тестовый СНИЛС");
  await markDlg.getByRole("button", { name: "Поставить отметку" }).click();
  await expect(card.getByText(/Ложное срабатывание: .*Иван Иванов/)).toBeVisible();
  await expect(card.getByText("тестовый СНИЛС")).toBeVisible();

  await card.getByRole("button", { name: "Создать исключение" }).click();
  const dlg = page.getByRole("dialog", { name: "Создать исключение" });
  await expect(dlg.getByText("Условия исключения (соединяются «и»)")).toBeVisible();
  await dlg.getByRole("checkbox", { name: /Фрагмент текста/ }).click();
  await dlg.getByLabel("Текущий пароль").fill("Correct-Horse-1");
  await dlg.getByRole("button", { name: "Добавить исключение" }).click();
  await expect(dlg.getByText(/версия 3 политики «Моя политика»/)).toBeVisible();
  await dlg.getByRole("button", { name: "Готово" }).click();

  const posted = seen.calls.find((c) => c.method === "POST" && c.path.endsWith("/exceptions"))?.body as Record<string, unknown>;
  expect(posted).toMatchObject({ detector: "pii.snils", pattern: "snils-rule", app: "support-bot", base_version: 2, event_id: EVENT_ID, expires_in_days: 30 });
  expect(posted).not.toHaveProperty("fragment");

  // Исключение видно на экране политики.
  await page.goto("/#/policies");
  await page.getByRole("button", { name: "Открыть политику Моя политика" }).click();
  await page.getByRole("tab", { name: "Исключения" }).click();
  const active = page.getByRole("region", { name: "Действующие исключения" });
  await expect(active.getByText(/правило snils-rule; приложение support-bot/)).toBeVisible();
  done();
});

test("события: без прав отметки и исключения кнопок нет", async ({ page }) => {
  const done = watch(page);
  await mockApi(page, { me: meOf("active", ["session", "self", "events.read"]) });
  await mockFalsePositive(page);
  await page.goto(`/#/events?event=${EVENT_ID}`);
  const card = page.getByRole("complementary", { name: "Карточка события" });
  await expect(card.getByRole("heading", { name: "Почему принято решение" })).toBeVisible();
  await expect(card.getByRole("button", { name: "Ложное срабатывание" })).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Создать исключение" })).toHaveCount(0);
  done();
});
