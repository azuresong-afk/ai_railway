import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { type Alert, type AlertRule, type NotifyChannel } from "./api";
import { AlertsScreen } from "./AlertsScreen";
import { eventLink, eventsLink, eventsPeriod } from "./format";

const me = (permissions: string[], mfa = false): Me => ({
  user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
  ...(mfa ? { mfa: { enabled: true } } : {}),
}) as Me;

const NOW = "2026-10-22T10:00:00Z";
const alert = (o: Partial<Alert> = {}): Alert => ({
  id: "al-1", rule_id: "r-1", rule_name: "Всплеск блокировок", kind: "threshold", severity: "high", title: "Много блокировок инъекций",
  status: "new", group: { app: "support-bot" }, count: 7, suppressed: 0, first_event_at: NOW, last_event_at: NOW, created_at: NOW,
  last_triggered_at: NOW, updated_at: NOW, ...o,
});
const rule = (o: Partial<AlertRule> = {}): AlertRule => ({
  id: "r-1", kind: "threshold", name: "Всплеск блокировок", description: "", enabled: true, locked: false, severity: "high",
  condition: { filter: 'action = "block"' }, group_by: ["app"], suppress_minutes: 60, group_minutes: 0, recipients: { roles: [], users: [] },
  effective_roles: ["security_admin", "auditor"], version: 3, created_at: NOW, created_by: "sec", updated_at: NOW, updated_by: "sec", ...o,
});
const channel = (o: Partial<NotifyChannel> = {}): NotifyChannel => ({
  id: "c-1", name: "Почта SOC", type: "email", enabled: true, min_severity: "medium",
  settings: { host: "smtp.corp.example", port: 587, username: "aisec", from: "aisec@corp.example", to: ["soc@corp.example"], ca_pem: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----" },
  secrets_set: ["password"], audit_stream: false, version: 2, created_at: NOW, created_by: "sec", updated_at: NOW, updated_by: "sec", ...o,
});
const card = (a: Alert) => ({ ...a, events: [{ id: "ev-1", ts: NOW }], events_truncated: false, history: [], details: {} });

type JsonBody = ReturnType<typeof JSON.parse>;
type Call = { method: string; url: string; body: JsonBody };
const calls: Call[] = [];
let store: { alerts: Alert[]; rules: AlertRule[]; channels: NotifyChannel[]; retention: number };
let handler: (c: Call) => Response | undefined;

const problem = (status: number, code: string, detail: string, errors?: unknown) =>
  new Response(JSON.stringify({ status, code, detail, ...(errors ? { errors } : {}) }), { status });
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  // jsdom не считает размеры: виртуальная таблица получает окно 800×600.
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockReturnValue({ width: 800, height: 600, top: 0, left: 0, right: 800, bottom: 600, x: 0, y: 0, toJSON: () => ({}) });
  for (const [k, v] of [["offsetHeight", 600], ["offsetWidth", 800], ["clientHeight", 600], ["clientWidth", 800]] as const) {
    vi.spyOn(HTMLElement.prototype, k, "get").mockReturnValue(v);
  }
  calls.length = 0;
  handler = () => undefined;
  store = { alerts: [alert()], rules: [rule(), rule({ id: "r-2", name: "Недоступность шлюза", kind: "system", locked: true, builtin: "system.gateway" })], channels: [channel()], retention: 365 };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const r = (x: Response) => Promise.resolve(x);
      if (url.startsWith("/api/v1/alerts?")) return r(json({ items: store.alerts }));
      if (url === "/api/v1/alerts/al-1" && method === "GET") return r(json(card(store.alerts[0]!)));
      if (url === "/api/v1/alerts/al-1/status") return r(json({ ...store.alerts[0], status: c.body.status }));
      if (url === "/api/v1/incidents" && method === "POST") return r(json({ id: "inc-1" }, 201));
      if (url === "/api/v1/alert-rules" && method === "GET") return r(json({ items: store.rules }));
      if (url === "/api/v1/alert-rules" && method === "POST") return r(json(rule({ id: "r-9", name: c.body.name }), 201));
      if (url.startsWith("/api/v1/alert-rules/") && method === "PUT") return r(json(rule({ id: url.split("/").pop()! })));
      if (url === "/api/v1/alert-settings" && method === "GET") return r(json({ retention_days: store.retention }));
      if (url === "/api/v1/alert-settings" && method === "PUT") return r(json({ retention_days: c.body.retention_days }));
      if (url === "/api/v1/notify-channels" && method === "GET") return r(json({ items: store.channels }));
      if (url === "/api/v1/notify-channels" && method === "POST") return r(json(channel({ id: "c-9", name: c.body.name, type: c.body.type }), 201));
      if (url === "/api/v1/notify-channels/c-1" && method === "PUT") return r(json(channel()));
      if (url === "/api/v1/notify-channels/c-1/test") return r(json({ id: "d-1", channel_id: "c-1", kind: "test", status: "failed", attempts: 1, error: "tls", created_at: NOW, updated_at: NOW }));
      if (url.startsWith("/api/v1/notify-channels/c-1/deliveries")) return r(json({ items: [{ id: "d-1", channel_id: "c-1", kind: "alert", status: "sent", attempts: 1, created_at: NOW, updated_at: NOW }] }));
      if (url === "/api/v1/roles") return r(json({ items: [{ id: "analyst", display_name: "Аналитик", description: "", builtin: true, mfa_required: false, permissions: [] }] }));
      return r(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AlertsScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const tab = (name: string) => fireEvent.mouseDown(screen.getByRole("tab", { name }), { button: 0 }) ?? fireEvent.click(screen.getByRole("tab", { name }));
const allPerms = ["alerts.read", "alerts.manage", "alert_rules.read", "alert_rules.manage", "notify_channels.read", "notify_channels.manage", "events.read", "roles.read"];

describe("экран «Оповещения»: список и карточка", () => {
  it("оповещение → карточка → в работе → закрыто", async () => {
    renderScreen(allPerms);
    fireEvent.click(await screen.findByRole("button", { name: "Открыть оповещение: Много блокировок инъекций" }));
    const aside = await screen.findByRole("complementary", { name: "Карточка оповещения" });
    await within(aside).findByText("support-bot");
    fireEvent.click(within(aside).getByRole("button", { name: "Принять в работу" }));
    const dlg = await screen.findByRole("dialog", { name: "Принять оповещение в работу" });
    fireEvent.change(within(dlg).getByLabelText("Комментарий"), { target: { value: "беру" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Принять в работу" }));
    await waitFor(() => expect(calls.find((c) => c.url === "/api/v1/alerts/al-1/status")?.body).toEqual({ status: "in_progress", comment: "беру" }));

    // Закрытие без комментария: поле comment не отправляется.
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.click(within(aside).getByRole("button", { name: "Закрыть оповещение" }));
    const d2 = await screen.findByRole("dialog", { name: "Закрыть оповещение" });
    fireEvent.click(within(d2).getByRole("button", { name: "Закрыть" }));
    await waitFor(() => expect(calls.filter((c) => c.url.endsWith("/status")).at(-1)?.body).toEqual({ status: "closed" }));
  });

  it("период отбирает сервер: в запрос уходит from", async () => {
    renderScreen(allPerms);
    await screen.findByRole("button", { name: /Открыть оповещение/ });
    expect(calls.find((c) => c.url.startsWith("/api/v1/alerts?"))?.url).not.toContain("from=");
    fireEvent.change(screen.getByLabelText("Период"), { target: { value: "7d" } });
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/api/v1/alerts?") && c.url.includes("from="))).toBe(true));
  });

  it("ссылки на события ведут на экран «События» с фильтром по группе", async () => {
    renderScreen(allPerms);
    fireEvent.click(await screen.findByRole("button", { name: /Открыть оповещение/ }));
    const link = await screen.findByRole("link", { name: "Открыть события с этими значениями" });
    expect(link.getAttribute("href")).toContain("/events?");
    expect(decodeURIComponent(link.getAttribute("href")!.replace(/\+/g, " "))).toContain('f=app = "support-bot"');
    expect(screen.getByRole("link", { name: /Событие от/ }).getAttribute("href")).toContain("event=ev-1");
  });

  it("без alerts.manage кнопок смены статуса нет", async () => {
    renderScreen(["alerts.read", "events.read"]);
    fireEvent.click(await screen.findByRole("button", { name: /Открыть оповещение/ }));
    await screen.findByRole("complementary", { name: "Карточка оповещения" });
    expect(screen.queryByRole("button", { name: "Принять в работу" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Закрыть оповещение" })).toBeNull();
    // Вкладок правил, каналов и срока хранения тоже нет.
    expect(screen.queryByRole("tab", { name: "Правила" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Каналы" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Срок хранения" })).toBeNull();
  });

  it("«Создать инцидент» видна только с incidents.manage и отправляет alert_id", async () => {
    const { unmount } = renderScreen([...allPerms, "incidents.manage"]);
    fireEvent.click(await screen.findByRole("button", { name: /Открыть оповещение/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Создать инцидент" }));
    await waitFor(() => expect(calls.find((c) => c.url === "/api/v1/incidents")?.body).toEqual({ alert_id: "al-1" }));
    unmount();
    renderScreen(allPerms);
    fireEvent.click(await screen.findByRole("button", { name: /Открыть оповещение/ }));
    await screen.findByRole("complementary", { name: "Карточка оповещения" });
    expect(screen.queryByRole("button", { name: "Создать инцидент" })).toBeNull();
  });

  it("сервер отказал (403): диалог остаётся с ошибкой", async () => {
    handler = (c) => (c.url.endsWith("/status") ? problem(403, "forbidden", "Недостаточно прав.") : undefined);
    renderScreen(allPerms);
    fireEvent.click(await screen.findByRole("button", { name: /Открыть оповещение/ }));
    const aside = await screen.findByRole("complementary", { name: "Карточка оповещения" });
    fireEvent.click(await within(aside).findByRole("button", { name: "Закрыть оповещение" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Закрыть" }));
    await within(dlg).findByText(/Сервер отказал в действии. Недостаточно прав./);
  });

  it("пустой список и ошибка загрузки", async () => {
    store.alerts = [];
    const { unmount } = renderScreen(allPerms);
    await screen.findByText("Оповещений пока нет");
    unmount();
    handler = (c) => (c.url.startsWith("/api/v1/alerts?") ? problem(500, "internal", "x") : undefined);
    renderScreen(allPerms);
    await screen.findByText(/Внутренняя ошибка сервера/);
  });

  it("фильтры уходят в запрос", async () => {
    renderScreen(allPerms);
    await screen.findByRole("button", { name: /Открыть оповещение/ });
    fireEvent.change(screen.getByLabelText("Статус"), { target: { value: "closed" } });
    fireEvent.change(screen.getByLabelText("Серьёзность"), { target: { value: "critical" } });
    await waitFor(() => expect(calls.some((c) => c.url.includes("status=closed") && c.url.includes("severity=critical"))).toBe(true));
  });
});

describe("правила", () => {
  it("системное правило — только получатели; без права управления — только просмотр", async () => {
    const { unmount } = renderScreen(allPerms);
    tab("Правила");
    await screen.findByText("Недоступность шлюза");
    expect(screen.getByRole("button", { name: "Получатели правила Недоступность шлюза" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Изменить правило Всплеск блокировок" })).toBeTruthy();
    unmount();
    renderScreen(["alerts.read", "alert_rules.read"]);
    tab("Правила");
    await screen.findByText("Недоступность шлюза");
    expect(screen.queryByRole("button", { name: "Создать правило" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Изменить правило/ })).toBeNull();
    expect(screen.getAllByText("Только просмотр").length).toBe(2);
  });

  it("создание правила «порог» отправляет условие и получателей", async () => {
    renderScreen(allPerms);
    tab("Правила");
    fireEvent.click(await screen.findByRole("button", { name: "Создать правило" }));
    const dlg = await screen.findByRole("dialog", { name: "Новое правило оповещения" });
    expect((within(dlg).getByRole("button", { name: "Создать правило" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Утечки в проде" } });
    fireEvent.change(within(dlg).getByLabelText("Фильтр событий"), { target: { value: 'env = "prod"' } });
    fireEvent.click(await within(dlg).findByRole("checkbox", { name: "Аналитик" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Создать правило" }));
    await waitFor(() => expect(calls.find((c) => c.url === "/api/v1/alert-rules" && c.method === "POST")?.body).toMatchObject({
      kind: "threshold", name: "Утечки в проде", condition: { filter: 'env = "prod"' }, recipients: { roles: ["analyst"], users: [] },
    }));
  });

  it("без прав на роли, пользователей и события — названия прав, не коды (3Н39 ревью 3.r2)", async () => {
    const { unmount } = renderScreen(["alerts.read", "alerts.manage", "alert_rules.read", "alert_rules.manage"]);
    tab("Правила");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить правило Всплеск блокировок" }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).getByText(/нужно право «Просмотр ролей и разрешений»/)).toBeTruthy();
    expect(within(dlg).getByText(/нужно право «Просмотр учётных записей»/)).toBeTruthy();
    expect(dlg.textContent).not.toMatch(/«[a-z_]+\.[a-z_.]+»/);
    unmount();
    renderScreen(["alerts.read"]);
    fireEvent.click(await screen.findByRole("button", { name: "Открыть оповещение: Много блокировок инъекций" }));
    const aside = await screen.findByRole("complementary", { name: "Карточка оповещения" });
    await within(aside).findByText(/нужно право «Просмотр событий»/);
    expect(aside.textContent).not.toMatch(/«[a-z_]+\.[a-z_.]+»/);
  });

  it("ослабление: сервер просит пароль, поле появляется, запрос повторяется с паролем", async () => {
    handler = (c) =>
      c.method === "PUT" && c.url.startsWith("/api/v1/alert-rules/") && !c.body.password
        ? problem(400, "invalid_request", "Проверьте введённые данные.", [{ field: "password", detail: "Введите текущий пароль." }])
        : undefined;
    renderScreen(allPerms);
    tab("Правила");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить правило Всплеск блокировок" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("checkbox", { name: "Правило включено" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить правило" }));
    await within(dlg).findByText(/Подтвердите, что это вы/);
    expect((within(dlg).getByRole("button", { name: "Сохранить правило" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-проверки-1" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить правило" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const puts = calls.filter((c) => c.method === "PUT").map((c) => c.body);
    expect(puts[0]).toMatchObject({ enabled: false, version: 3 });
    expect(puts[0].password).toBeUndefined();
    expect(puts[1]).toMatchObject({ enabled: false, password: "Пароль-для-проверки-1" });
  });

  it("системное правило: в запросе только получатели", async () => {
    renderScreen(allPerms);
    tab("Правила");
    fireEvent.click(await screen.findByRole("button", { name: "Получатели правила Недоступность шлюза" }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).queryByLabelText("Название")).toBeTruthy();
    expect((within(dlg).getByLabelText("Название") as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(await within(dlg).findByRole("checkbox", { name: "Аналитик" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить правило" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(Object.keys(calls.find((c) => c.method === "PUT")!.body).sort()).toEqual(["recipients", "version"]);
  });
});

describe("каналы", () => {
  it("секреты не показываются: только «заданы»; тест и журнал", async () => {
    renderScreen(allPerms);
    tab("Каналы");
    await screen.findByText("Почта SOC");
    expect(screen.getByText("заданы: пароль")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Тестовая отправка Почта SOC" }));
    await screen.findByText(/не доставлено \(код ошибки: tls\)/);
    fireEvent.click(screen.getByRole("button", { name: "Журнал доставки Почта SOC" }));
    const dlg = await screen.findByRole("dialog", { name: /Журнал доставки/ });
    await within(dlg).findByText("Доставлено");
  });

  it("правка без ввода секретов не отправляет secrets; секрет в поле не подставляется", async () => {
    renderScreen(allPerms);
    tab("Каналы");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить канал Почта SOC" }));
    const dlg = await screen.findByRole("dialog");
    const pw = within(dlg).getByLabelText("Пароль SMTP") as HTMLInputElement;
    expect(pw.value).toBe("");
    expect(pw.type).toBe("password");
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить канал" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const body = calls.find((c) => c.method === "PUT")!.body;
    expect(body.secrets).toEqual({});
    expect(body.version).toBe(2);
    expect(body.type).toBeUndefined();
  });

  it("удаление пароля SMTP — флажком, с логином и повторной проверкой (3Н38 ревью 3.r2)", async () => {
    handler = (c) =>
      c.method === "PUT" && c.url === "/api/v1/notify-channels/c-1" && !c.body.password
        ? problem(400, "invalid_request", "Проверьте введённые данные.", [{ field: "password", detail: "Введите текущий пароль." }])
        : undefined;
    renderScreen(allPerms);
    tab("Каналы");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить канал Почта SOC" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("checkbox", { name: "Удалить пароль и логин SMTP" }));
    expect(within(dlg).queryByLabelText("Пароль SMTP")).toBeNull();
    expect((within(dlg).getByLabelText("Логин SMTP") as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить канал" }));
    await within(dlg).findByText(/Подтвердите, что это вы/);
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-проверки-1" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить канал" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const puts = calls.filter((c) => c.method === "PUT").map((c) => c.body);
    expect(puts[1]).toMatchObject({ secrets: { password: "" }, settings: { username: "" }, password: "Пароль-для-проверки-1" });
  });

  it("поля секретов не принимают сохранённый пароль консоли (3В20 ревью 3.r2)", async () => {
    renderScreen(allPerms);
    tab("Каналы");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить канал Почта SOC" }));
    const dlg = await screen.findByRole("dialog");
    const pw = within(dlg).getByLabelText("Пароль SMTP") as HTMLInputElement;
    expect(pw.autocomplete).toBe("new-password");
    const login = within(dlg).getByLabelText("Логин SMTP") as HTMLInputElement;
    expect(login.autocomplete).toBe("off");
    expect(login.name).not.toMatch(/user|login|email/i);
    fireEvent.click(within(dlg).getByRole("button", { name: "Отменить" }));
    fireEvent.click(await screen.findByRole("button", { name: "Создать канал" }));
    const created = await screen.findByRole("dialog", { name: "Новый канал уведомлений" });
    fireEvent.change(within(created).getByLabelText("Тип канала"), { target: { value: "webhook" } });
    for (const label of ["Адрес webhook", "Ключ подписи"]) {
      expect((within(created).getByLabelText(label) as HTMLInputElement).autocomplete).toBe("new-password");
    }
  });

  it("создание webhook: адрес и ключ подписи уходят секретами, адрес проверяется", async () => {
    renderScreen(allPerms);
    tab("Каналы");
    fireEvent.click(await screen.findByRole("button", { name: "Создать канал" }));
    const dlg = await screen.findByRole("dialog", { name: "Новый канал уведомлений" });
    fireEvent.change(within(dlg).getByLabelText("Тип канала"), { target: { value: "webhook" } });
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Mattermost" } });
    fireEvent.change(within(dlg).getByLabelText(/Корневые сертификаты/), { target: { value: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----" } });
    fireEvent.change(within(dlg).getByLabelText("Адрес webhook"), { target: { value: `http://plain.example/hook` } });
    expect((within(dlg).getByRole("button", { name: "Создать канал" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Адрес webhook"), { target: { value: `https://mm.example/hooks/abc` } });
    fireEvent.change(within(dlg).getByLabelText("Ключ подписи"), { target: { value: "k".repeat(32) } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Создать канал" }));
    await waitFor(() => expect(calls.find((c) => c.url === "/api/v1/notify-channels" && c.method === "POST")?.body).toMatchObject({
      type: "webhook", name: "Mattermost", secrets: { url: `https://mm.example/hooks/abc`, signing_key: "k".repeat(32) },
    }));
  });

  it("без права управления кнопок создания, теста и правки нет", async () => {
    renderScreen(["alerts.read", "notify_channels.read"]);
    tab("Каналы");
    await screen.findByText("Почта SOC");
    expect(screen.queryByRole("button", { name: "Создать канал" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Тестовая отправка/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Изменить канал/ })).toBeNull();
    expect(screen.getByRole("button", { name: /Журнал доставки/ })).toBeTruthy();
  });
});

describe("срок хранения", () => {
  it("сокращение просит пароль после ответа сервера, увеличение — нет", async () => {
    handler = (c) =>
      c.method === "PUT" && c.url === "/api/v1/alert-settings" && c.body.retention_days < 365 && !c.body.password
        ? problem(400, "invalid_request", "Проверьте введённые данные.", [{ field: "password", detail: "Введите текущий пароль." }])
        : undefined;
    renderScreen(allPerms);
    tab("Срок хранения");
    const input = (await screen.findByLabelText("Срок хранения закрытых оповещений, суток")) as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe("365"));
    fireEvent.change(input, { target: { value: "30" } });
    await screen.findByText("Целое число суток от 90 до 1825.");
    fireEvent.change(input, { target: { value: "180" } });
    await screen.findByText(/Сокращение срока необратимо/);
    fireEvent.click(screen.getByRole("button", { name: "Сохранить срок" }));
    await screen.findByText(/Подтвердите, что это вы/);
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-проверки-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить срок" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toEqual({ retention_days: 180, password: "Пароль-для-проверки-1" }));
  });

  it("без права управления поле только для чтения", async () => {
    renderScreen(["alerts.read", "alert_rules.read"]);
    tab("Срок хранения");
    const input = (await screen.findByLabelText("Срок хранения закрытых оповещений, суток")) as HTMLInputElement;
    expect(input.disabled).toBe(true);
    expect(screen.queryByRole("button", { name: "Сохранить срок" })).toBeNull();
  });
});

describe("ссылки на события", () => {
  it("период покрывает срабатывания, фильтр строится по группе", () => {
    const now = Date.parse(NOW);
    expect(eventsPeriod(alert(), now + 30 * 60_000)).toBe("1h");
    expect(eventsPeriod(alert(), now + 3 * 86_400_000)).toBe("7d");
    expect(eventsPeriod(alert(), now + 90 * 86_400_000)).toBe("30d");
    const l = eventsLink(alert({ group: { app: 'a"b', unknown: "x" } }), now);
    expect(decodeURIComponent(l.replace(/\+/g, " "))).toContain('f=app = "a\\"b"');
    expect(l).not.toContain("unknown");
    expect(eventsLink(alert({ group: {} }), now)).toBe("/events?r=1h");
    expect(eventLink("ev 1", alert(), now)).toBe("/events?r=1h&event=ev+1");
  });
});
