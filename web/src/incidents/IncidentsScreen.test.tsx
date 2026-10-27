import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { Incident, IncidentCard } from "./api";
import { IncidentsScreen } from "./IncidentsScreen";
import { reactionText, timelineLine, transitions } from "./format";

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

const NOW = "2026-10-22T10:00:00Z";
const inc = (o: Partial<Incident> = {}): Incident => ({
  id: "inc-1", number: 7, title: "Утечка системного промпта", severity: "high", category: "system_prompt_leak", status: "new", source: "alert",
  reaction_due_at: "2026-10-22T14:00:00Z", overdue: false, created_at: NOW, created_by: "system", updated_at: NOW, updated_by: "system", version: 1, ...o,
});
const card = (i: Incident): IncidentCard => ({
  ...i,
  category_title: "Утечка системного промпта",
  stages: [
    { key: "intake", title: "Приём сообщения", done_at: NOW, done_by: "sec" },
    { key: "triage", title: "Сбор первичных сведений" },
    { key: "containment", title: "Локализация" },
    { key: "investigation", title: "Сбор сведений для расследования" },
  ],
  timeline: [{ at: NOW, actor: "system", kind: "created", details: {} }],
  comments: [{ id: "c-1", at: NOW, author: "user:u-2", author_name: "Аналитик", body: "<b>жирный</b> текст", superseded: false }],
  alerts: [{ id: "al-1", rule_id: "r-1", rule_name: "Канарейка", title: "Утечка канарейки", severity: "critical", status: "new", count: 3, created_at: NOW }],
  events: [{ id: "ev-1", ts: NOW }],
  events_truncated: false,
  instruction: { category: "system_prompt_leak", body: "1. Смените промпт.\n2. Проверьте доступ.", version: 1, default: true },
});

type JsonBody = ReturnType<typeof JSON.parse>;
type Call = { method: string; url: string; body: JsonBody };
const calls: Call[] = [];
let items: Incident[];
let handler: (c: Call) => Response | undefined;
const problem = (status: number, code: string, detail: string) => new Response(JSON.stringify({ status, code, detail }), { status });
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });

beforeEach(() => {
  calls.length = 0;
  handler = () => undefined;
  items = [inc()];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const r = (x: Response) => Promise.resolve(x);
      if (url.startsWith("/api/v1/incidents?")) return r(json({ items }));
      if (url === "/api/v1/incidents" && method === "POST") return r(json(inc({ id: "inc-9", number: 9, title: c.body.title ?? "x" }), 201));
      if (/^\/api\/v1\/incidents\/inc-1\/export$/.test(url)) return r(new Response('{"format":"aisec-incident/1"}'));
      if (/^\/api\/v1\/incidents\/inc-1$/.test(url)) return r(json(card(items[0]!)));
      if (/^\/api\/v1\/incidents\/inc-1\/status$/.test(url)) return r(json({ ...items[0], status: c.body.status }));
      if (/^\/api\/v1\/incidents\/inc-1\/assignee$/.test(url)) return r(json({ ...items[0], assignee_id: c.body.user_id }));
      if (/^\/api\/v1\/incidents\/inc-1\/comments$/.test(url)) return r(json({ id: "c-2", at: NOW, author: "user:u-me", author_name: "Безопасник", body: c.body.body, superseded: false }, 201));
      if (/^\/api\/v1\/incidents\/inc-1\/stages\//.test(url)) return r(json(items[0]));
      if (url === "/api/v1/incident-categories")
        return r(json({ items: [{ id: "system_prompt_leak", title: "Утечка системного промпта", rows: ["DM-08"], instruction: { category: "system_prompt_leak", body: "Текст по умолчанию", version: 1, default: true } }, { id: "other", title: "Прочее", rows: [], instruction: { category: "other", body: "", version: 1, default: true } }] }));
      if (url === "/api/v1/events/settings") return r(json({ metadata_days: 90, content_days: 30, updated_at: NOW }));
      if (url === "/api/v1/incident-settings" && method === "GET") return r(json({ retention_days: 1095 }));
      if (url === "/api/v1/incident-settings" && method === "PUT") return r(json({ retention_days: c.body.retention_days }));
      if (url === "/api/v1/incident-categories/system_prompt_leak" && method === "PUT") return r(json({ category: "system_prompt_leak", body: c.body.body, version: 2, default: false }));
      return r(problem(404, "not_found", "нет"));
    }),
  );
  // Скачивание файла: jsdom не умеет URL.createObjectURL.
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:x"), revokeObjectURL: vi.fn() }));
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const renderScreen = (permissions: string[], path = "/incidents") =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <IncidentsScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const tab = (name: string) => fireEvent.mouseDown(screen.getByRole("tab", { name }), { button: 0 });
const read = ["incidents.read", "events.read"];
const manage = [...read, "incidents.manage", "incidents.export"];
const openCard = async () => {
  fireEvent.click(await screen.findByRole("button", { name: "Открыть инцидент 7: Утечка системного промпта" }));
  const aside = await screen.findByRole("complementary", { name: "Карточка инцидента" });
  await within(aside).findByText("Приём сообщения:");
  return aside;
};

describe("список и доска", () => {
  it("список с фильтрами: по умолчанию незакрытые, фильтры уходят в запрос", async () => {
    renderScreen(read);
    await screen.findByRole("button", { name: /Открыть инцидент 7/ });
    expect(calls.find((c) => c.url.startsWith("/api/v1/incidents?"))?.url).toContain("status=open");
    fireEvent.change(screen.getByLabelText("Серьёзность"), { target: { value: "critical" } });
    fireEvent.change(screen.getByLabelText("Категория"), { target: { value: "other" } });
    await waitFor(() => expect(calls.some((c) => c.url.includes("severity=critical") && c.url.includes("category=other"))).toBe(true));
  });

  it("«Назначены мне» отправляет assignee_id", async () => {
    renderScreen(read);
    await screen.findByRole("button", { name: /Открыть инцидент 7/ });
    fireEvent.click(screen.getByRole("checkbox", { name: "Назначены мне" }));
    await waitFor(() => expect(calls.some((c) => c.url.includes("assignee_id=u-me"))).toBe(true));
  });

  it("доска раскладывает инциденты по статусам", async () => {
    items = [inc(), inc({ id: "inc-2", number: 8, title: "Второй", status: "contained" })];
    renderScreen(read, "/incidents?view=board");
    const board = await screen.findByRole("group", { name: "Доска инцидентов" });
    expect(within(within(board).getByRole("region", { name: "Статус: Новый" })).getByText("Утечка системного промпта")).toBeInTheDocument();
    expect(within(within(board).getByRole("region", { name: "Статус: Локализован" })).getByText("Второй")).toBeInTheDocument();
    expect(within(within(board).getByRole("region", { name: "Статус: Закрыт" })).queryByRole("button")).toBeNull();
    // Фильтр по статусу к доске не применяется.
    expect(calls.find((c) => c.url.startsWith("/api/v1/incidents?"))?.url).not.toContain("status=");
  });

  it("пустой список и ошибка загрузки", async () => {
    items = [];
    const { unmount } = renderScreen(read);
    await screen.findByText("Инцидентов пока нет");
    unmount();
    handler = (c) => (c.url.startsWith("/api/v1/incidents?") ? problem(500, "internal", "x") : undefined);
    renderScreen(read);
    await screen.findByText(/Внутренняя ошибка сервера/);
  });

  it("без incidents.read — сообщение об отсутствии доступа и ни одного запроса", () => {
    renderScreen(["events.read"]);
    expect(screen.getByText(/Нет доступа к инцидентам/)).toBeInTheDocument();
    expect(calls).toHaveLength(0);
  });
});

describe("карточка инцидента", () => {
  it("показывает поля, этапы, инструкцию, оповещения, хронологию; комментарий — только текстом", async () => {
    renderScreen(read);
    const aside = await openCard();
    expect(within(aside).getByText("Инцидент № 7: Утечка системного промпта")).toBeInTheDocument();
    expect(within(aside).getByRole("region", { name: "Инструкция реагирования" })).toHaveTextContent("Смените промпт.");
    expect(within(aside).getByRole("region", { name: "Оповещения инцидента" })).toHaveTextContent("Утечка канарейки");
    expect(within(aside).getByRole("region", { name: "Хронология" })).toHaveTextContent("Инцидент создан");
    expect(within(aside).getByText("<b>жирный</b> текст")).toBeInTheDocument();
    expect(aside.querySelector("b")).toBeNull();
    expect(within(aside).getByRole("link", { name: /Событие от/ }).getAttribute("href")).toContain("event=ev-1");
  });

  it("без incidents.manage кнопок изменения нет", async () => {
    renderScreen(read);
    const aside = await openCard();
    for (const n of ["Взять в работу", "Закрыть инцидент", "Назначить себя", "Добавить комментарий", "Выгрузить JSON"]) {
      expect(within(aside).queryByRole("button", { name: n })).toBeNull();
    }
    expect(within(aside).queryByRole("button", { name: /Отметить этап/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Создать инцидент" })).toBeNull();
  });

  it("смена статуса: «Взять в работу» отправляет status", async () => {
    renderScreen(manage);
    const aside = await openCard();
    fireEvent.click(within(aside).getByRole("button", { name: "Взять в работу" }));
    const dlg = await screen.findByRole("dialog", { name: "Взять в работу" });
    fireEvent.click(within(dlg).getByRole("button", { name: "Взять в работу" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/status"))?.body).toEqual({ status: "in_progress" }));
  });

  it("закрытие требует резолюцию и отправляет её с комментарием", async () => {
    renderScreen(manage);
    const aside = await openCard();
    fireEvent.click(within(aside).getByRole("button", { name: "Закрыть инцидент" }));
    const dlg = await screen.findByRole("dialog", { name: "Закрыть инцидент" });
    const submit = within(dlg).getByRole("button", { name: "Закрыть инцидент" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Резолюция"), { target: { value: "false_positive" } });
    fireEvent.change(within(dlg).getByLabelText("Комментарий"), { target: { value: "ошибка правила" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/status"))?.body).toEqual({ status: "closed", resolution: "false_positive", comment: "ошибка правила" }));
  });

  it("запрещённый переход (409) объясняется в диалоге", async () => {
    handler = (c) => (c.url.endsWith("/status") ? problem(409, "conflict", "Переход из этого статуса запрещён.") : undefined);
    renderScreen(manage);
    const aside = await openCard();
    fireEvent.click(within(aside).getByRole("button", { name: "Взять в работу" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Взять в работу" }));
    await within(dlg).findByText(/Переход из этого статуса запрещён/);
  });

  it("отказ сервера (403) на смену статуса показывается текстом", async () => {
    handler = (c) => (c.url.endsWith("/status") ? problem(403, "forbidden", "Недостаточно прав.") : undefined);
    renderScreen(manage);
    const aside = await openCard();
    fireEvent.click(within(aside).getByRole("button", { name: "Взять в работу" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Взять в работу" }));
    await within(dlg).findByText(/Сервер отказал в действии. Недостаточно прав./);
  });

  it("у закрытого инцидента переходов нет, есть «Открыть заново»", async () => {
    items = [inc({ status: "closed", resolution: "resolved", closed_at: NOW, closed_by: "sec" })];
    renderScreen(manage, "/incidents?id=inc-1");
    const aside = await screen.findByRole("complementary", { name: "Карточка инцидента" });
    await within(aside).findByText("Приём сообщения:");
    expect(within(aside).getByText(/Закрыт: Устранён/)).toBeInTheDocument();
    expect(within(aside).queryByRole("button", { name: "Закрыть инцидент" })).toBeNull();
    expect(within(aside).queryByRole("button", { name: "Добавить комментарий" })).toBeNull();
    fireEvent.click(within(aside).getByRole("button", { name: "Открыть заново" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url === "/api/v1/incidents")?.body).toEqual({ reopen_of: "inc-1" }));
  });

  it("назначение себя без users.read, комментарий, этап и выгрузка", async () => {
    renderScreen(manage);
    const aside = await openCard();
    fireEvent.click(within(aside).getByRole("button", { name: "Назначить себя" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/assignee"))?.body).toEqual({ user_id: "u-me" }));

    fireEvent.change(within(aside).getByLabelText("Новый комментарий"), { target: { value: "проверил логи" } });
    fireEvent.click(within(aside).getByRole("button", { name: "Добавить комментарий" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/comments"))?.body).toEqual({ body: "проверил логи" }));

    fireEvent.click(within(aside).getByRole("button", { name: "Отметить этап: Сбор первичных сведений" }));
    const dlg = await screen.findByRole("dialog", { name: "Отметить этап реагирования" });
    fireEvent.click(within(dlg).getByRole("button", { name: "Отметить этап" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/stages/triage") && c.method === "POST")).toBe(true));

    fireEvent.click(within(aside).getByRole("button", { name: "Выгрузить JSON" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/export"))).toBe(true));
  });

  it("ручное создание: название, серьёзность и категория", async () => {
    renderScreen(manage);
    fireEvent.click(await screen.findByRole("button", { name: "Создать инцидент" }));
    const dlg = await screen.findByRole("dialog", { name: "Создать инцидент" });
    const submit = within(dlg).getByRole("button", { name: "Создать инцидент" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Подозрительная активность" } });
    fireEvent.change(within(dlg).getByLabelText("Категория"), { target: { value: "other" } });
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url === "/api/v1/incidents")?.body).toEqual({ title: "Подозрительная активность", severity: "medium", category: "other" }));
  });
});

describe("перенесено из этапа 3 (задача 4.5)", () => {
  it("событие старше срока хранения событий — без ссылки, с пометкой; без права — его название", async () => {
    handler = (c) =>
      /^\/api\/v1\/incidents\/inc-1$/.test(c.url)
        ? json({ ...card(items[0]!), events: [{ id: "ev-old", ts: "2025-01-10T10:00:00Z" }, { id: "ev-1", ts: new Date().toISOString() }] })
        : undefined;
    const { unmount } = renderScreen(read);
    const aside = await openCard();
    const events = within(aside).getByRole("region", { name: "События инцидента" });
    await within(events).findByText(/удалено по сроку хранения/);
    expect(within(events).getAllByRole("link", { name: /Событие от/ })).toHaveLength(1);
    expect(within(events).getByRole("link", { name: /Событие от/ }).getAttribute("href")).toContain("event=ev-1");
    unmount();
    calls.length = 0;
    renderScreen(["incidents.read"]);
    const aside2 = await openCard();
    expect(within(aside2).getByText("Для просмотра событий нужно право «Просмотр событий».")).toBeInTheDocument();
    expect(calls.some((c) => c.url === "/api/v1/events/settings")).toBe(false);
  });

  it("срок хранения инцидентов: просмотр по incidents.read, изменение по incident_categories.manage с паролем при сокращении", async () => {
    handler = (c) =>
      c.method === "PUT" && c.url === "/api/v1/incident-settings" && c.body.retention_days < 1095 && !c.body.password
        ? new Response(JSON.stringify({ status: 400, code: "invalid_request", detail: "Проверьте введённые данные.", errors: [{ field: "password", detail: "Введите текущий пароль." }] }), { status: 400 })
        : undefined;
    const { unmount } = renderScreen(read);
    tab("Срок хранения");
    const ro = (await screen.findByLabelText("Срок хранения закрытых инцидентов, суток")) as HTMLInputElement;
    await waitFor(() => expect(ro.value).toBe("1095"));
    expect(ro.disabled).toBe(true);
    expect(screen.queryByRole("button", { name: "Сохранить срок" })).toBeNull();
    unmount();
    renderScreen([...read, "incident_categories.manage"]);
    tab("Срок хранения");
    const input = (await screen.findByLabelText("Срок хранения закрытых инцидентов, суток")) as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe("1095"));
    fireEvent.change(input, { target: { value: "100" } });
    await screen.findByText("Целое число суток от 365 до 1825.");
    fireEvent.change(input, { target: { value: "730" } });
    await screen.findByText(/Сокращение срока необратимо/);
    fireEvent.click(screen.getByRole("button", { name: "Сохранить срок" }));
    await screen.findByText(/Подтвердите, что это вы/);
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-проверки-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить срок" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toEqual({ retention_days: 730, password: "Пароль-для-проверки-1" }));
  });
});

describe("инструкции категорий", () => {
  it("вкладка только по праву incident_categories.manage; сохранение шлёт версию", async () => {
    const { unmount } = renderScreen(read);
    expect(screen.queryByRole("tab", { name: "Инструкции по категориям" })).toBeNull();
    unmount();
    renderScreen([...read, "incident_categories.manage"]);
    tab("Инструкции по категориям");
    const area = await screen.findAllByLabelText("Инструкция реагирования");
    fireEvent.change(area[0]!, { target: { value: "Новый текст" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить инструкцию: Утечка системного промпта" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ body: "Новый текст", version: 1 }));
  });
});

describe("форматирование", () => {
  it("переходы статусов совпадают с API", () => {
    expect(transitions.new).toEqual(["in_progress", "closed"]);
    expect(transitions.in_progress).toEqual(["contained", "closed"]);
    expect(transitions.contained).toEqual(["closed"]);
    expect(transitions.closed).toEqual([]);
  });
  it("срок реакции словами", () => {
    const base = { reaction_due_at: "2026-10-22T14:00:00Z", overdue: false, status: "new" as const };
    expect(reactionText(base, Date.parse("2026-10-22T10:00:00Z"))).toBe("Осталось 4 ч");
    expect(reactionText({ ...base, overdue: true }, Date.parse("2026-10-22T15:00:00Z"))).toBe("Срок реакции истёк");
    expect(reactionText({ ...base, status: "in_progress", reacted_at: "2026-10-22T11:00:00Z" }, 0)).toBe("Реакция в срок");
  });
  it("строка хронологии терпит чужие данные", () => {
    expect(timelineLine({ at: NOW, actor: "a", kind: "status_changed", details: { from: 5, to: {}, resolution: "resolved" } })).toContain("Статус изменён");
    expect(timelineLine({ at: NOW, actor: "a", kind: "status_changed", details: { from: "new", to: "closed", resolution: "resolved", comment: "ок" } })).toBe("Статус изменён: Новый → Закрыт (Устранён) — ок");
  });
});
