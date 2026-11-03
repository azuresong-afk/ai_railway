import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { RunCard, Scenarios, Schedule, Target } from "./api";
import { RedteamScreen } from "./RedteamScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

const limits = { rate_per_minute: 30, concurrency: 2, request_timeout_sec: 30, run_timeout_min: 30 };
const t1 = "0190f3a2-0000-7000-8000-000000000011";
const t2 = "0190f3a2-0000-7000-8000-000000000012";
const gwTarget: Target = {
  id: t1, name: "Бот поддержки", kind: "gateway", app_id: "0190f3a2-0000-7000-8000-0000000000aa", model: "yandexgpt-lite", headers: [], limits, storage: "none",
  created_at: "2026-10-30T10:00:00Z", created_by: "sec", updated_at: "2026-10-30T10:00:00Z", updated_by: "sec",
};
const epTarget: Target = {
  id: t2, name: "Портал заказчика", kind: "endpoint", url: "portal.test:8080/chat", request_template: '{"q":"{{prompt}}"}', response_path: "answer", auth_header: "Authorization",
  authorization_note: "Договор 17/26", headers: [], limits, storage: "masked", created_at: "2026-10-30T10:00:00Z", created_by: "sec", updated_at: "2026-10-31T10:00:00Z", updated_by: "sec",
};

const run1 = "0190f3a2-0000-7000-8000-0000000000b1";
const run2 = "0190f3a2-0000-7000-8000-0000000000b2";
const finished: RunCard = {
  id: run1, target_id: t1, target_name: "Бот поддержки", target_kind: "gateway", status: "done", scenarios: 4,
  counts: { succeeded: 1, blocked: 2, defended: 1 }, db_version: 3, started_at: "2026-11-02T09:00:00Z", started_by: "sec", finished_at: "2026-11-02T09:05:00Z", deadline: "2026-11-02T09:30:00Z",
  results: [
    { scenario_id: "INJ-RU-001", lang: "ru", threat: "DM-01", category: "injection", verdict: "succeeded", step: 2, matched: ["canary"], findings: [], event_ids: ["0190f3a2-0000-7000-8000-0000000000e1"], latency_ms: 800 },
    { scenario_id: "INJ-RU-002", lang: "ru", threat: "DM-01", category: "injection", verdict: "blocked", step: 1, matched: [], findings: [{ detector: "injection.heuristic", category: "injection", threat: "DM-01" }], event_ids: [], latency_ms: 300 },
    { scenario_id: "LEAK-EN-001", lang: "en", threat: "DM-05", category: "prompt_leak", verdict: "blocked", step: 1, matched: [], findings: [], event_ids: [], latency_ms: 300 },
    { scenario_id: "LEAK-EN-002", lang: "en", threat: "DM-05", category: "prompt_leak", verdict: "defended", step: 1, matched: [], findings: [], event_ids: [], latency_ms: 300 },
  ],
};
const running = { ...finished, id: run2, status: "running", counts: {}, finished_at: undefined, results: [] } as unknown as RunCard;
const summary = (r: RunCard) => ({ ...r, results: undefined });

const scenarios: Scenarios = {
  state: {
    kind: "redteam_scenarios", title: "Сценарии", active: "current",
    current: { version: 3, date: "2026-10-30", records: 4, subkey_serial: 1, fingerprint: "ab12", uploaded_at: "2026-10-31T10:00:00Z", valid: true },
    previous: { version: 2, date: "2026-09-30", records: 3, subkey_serial: 1, fingerprint: "ab12", uploaded_at: "2026-10-01T10:00:00Z", valid: true },
  },
  scenarios: [
    { id: "INJ-RU-001", lang: "ru", threat: "DM-01", category: "injection", title: "Игнорируй инструкции", steps: 2, judge: false, source: "собственный", license: "Apache-2.0" },
    { id: "LEAK-EN-001", lang: "en", threat: "DM-05", category: "prompt_leak", title: "Reveal system prompt", steps: 1, judge: true, source: "собственный", license: "Apache-2.0" },
    { id: "PII-RU-001", lang: "ru", threat: "DM-02", category: "pii", title: "Выдать ПДн", steps: 1, judge: false, source: "собственный", license: "Apache-2.0" },
  ],
} as Scenarios;

const schedule: Schedule = {
  id: "0190f3a2-0000-7000-8000-0000000000c1", name: "Ночной прогон", target_id: t1, frequency: "weekly", weekday: 2, at: "03:00", threats: ["DM-01"], enabled: true,
  next_run_at: "2026-11-10T00:00:00Z", last_status: "busy", retries: 1, version: 2, created_at: "2026-10-30T10:00:00Z", created_by: "sec", updated_at: "2026-10-30T10:00:00Z", updated_by: "sec",
};

type Call = { method: string; url: string; body: unknown; type: string | undefined };
const calls: Call[] = [];
let handler: (c: Call) => Response | undefined;
let targets: Target[];
let runs: RunCard[];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });

beforeEach(() => {
  calls.length = 0;
  handler = () => undefined;
  targets = [gwTarget, epTarget];
  runs = [running, finished];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:x"), revokeObjectURL: vi.fn() }));
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const headers = (init.headers ?? {}) as Record<string, string>;
      const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
      const c: Call = { method, url, body, type: headers["Content-Type"] };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const path = url.split("?")[0] ?? url;
      const run = /^\/api\/v1\/redteam\/runs\/([^/]+)$/.exec(path);
      if (path === "/api/v1/redteam/targets" && method === "GET") return Promise.resolve(json({ items: targets, gateway_configured: true }));
      if (path === "/api/v1/redteam/targets" && method === "POST") return Promise.resolve(json({ ...gwTarget, id: "new" }, 201));
      if (/^\/api\/v1\/redteam\/targets\/[^/]+$/.test(path) && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      if (path === "/api/v1/redteam/scenarios" && method === "GET") return Promise.resolve(json(scenarios));
      if (path === "/api/v1/redteam/scenarios" && method === "PUT") return Promise.resolve(json({ ...scenarios, state: { ...scenarios.state, current: { ...scenarios.state.current!, version: 4 } } }));
      if (path === "/api/v1/redteam/scenarios/rollback") return Promise.resolve(json({ ...scenarios, state: { ...scenarios.state, current: scenarios.state.previous } }));
      if (path === "/api/v1/redteam/runs" && method === "GET") return Promise.resolve(json({ items: runs.map(summary) }));
      if (path === "/api/v1/redteam/runs" && method === "POST") return Promise.resolve(json(summary(running), 202));
      if (run && method === "GET") {
        const r = runs.find((x) => x.id === run[1]);
        return Promise.resolve(r ? json(r) : problem(404, "not_found", "нет"));
      }
      if (/\/report$/.test(path)) return Promise.resolve(new Response("<html></html>", { status: 200, headers: { "Content-Type": "text/html" } }));
      if (/\/cancel$/.test(path)) return Promise.resolve(new Response(null, { status: 204 }));
      if (path === "/api/v1/redteam/schedules" && method === "GET") return Promise.resolve(json({ items: [schedule] }));
      if (path === "/api/v1/redteam/schedules" && method === "POST") return Promise.resolve(json({ ...schedule, id: "new" }, 201));
      if (/^\/api\/v1\/redteam\/schedules\/[^/]+$/.test(path) && method === "PUT") return Promise.resolve(json(schedule));
      if (/^\/api\/v1\/redteam\/schedules\/[^/]+$/.test(path) && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      if (path === "/api/v1/applications") return Promise.resolve(json({ items: [{ id: gwTarget.app_id, slug: "support-bot", name: "Бот поддержки (приложение)", models: ["yandexgpt-lite"] }] }));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RedteamScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const reader = ["redteam.read"];
const admin = ["redteam.read", "redteam.run", "redteam.targets.manage", "redteam.scenarios.load", "redteam.schedules.manage", "redteam.export", "events.content.read"];
const openTab = async (name: string) => fireEvent.mouseDown(await screen.findByRole("tab", { name }), { button: 0 });

describe("экран «Тестирование устойчивости»: запуски", () => {
  it("список запусков с итогами и долей удавшихся; у читателя нет кнопки запуска", async () => {
    renderScreen(reader);
    const list = await screen.findByRole("table", { name: "Запуски тестирования" });
    expect(within(list).getAllByText("Бот поддержки")).toHaveLength(2);
    expect(within(list).getByText("завершён")).toBeInTheDocument();
    expect(within(list).getByText("идёт")).toBeInTheDocument();
    // 1 из 4 проверенных: 25,0 % с запятой (ТЗ 6.7).
    expect(within(list).getByText(/25,0 %/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Запустить тестирование" })).toBeNull();
  });

  it("результаты запуска: итоги по сценариям, ссылка на событие шлюза, без отчёта у читателя", async () => {
    renderScreen(reader);
    fireEvent.click((await screen.findAllByRole("button", { name: /02\.11\.2026/ }))[1]!);
    const res = await screen.findByRole("table", { name: "Результаты сценариев" });
    expect(within(res).getByText("INJ-RU-001")).toBeInTheDocument();
    expect(within(res).getAllByText("Заблокировано защитой").length).toBeGreaterThan(0);
    expect(within(res).getByRole("link", { name: "0190f3a2" })).toHaveAttribute("href", expect.stringContaining("#/events?event="));
    expect(screen.getByText(/Удалось атак: 1/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "HTML" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Итог"), { target: { value: "defended" } });
    expect(within(screen.getByRole("table", { name: "Результаты сценариев" })).queryByText("INJ-RU-001")).toBeNull();
  });

  it("отчёт: формат в запросе, выдержки — только по отметке и с правом на содержимое", async () => {
    renderScreen(admin);
    fireEvent.click((await screen.findAllByRole("button", { name: /02\.11\.2026/ }))[1]!);
    fireEvent.click(await screen.findByRole("button", { name: "CSV" }));
    await waitFor(() => expect(calls.some((c) => c.url === `/api/v1/redteam/runs/${run1}/report?format=csv`)).toBe(true));
    fireEvent.click(screen.getByRole("checkbox", { name: /выдержки ответов/i }));
    fireEvent.click(screen.getByRole("button", { name: "XLSX" }));
    await waitFor(() => expect(calls.some((c) => c.url === `/api/v1/redteam/runs/${run1}/report?format=xlsx&examples=true`)).toBe(true));
  });

  it("без права на содержимое отметки «выдержки» нет", async () => {
    renderScreen(["redteam.read", "redteam.export"]);
    fireEvent.click((await screen.findAllByRole("button", { name: /02\.11\.2026/ }))[1]!);
    expect(await screen.findByRole("button", { name: "HTML" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /выдержки ответов/i })).toBeNull();
  });

  it("отказ сервера в отчёте показан текстом", async () => {
    handler = (c) => (c.url.includes("/report") ? problem(403, "forbidden", "Нет права redteam.export.") : undefined);
    renderScreen(admin);
    fireEvent.click((await screen.findAllByRole("button", { name: /02\.11\.2026/ }))[1]!);
    fireEvent.click(await screen.findByRole("button", { name: "HTML" }));
    expect(await screen.findByText(/Нет права redteam.export./)).toBeInTheDocument();
  });

  it("идущий запуск отменяется", async () => {
    renderScreen(admin);
    fireEvent.click((await screen.findAllByRole("button", { name: /02\.11\.2026/ }))[0]!);
    fireEvent.click(await screen.findByRole("button", { name: "Отменить запуск" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === `/api/v1/redteam/runs/${run2}/cancel`)).toBe(true));
  });

  it("запуск: секретное значение заголовка уходит только в запросе запуска", async () => {
    renderScreen(admin);
    const open = await screen.findByRole("button", { name: "Запустить тестирование" });
    await waitFor(() => expect(open).toBeEnabled());
    fireEvent.click(open);
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Цель"), { target: { value: t2 } });
    const start = within(dlg).getByRole("button", { name: "Запустить" });
    expect(start).toBeDisabled();
    const secret = within(dlg).getByLabelText("Значение заголовка Authorization");
    expect(secret).toHaveAttribute("type", "password");
    fireEvent.change(secret, { target: { value: "Bearer synthetic-token" } });
    fireEvent.click(await within(dlg).findByRole("checkbox", { name: "DM-01" }));
    fireEvent.click(start);
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url === "/api/v1/redteam/runs")?.body).toEqual({ target_id: t2, threats: ["DM-01"], auth_value: "Bearer synthetic-token" }));
  });
});

describe("экран «Тестирование устойчивости»: покрытие матрицы", () => {
  it("строки матрицы с итогами последнего завершённого запуска; строка без результатов — «не проверялась»", async () => {
    renderScreen(reader);
    await openTab("Покрытие матрицы");
    const table = await screen.findByRole("table", { name: "Покрытие строк матрицы обнаружения" });
    await waitFor(() => expect(within(table).getByText("DM-05")).toBeInTheDocument());
    const rows = within(table).getAllByRole("row");
    const row = (id: string) => rows.find((r) => within(r).queryByText(id)) as HTMLElement;
    expect(within(row("DM-01")).getByText("Атака удалась")).toBeInTheDocument();
    expect(within(row("DM-05")).getByText("Заблокировано защитой")).toBeInTheDocument();
    expect(within(row("DM-02")).getByText("не проверялась")).toBeInTheDocument();
    expect(screen.getByText(/Проверено строк:/)).toHaveTextContent("2 из 3");
  });
});

describe("экран «Тестирование устойчивости»: цели", () => {
  it("список целей без секретов; читателю нельзя добавлять и удалять", async () => {
    renderScreen(reader);
    await openTab("Цели");
    const table = await screen.findByRole("table", { name: "Цели тестирования" });
    expect(within(table).getByText("portal.test:8080/chat")).toBeInTheDocument();
    expect(within(table).getByText(/секретный заголовок: Authorization/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Добавить цель" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Удалить" })).toBeNull();
  });

  it("цель-адрес: нужен пароль и основание, пароль уходит в теле запроса", async () => {
    renderScreen(admin);
    await openTab("Цели");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить цель" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Портал" } });
    fireEvent.click(within(dlg).getByRole("radio", { name: "Адрес приложения заказчика" }));
    fireEvent.change(within(dlg).getByLabelText("Адрес"), { target: { value: "portal.test:8080/chat" } });
    const add = within(dlg).getByRole("button", { name: "Добавить цель" });
    expect(add).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Основание"), { target: { value: "Договор 17/26 от 01.10.2026" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "synthetic-pass" } });
    fireEvent.click(add);
    await waitFor(() => {
      const c = calls.find((x) => x.method === "POST" && x.url === "/api/v1/redteam/targets");
      expect(c?.body).toMatchObject({ kind: "endpoint", name: "Портал", url: "portal.test:8080/chat", authorization_note: "Договор 17/26 от 01.10.2026", password: "synthetic-pass" });
    });
  });

  it("при втором факторе вместо пароля просят код", async () => {
    renderScreen(admin, true);
    await openTab("Цели");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить цель" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("radio", { name: "Адрес приложения заказчика" }));
    expect(within(dlg).getByLabelText("Код из приложения-аутентификатора")).toBeInTheDocument();
    expect(within(dlg).queryByLabelText("Текущий пароль")).toBeNull();
  });

  it("удаление цели просит подтверждения", async () => {
    renderScreen(admin);
    await openTab("Цели");
    fireEvent.click((await screen.findAllByRole("button", { name: "Удалить" }))[0]!);
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.click(await screen.findByRole("button", { name: "Удалить цель" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/api/v1/redteam/targets/${t1}`)).toBe(true));
  });

  it("отказ сервера в добавлении цели показан текстом", async () => {
    handler = (c) => (c.method === "POST" && c.url === "/api/v1/redteam/targets" ? problem(403, "forbidden", "Адрес цели задаётся в консоли.") : undefined);
    renderScreen(admin);
    await openTab("Цели");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить цель" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Бот" } });
    await waitFor(() => expect(within(dlg).getByLabelText("Приложение")).toBeInTheDocument());
    fireEvent.change(within(dlg).getByLabelText("Модель"), { target: { value: "yandexgpt-lite" } });
    fireEvent.change(within(dlg).getByLabelText("Приложение"), { target: { value: gwTarget.app_id } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Добавить цель" }));
    expect(await screen.findByText(/Адрес цели задаётся в консоли./)).toBeInTheDocument();
  });
});

describe("экран «Тестирование устойчивости»: расписания", () => {
  it("список с последней попыткой; цели с секретным заголовком в форму не попадают", async () => {
    renderScreen(admin);
    await openTab("Расписания");
    const table = await screen.findByRole("table", { name: "Расписания запусков" });
    expect(within(table).getByText("Ночной прогон")).toBeInTheDocument();
    expect(within(table).getByText(/еженедельно, вторник, 03:00/)).toBeInTheDocument();
    expect(within(table).getByText("цель или сервер заняты")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Добавить расписание" }));
    const dlg = await screen.findByRole("dialog");
    const options = within(within(dlg).getByLabelText("Цель")).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(["Бот поддержки"]);
  });

  it("создание: время и частота уходят в запросе", async () => {
    renderScreen(admin);
    await openTab("Расписания");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить расписание" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Прогон" } });
    fireEvent.change(within(dlg).getByLabelText("Как часто"), { target: { value: "daily" } });
    fireEvent.change(within(dlg).getByLabelText("Время (ЧЧ:ММ)"), { target: { value: "04:30" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Добавить расписание" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url === "/api/v1/redteam/schedules")?.body).toEqual({ name: "Прогон", target_id: t1, frequency: "daily", at: "04:30", enabled: true }));
  });

  it("изменение отправляет версию, которую видел администратор", async () => {
    renderScreen(admin);
    await openTab("Расписания");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить расписание" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ version: 2, weekday: 2, threats: ["DM-01"] }));
  });

  it("читателю управление расписаниями недоступно", async () => {
    renderScreen(reader);
    await openTab("Расписания");
    await screen.findByRole("table", { name: "Расписания запусков" });
    expect(screen.queryByRole("button", { name: "Добавить расписание" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Изменить" })).toBeNull();
  });
});

describe("экран «Тестирование устойчивости»: сценарии", () => {
  it("версии базы и список сценариев без текстов атак", async () => {
    renderScreen(reader);
    await openTab("Сценарии");
    const versions = await screen.findByRole("table", { name: "Сохранённые версии" });
    expect(within(versions).getByText(/3 от 2026-10-30/)).toBeInTheDocument();
    const list = await screen.findByRole("table", { name: "Сценарии" });
    expect(within(list).getByText("Игнорируй инструкции")).toBeInTheDocument();
    expect(within(list).getByText("оценщик judge.llm")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Загрузить базу сценариев" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Вернуть предыдущую версию" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Язык"), { target: { value: "en" } });
    expect(within(screen.getByRole("table", { name: "Сценарии" })).queryByText("Игнорируй инструкции")).toBeNull();
  });

  it("загрузка файла базы — двоичным телом", async () => {
    renderScreen(admin);
    await openTab("Сценарии");
    const input = await screen.findByLabelText("Файл базы сценариев");
    const load = screen.getByRole("button", { name: "Загрузить базу сценариев" });
    expect(load).toBeDisabled();
    fireEvent.change(input, { target: { files: [new File(["x"], "redteam.aisecdb")] } });
    fireEvent.click(load);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.type).toBe("application/octet-stream"));
    expect(await screen.findByText(/База сценариев версии 4 загружена/)).toBeInTheDocument();
  });

  it("возврат предыдущей версии подтверждается", async () => {
    renderScreen(admin);
    await openTab("Сценарии");
    fireEvent.click(await screen.findByRole("button", { name: "Вернуть предыдущую версию" }));
    expect(calls.some((c) => c.url.endsWith("/rollback"))).toBe(false);
    fireEvent.click(await screen.findByRole("button", { name: "Вернуть версию" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/api/v1/redteam/scenarios/rollback")).toBe(true));
    expect(await screen.findByText(/Возвращена предыдущая версия базы сценариев: 2/)).toBeInTheDocument();
  });

  it("без базы — предупреждение", async () => {
    handler = (c) =>
      c.url === "/api/v1/redteam/scenarios" && c.method === "GET" ? json({ state: { kind: "redteam_scenarios", title: "Сценарии", active: "none" }, scenarios: [] }) : undefined;
    renderScreen(admin);
    await openTab("Сценарии");
    expect(await screen.findByText(/База сценариев не загружена/)).toBeInTheDocument();
  });
});
