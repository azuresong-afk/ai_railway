import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { ShadowCatalog, ShadowExclusion, ShadowImport, ShadowService, ShadowSyslog, ShadowUser } from "./api";
import { ShadowAIScreen } from "./ShadowAIScreen";

// Графики ECharts в jsdom не рисуются: подменяем компонент, данные проверяются таблицей.
vi.mock("../dashboards/Chart", () => ({
  Chart: ({ label }: { label: string }) => <div role="img" aria-label={label} />,
  token: () => "",
}));

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

// Синтетические данные: псевдонимы — произвольные hex, не от реальных логинов.
const alias = "0123456789abcdef0123456789abcdef";
const catalog: ShadowCatalog = {
  loaded: true, valid: true, version: 3, date: "2026-10-01", uploaded_at: "2026-10-02T10:00:00Z", subkey_not_after: "2027-10-01T00:00:00Z",
  services: [
    { id: "chatgpt", name: "ChatGPT", vendor: "OpenAI", category: "chat", domains: ["chatgpt.com"], suffixes: [] },
    { id: "deepseek", name: "DeepSeek", vendor: "DeepSeek", category: "chat", domains: [], suffixes: ["deepseek.com"] },
  ],
};
const svc: ShadowService = {
  id: "chatgpt", name: "ChatGPT", vendor: "OpenAI", category: "chat", requests: 1200, bytes: 2048, users: 3,
  first_seen: "2026-10-20T09:00:00Z", last_seen: "2026-10-27T15:00:00Z",
};
const usr: ShadowUser = { alias, kind: "user", requests: 40, bytes: 100, services: ["chatgpt", "deepseek"], last_seen: "2026-10-27T15:00:00Z" };
const imp: ShadowImport = {
  id: "i-1", created_at: "2026-10-27T12:00:00Z", created_by: "user:u-me", catalog_version: 3, format: "squid", lines: 10, matched: 6,
  unmatched: 1, errors: 3, outdated: 0, excluded: 0, error_lines: [2, 5, 9], users_pseudonymized: true, sha256: "ab", services: 2,
};
const syslogOff: ShadowSyslog = {
  enabled: false, running: false, accept_errors: 0, tls: false, client_cert_required: false, allowed_networks: [], connections: 0,
  limits: { max_connections: 0, max_connections_per_address: 0, max_frame_bytes: 0, lines_per_second: 0, idle_timeout_seconds: 0, frame_timeout_seconds: 0 },
  accepted: 0, rejected_network: 0, rejected_limit: 0, tls_failed: 0, frame_too_large: 0, bad_frame: 0, idle_timeouts: 0, read_timeouts: 0, lines: 0,
  matched: 0, unmatched: 0, errors: 0, excluded: 0, outdated: 0, no_catalog: 0, dropped: 0, throttled: 0, unlicensed: 0, license_module: true, pending: 0, flush_failures: 0, last_flush_failed: false,
};

type Call = { method: string; url: string; body: unknown; type: string | undefined };
const calls: Call[] = [];
let services: ShadowService[];
let exclusions: ShadowExclusion[];
let cat: ShadowCatalog;
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });

beforeEach(() => {
  calls.length = 0;
  services = [svc];
  exclusions = [];
  cat = catalog;
  handler = () => undefined;
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
      if (path === "/api/v1/shadow-ai/catalog" && method === "GET") return Promise.resolve(json(cat));
      if (path === "/api/v1/shadow-ai/settings") return Promise.resolve(json({ retention_days: 365, users_pseudonymized: true }));
      if (path === "/api/v1/shadow-ai/syslog") return Promise.resolve(json(syslogOff));
      if (path === "/api/v1/shadow-ai/services") return Promise.resolve(json({ items: services }));
      if (path === "/api/v1/shadow-ai/users") return Promise.resolve(json({ items: services.length ? [usr] : [] }));
      if (path === "/api/v1/shadow-ai/timeline")
        return Promise.resolve(json({ step: "day", items: services.length ? [{ bucket: "2026-10-27T00:00:00Z", requests: 1200, bytes: 2048, users: 3, services: 1 }] : [] }));
      if (path === "/api/v1/shadow-ai/imports" && method === "GET") return Promise.resolve(json({ items: [imp] }));
      if (path === "/api/v1/shadow-ai/imports" && method === "POST") return Promise.resolve(json(imp, 201));
      if (path === "/api/v1/shadow-ai/exclusions" && method === "GET") return Promise.resolve(json({ items: exclusions }));
      if (path === "/api/v1/shadow-ai/exclusions" && method === "POST")
        return Promise.resolve(json({ kind: "service", value: "chatgpt", comment: "", created_at: "2026-10-28T10:00:00Z", created_by: "user:u-me" }, 201));
      if (path.startsWith("/api/v1/shadow-ai/exclusions/") && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const renderScreen = (permissions: string[]) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ShadowAIScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const reader = ["shadow_ai.read", "events.read"];
const manager = ["shadow_ai.read", "shadow_ai.manage", "shadow_ai.exclusions.manage", "events.read"];
// Администратор системы (4В26): импорт и каталог — да, исключения — нет.
const sysadmin = ["shadow_ai.read", "shadow_ai.manage", "events.read"];
const openTab = async (name: string) => fireEvent.mouseDown(await screen.findByRole("tab", { name }), { button: 0 });

describe("экран «Теневой ИИ»", () => {
  it("показывает сервисы, пользователей псевдонимами со ссылкой на события и динамику", async () => {
    renderScreen(reader);
    const table = await screen.findByRole("table", { name: "Сервисы за период" });
    expect(within(table).getByText("ChatGPT")).toBeInTheDocument();
    expect(within(table).getByText("Чат")).toBeInTheDocument();
    const users = await screen.findByRole("table", { name: "Пользователи за период" });
    expect(within(users).getByText(alias)).toBeInTheDocument();
    expect(within(users).getByText("ChatGPT, DeepSeek")).toBeInTheDocument();
    const link = within(users).getByRole("link", { name: `События пользователя ${alias}` });
    expect(new URLSearchParams(link.getAttribute("href")!.split("?")[1]).get("f")).toBe(`user = "${alias}"`);
    expect(screen.getByRole("img", { name: /Обращения к ИИ-сервисам/ })).toBeInTheDocument();
    // Только чтение: кнопок управления нет.
    expect(screen.queryByRole("button", { name: /Исключить/ })).toBeNull();
    // Пользователи выбранного сервиса — запрос с service.
    fireEvent.click(within(table).getByRole("button", { name: "Пользователи сервиса" }));
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/api/v1/shadow-ai/users?") && c.url.includes("service=chatgpt"))).toBe(true));
    // Смена периода — новый запрос с другим началом.
    const before = calls.filter((c) => c.url.startsWith("/api/v1/shadow-ai/services?")).length;
    fireEvent.change(screen.getByLabelText("Период"), { target: { value: "7d" } });
    await waitFor(() => expect(calls.filter((c) => c.url.startsWith("/api/v1/shadow-ai/services?")).length).toBeGreaterThan(before));
  });

  it("пустой период и незагруженный каталог", async () => {
    services = [];
    cat = { loaded: false, valid: false, services: [] };
    renderScreen(manager);
    expect(await screen.findByText("За период обращений к ИИ-сервисам не найдено")).toBeInTheDocument();
    expect(screen.getByText(/Каталог ИИ-сервисов не загружен/)).toBeInTheDocument();
    await openTab("Импорт и каталог");
    expect(await screen.findByRole("button", { name: "Импортировать журнал" })).toBeDisabled();
  });

  it("отказ сервера в чтении показан текстом", async () => {
    handler = (c) => (c.url.startsWith("/api/v1/shadow-ai/services") ? problem(403, "forbidden", "Нет права shadow_ai.read.") : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/Сервер отказал в действии. Нет права shadow_ai.read./)).toBeInTheDocument();
  });

  it("импорт журнала: файл телом запроса, итог с номерами ошибочных строк", async () => {
    renderScreen(manager);
    await openTab("Импорт и каталог");
    fireEvent.change(await screen.findByLabelText("Формат журнала"), { target: { value: "cef" } });
    const file = new File(["CEF:0|x|y|1|1|n|1|dhost=chatgpt.com\n"], "access.log.gz", { type: "application/gzip" });
    fireEvent.change(screen.getByLabelText("Файл журнала"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Импортировать журнал" }));
    expect(await screen.findByText(/Журнал импортирован: строк 10/)).toBeInTheDocument();
    expect(screen.getByText(/Ошибочные строки: 2, 5, 9/)).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.url.startsWith("/api/v1/shadow-ai/imports"))!;
    expect(post.url).toBe("/api/v1/shadow-ai/imports?format=cef&compression=gzip");
    expect(post.body).toBe(file);
    expect(post.type).toBe("application/gzip");
    // История импорта.
    expect(within(screen.getByRole("table", { name: "Импорты" })).getByText("Squid access.log")).toBeInTheDocument();
  });

  it("импорт: отказ сервера 403 и конфликт 409 показаны", async () => {
    handler = (c) => (c.method === "POST" && c.url.startsWith("/api/v1/shadow-ai/imports") ? problem(403, "forbidden", "Нет права shadow_ai.manage.") : undefined);
    renderScreen(manager);
    await openTab("Импорт и каталог");
    fireEvent.change(await screen.findByLabelText("Файл журнала"), { target: { files: [new File(["x"], "a.log")] } });
    fireEvent.click(screen.getByRole("button", { name: "Импортировать журнал" }));
    expect(await screen.findByText(/Сервер отказал в действии. Нет права shadow_ai.manage./)).toBeInTheDocument();
    handler = (c) => (c.method === "POST" ? problem(409, "conflict", "Этот файл уже импортирован.") : undefined);
    fireEvent.click(screen.getByRole("button", { name: "Импортировать журнал" }));
    expect(await screen.findByText("Этот файл уже импортирован.")).toBeInTheDocument();
  });

  it("без права управления нет импорта, загрузки каталога и исключений", async () => {
    exclusions = [{ kind: "user", value: alias, comment: "шлюз", created_at: "2026-10-28T10:00:00Z", created_by: "user:u-1" }];
    renderScreen(reader);
    await openTab("Импорт и каталог");
    expect(await screen.findByText(/Импортировать журналы и загружать каталог может администратор безопасности/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Загрузить каталог" })).toBeNull();
    await openTab("Исключения");
    expect(await screen.findByText("шлюз")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Добавить исключение" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Снять исключение/ })).toBeNull();
  });

  it("без права исключений нет кнопок исключения, импорт доступен", async () => {
    exclusions = [{ kind: "user", value: alias, comment: "шлюз", created_at: "2026-10-28T10:00:00Z", created_by: "user:u-1" }];
    renderScreen(sysadmin);
    const table = await screen.findByRole("table", { name: "Сервисы за период" });
    expect(within(table).queryByRole("button", { name: "Исключить сервис ChatGPT" })).toBeNull();
    await openTab("Импорт и каталог");
    expect(await screen.findByRole("button", { name: "Импортировать журнал" })).toBeInTheDocument();
    await openTab("Исключения");
    expect(await screen.findByText("шлюз")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Добавить исключение" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Снять исключение/ })).toBeNull();
  });

  it("исключение сервиса из таблицы — с паролем; снятие — с подтверждением", async () => {
    renderScreen(manager);
    const table = await screen.findByRole("table", { name: "Сервисы за период" });
    fireEvent.click(within(table).getByRole("button", { name: "Исключить сервис ChatGPT" }));
    const dialog = await screen.findByRole("dialog", { name: "Исключение из учёта теневого ИИ" });
    expect(within(dialog).getByLabelText("Сервис")).toHaveValue("chatgpt");
    const add = within(dialog).getByRole("button", { name: "Добавить исключение" });
    expect(add).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    fireEvent.change(within(dialog).getByLabelText("Комментарий"), { target: { value: "корпоративная подписка" } });
    fireEvent.click(add);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const post = calls.find((c) => c.method === "POST" && c.url === "/api/v1/shadow-ai/exclusions")!;
    expect(post.body).toEqual({ kind: "service", service: "chatgpt", comment: "корпоративная подписка", password: "Correct-Horse-1" });

    exclusions = [{ kind: "service", value: "chatgpt", comment: "корпоративная подписка", created_at: "2026-10-28T10:00:00Z", created_by: "user:u-me" }];
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Снять исключение chatgpt" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Снять исключение" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/v1/shadow-ai/exclusions/service/chatgpt")).toBe(true));
  });

  it("исключение пользователя логином: логин уходит на сервер один раз, неверный пароль — ошибка в диалоге", async () => {
    handler = (c) =>
      c.method === "POST" && c.url === "/api/v1/shadow-ai/exclusions" && (c.body as { password?: string }).password === "bad"
        ? problem(403, "reauthentication_failed", "Неверный пароль.")
        : undefined;
    renderScreen(manager);
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить исключение" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Что исключить"), { target: { value: "user" } });
    fireEvent.change(within(dialog).getByLabelText("Логин или адрес"), { target: { value: "gw-service" } });
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "bad" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Добавить исключение" }));
    expect(await within(dialog).findByText(/Неверный пароль/)).toBeInTheDocument();
    // Пароль стирается после отказа.
    expect(within(dialog).getByLabelText("Текущий пароль")).toHaveValue("");
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toEqual({ kind: "user", login: "gw-service", password: "bad" });
  });

  it("приём по syslog: выключен и включён со счётчиками", async () => {
    renderScreen(reader);
    await openTab("Приём по syslog");
    expect(await screen.findByText(/Приём журналов по syslog выключен/)).toBeInTheDocument();
  });

  it("приём по syslog включён: режим, сети и счётчики отказов", async () => {
    handler = (c) =>
      c.url === "/api/v1/shadow-ai/syslog"
        ? json({
            ...syslogOff, enabled: true, running: true, address: "0.0.0.0:6514", format: "cef", tls: true, client_cert_required: true, allowed_networks: ["10.20.0.0/24"],
            connections: 2, rejected_network: 5, frame_too_large: 1, lines: 900, last_flush_failed: true,
            limits: { max_connections: 256, max_connections_per_address: 16, max_frame_bytes: 16384, lines_per_second: 5000, idle_timeout_seconds: 300, frame_timeout_seconds: 30 },
          })
        : undefined;
    renderScreen(reader);
    await openTab("Приём по syslog");
    expect(await screen.findByText("TLS, клиентский сертификат обязателен")).toBeInTheDocument();
    expect(screen.getByText("10.20.0.0/24")).toBeInTheDocument();
    const conns = screen.getByRole("table", { name: "Соединения syslog" });
    expect(within(within(conns).getByText("Отказ: источник не из разрешённых сетей").closest("tr")!).getByText("5")).toBeInTheDocument();
    expect(screen.getByText(/Последняя запись сводок в базу не удалась/)).toBeInTheDocument();
    expect(screen.queryByText(/строки может прислать любой узел сети/)).toBeNull();
  });

  it("TLS без клиентского сертификата и без разрешённых сетей — предупреждение", async () => {
    handler = (c) =>
      c.url === "/api/v1/shadow-ai/syslog"
        ? json({ ...syslogOff, enabled: true, running: true, address: "0.0.0.0:6514", format: "cef", tls: true, client_cert_required: false, allowed_networks: [] })
        : undefined;
    renderScreen(reader);
    await openTab("Приём по syslog");
    expect(await screen.findByText(/строки может прислать любой узел сети/)).toBeInTheDocument();
  });

  it("приём по syslog остановлен ошибкой — сообщение с причиной", async () => {
    handler = (c) =>
      c.url === "/api/v1/shadow-ai/syslog"
        ? json({ ...syslogOff, enabled: true, running: false, stopped_at: "2026-10-28T11:00:00Z", last_error: "приём по syslog: use of closed network connection", accept_errors: 4 })
        : undefined;
    renderScreen(reader);
    await openTab("Приём по syslog");
    expect(await screen.findByText(/Приём по syslog остановлен/)).toBeInTheDocument();
    expect(screen.getByText(/use of closed network connection/)).toBeInTheDocument();
    const conns = screen.getByRole("table", { name: "Соединения syslog" });
    expect(within(within(conns).getByText("Временные ошибки приёма соединений").closest("tr")!).getByText("4")).toBeInTheDocument();
  });
});
