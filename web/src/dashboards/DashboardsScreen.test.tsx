import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { DashboardsScreen } from "./DashboardsScreen";

// Графики ECharts в jsdom не рисуются (нет разметки): подменяем компонент, данные проверяются через таблицы.
vi.mock("./Chart", () => ({
  Chart: ({ label }: { label: string }) => <div role="img" aria-label={label} />,
  token: () => "#000",
}));

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u1", login: "a", display_name: "Аналитик", role: "analyst", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

const period = { name: "24h", from: "2026-10-21T10:00:00Z", to: "2026-10-22T10:00:00Z", unit: "hour", timezone: "Europe/Moscow", aggregates_ready: true };
const totals = { requests: 1200, with_findings: 300, non_text_unchecked: 4, blocked: 20, would_block: 5, masked: 70, tokens_prompt: 5000, tokens_completion: 7000, cost: "12.5000000", unpriced_requests: 3 };
const overview = {
  period,
  totals,
  latency: { p95_ms: 25, overflow: false, requests: 1200 },
  decisions: [
    { bucket: "2026-10-22T09:00:00Z", key: "allowed", value: 90 },
    { bucket: "2026-10-22T09:00:00Z", key: "blocked", value: 10 },
  ],
  top_detectors: [{ key: "pii.regex", value: 40 }],
  apps: [{ key: "support-bot", requests: 900, with_findings: 200, blocked: 15, would_block: 0, masked: 50, tokens_prompt: 1, tokens_completion: 1, cost: "1", unpriced_requests: 0 }],
  feed: [{ id: "6f1c0000-0000-4000-8000-000000000001", time: "2026-10-22T09:30:00Z", app: "support-bot", model: "gpt-x", action: "block", policy_mode: "enforce", severity: "high", rule: "R-1", threats: ["DM-01"] }],
};

const calls: string[] = [];
let streams: { url: string; closed: boolean }[];
beforeEach(() => {
  calls.length = 0;
  streams = [];
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal(
    "EventSource",
    class {
      static CLOSED = 2;
      readyState = 1;
      onopen: (() => void) | null = null;
      onerror: (() => void) | null = null;
      rec: { url: string; closed: boolean };
      constructor(url: string) {
        this.rec = { url, closed: false };
        streams.push(this.rec);
      }
      addEventListener() {}
      close() {
        this.rec.closed = true;
      }
    },
  );
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      calls.push(url);
      const ok = (b: unknown) => Promise.resolve(new Response(JSON.stringify(b), { status: 200 }));
      if (url.startsWith("/api/v1/dashboards/overview")) return ok(overview);
      if (url.startsWith("/api/v1/alerts")) return ok({ items: [{ id: "a1", title: "Всплеск блокировок" }], next_cursor: "" });
      if (url.startsWith("/api/v1/incidents")) return ok({ items: [], next_cursor: "" });
      if (url.startsWith("/api/v1/system/status")) return ok({ gateways: [{ id: "g1", name: "gw-1", state: "offline" }] });
      if (url.startsWith("/api/v1/applications")) return ok({ items: [{ id: "app-1", name: "Бот поддержки", slug: "support-bot", status: "active" }], next_cursor: "" });
      if (url.startsWith("/api/v1/dashboards/app/app-1")) return ok({ period, application: { id: "app-1", slug: "support-bot", name: "Бот поддержки" }, totals, latency: { p95_ms: 0, overflow: false, requests: 0 }, decisions: [], top_detectors: [], models: [], feed: [] });
      return Promise.resolve(new Response(JSON.stringify({ status: 403, code: "forbidden", detail: "Нет прав." }), { status: 403 }));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <DashboardsScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );

describe("экран «Обзор»", () => {
  it("показывает показатели, ленту решений и то, что требует внимания", async () => {
    renderScreen(["dashboards.read", "events.read", "alerts.read", "system.read"]);
    expect(await screen.findByText("1 200")).toBeTruthy();
    expect(screen.getByText("до 25 мс")).toBeTruthy();
    const feed = screen.getByRole("table", { name: "Лента решений" });
    expect(within(feed).getByText("R-1")).toBeTruthy();
    expect(within(feed).getByRole("link").getAttribute("href")).toContain("event=6f1c0000-0000-4000-8000-000000000001");
    expect(await screen.findByText(/Критическое оповещение: Всплеск блокировок/)).toBeTruthy();
    expect(await screen.findByText(/Шлюз «gw-1» не в сети/)).toBeTruthy();
    // Права, которых нет, не запрашиваются: инциденты не читаются.
    expect(calls.some((u) => u.startsWith("/api/v1/incidents"))).toBe(false);
  });

  it("график доступен таблицей данных", async () => {
    renderScreen(["dashboards.read", "events.read"]);
    await screen.findByText("1 200");
    fireEvent.click(screen.getAllByRole("button", { name: "Показать данные таблицей" })[0]!);
    const t = await screen.findByRole("table", { name: "Данные: Запросы по решениям" });
    expect(within(t).getByText("Заблокировано")).toBeTruthy();
  });

  it("смена периода делает новый запрос, реальное время открывает поток и закрывает при выключении", async () => {
    renderScreen(["dashboards.read", "events.read"]);
    await screen.findByText("1 200");
    fireEvent.change(screen.getByLabelText("Период"), { target: { value: "7d" } });
    await waitFor(() => expect(calls.some((u) => u.includes("overview?period=7d"))).toBe(true));
    fireEvent.click(screen.getByRole("checkbox", { name: "Обновлять в реальном времени" }));
    await waitFor(() => expect(streams.length).toBe(1));
    expect(streams[0]!.url).toContain("dashboard=overview");
    expect(streams[0]!.url).toContain("period=7d");
    fireEvent.click(screen.getByRole("checkbox", { name: "Обновлять в реальном времени" }));
    await waitFor(() => expect(streams[0]!.closed).toBe(true));
  });

  it("произвольный период: начало позже конца не отправляется", async () => {
    renderScreen(["dashboards.read", "events.read"]);
    await screen.findByText("1 200");
    fireEvent.change(screen.getByLabelText("Период"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("С"), { target: { value: "2026-10-21T12:00" } });
    fireEvent.change(screen.getByLabelText("По"), { target: { value: "2026-10-21T10:00" } });
    expect(await screen.findByText("Начало должно быть раньше конца.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Применить период" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("владелец приложения видит только вкладку «Приложение»", async () => {
    renderScreen(["dashboards.read"]);
    expect(screen.queryByRole("tab", { name: "Обзор" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Угрозы" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Приложение" })).toBeTruthy();
    await screen.findByRole("option", { name: "Бот поддержки" });
    fireEvent.change(screen.getByRole("combobox", { name: "Приложение" }), { target: { value: "app-1" } });
    await waitFor(() => expect(calls.some((u) => u.startsWith("/api/v1/dashboards/app/app-1"))).toBe(true));
    expect(calls.some((u) => u.startsWith("/api/v1/dashboards/overview"))).toBe(false);
  });

  it("отказ сервера показывается ошибкой, а не пустым экраном", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ status: 403, code: "forbidden", detail: "Нет прав." }), { status: 403 })));
    renderScreen(["dashboards.read", "events.read"]);
    expect((await screen.findByRole("alert")).textContent).toContain("Нет прав.");
  });
});
