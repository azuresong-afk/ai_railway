import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { UsageScreen } from "./UsageScreen";

vi.mock("../dashboards/Chart", () => ({
  Chart: ({ label }: { label: string }) => <div role="img" aria-label={label} />,
  token: () => "#000",
}));

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u1", login: "a", display_name: "Админ", role: "system_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

const row = (key: string, o: Record<string, unknown> = {}) => ({ key, requests: 10, with_findings: 1, blocked: 0, would_block: 0, masked: 0, tokens_prompt: 100, tokens_completion: 200, cost: "1.5000000", unpriced_requests: 0, ...o });
const status = (o: Record<string, unknown> = {}) => ({
  application_id: "app-1", application: "bot", name: "Бот", month: "2026-10",
  budget: { mode: "soft", monthly_limit: "1000.00", updated_at: "2026-10-01T00:00:00Z" },
  spent: "850.00", priced_tokens: 1, unpriced_tokens: 0, requests: 5, unpriced_requests: 0, percent: 85, exhausted: false, ...o,
});
const consumption = {
  period: { name: "30d", from: "2026-09-22T00:00:00Z", to: "2026-10-22T00:00:00Z", unit: "day", timezone: "Europe/Moscow", aggregates_ready: true },
  totals: { requests: 50, with_findings: 2, non_text_unchecked: 0, blocked: 0, would_block: 0, masked: 0, tokens_prompt: 1000, tokens_completion: 2000, cost: "7.0000000", unpriced_requests: 4 },
  series: [{ bucket: "2026-10-21T00:00:00Z", requests: 50, tokens: 3000, cost: "7.0000000" }],
  by_app: [row("bot")],
  by_model: [row("gpt-x"), row("local-model", { cost: "0.0000000", unpriced_requests: 4 })],
  by_provider: [], by_department: [row("")], by_user: [row("u-abc")],
  forecast: { month: "2026-10", spent: "7.0000000", projected: "10.0000000", enough: true, month_elapsed: 0.7 },
  budgets: [status()],
};

interface Call { method: string; url: string; body: unknown }
const calls: Call[] = [];
let prices: Record<string, unknown>[];
beforeEach(() => {
  calls.length = 0;
  prices = [{ id: "pr-1", provider_id: "p-1", model: "gpt-x", input_price: "0.1500", output_price: "0.3000", created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" }];
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const ok = (b: unknown, code = 200) => Promise.resolve(new Response(code === 204 ? null : JSON.stringify(b), { status: code }));
      if (url.startsWith("/api/v1/dashboards/consumption")) return ok(consumption);
      if (url === "/api/v1/model-prices" && method === "GET") return ok({ items: prices });
      if (url === "/api/v1/model-prices" && method === "POST") return ok({ id: "pr-2", ...JSON.parse(String(init.body)), created_at: "x", updated_at: "x" }, 201);
      if (url === "/api/v1/providers") return ok({ items: [{ id: "p-1", name: "Основной" }] });
      if (url.startsWith("/api/v1/budgets")) return ok({ month: "2026-10", items: [status()] });
      if (url.startsWith("/api/v1/applications?")) return ok({ items: [{ id: "app-1", name: "Бот", status: "active" }, { id: "app-2", name: "Чат", status: "active" }], next_cursor: "" });
      if (url === "/api/v1/applications/app-2/budget" && method === "PUT") return ok(status({ application_id: "app-2", name: "Чат" }));
      return ok({ status: 404, code: "not_found", detail: "нет" }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <UsageScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const all = ["dashboards.read", "model_prices.read", "model_prices.manage", "budgets.read", "budgets.manage"];

describe("экран «Потребление»", () => {
  it("показывает расход, прогноз и срезы; стоимость без цены — «не определена»", async () => {
    renderScreen(all);
    expect(await screen.findByText("Прогноз на 2026-10")).toBeTruthy();
    expect(screen.getByText(/нужны сутки месяца/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Срез"), { target: { value: "model" } });
    const t = screen.getByRole("table", { name: "Потребление: Модели" });
    expect(within(t).getByText("не определена")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Срез"), { target: { value: "department" } });
    expect(within(screen.getByRole("table", { name: "Потребление: Подразделения" })).getByText("не указано")).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "Исполнение бюджетов" })).getByText("85 %")).toBeTruthy();
  });

  it("без прав на цены и бюджеты остаётся только расход", async () => {
    renderScreen(["dashboards.read"]);
    await screen.findByText("Прогноз на 2026-10");
    expect(screen.queryByRole("tab", { name: "Цены моделей" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Бюджеты" })).toBeNull();
    expect(screen.queryByRole("table", { name: "Исполнение бюджетов" })).toBeNull();
  });

  it("читатель цен не видит кнопок изменения", async () => {
    renderScreen(["dashboards.read", "model_prices.read"]);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Цены моделей" }), { button: 0 });
    await screen.findByText("gpt-x");
    expect(screen.getByText("Основной")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Задать цену модели" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Удалить цену/ })).toBeNull();
  });

  it("цена: неверный формат блокирует кнопку, верный — отправляется", async () => {
    renderScreen(all);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Цены моделей" }), { button: 0 });
    await screen.findByText("gpt-x");
    fireEvent.click(screen.getByRole("button", { name: "Задать цену модели" }));
    const dlg = await screen.findByRole("dialog", { name: "Новая цена модели" });
    await within(dlg).findByRole("option", { name: "Основной" });
    fireEvent.change(within(dlg).getByLabelText("Провайдер"), { target: { value: "p-1" } });
    fireEvent.change(within(dlg).getByLabelText("Модель"), { target: { value: "gpt-y" } });
    fireEvent.change(within(dlg).getByLabelText(/Цена входа/), { target: { value: "0,1" } });
    fireEvent.change(within(dlg).getByLabelText(/Цена выхода/), { target: { value: "0.2" } });
    expect((within(dlg).getByRole("button", { name: "Задать цену" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText(/Цена входа/), { target: { value: "0.1" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Задать цену" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ provider_id: "p-1", model: "gpt-y", input_price: "0.1", output_price: "0.2" }));
  });

  it("бюджет: жёсткий режим предупреждает, сумма проверяется, запрос уходит приложению", async () => {
    renderScreen(all);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Бюджеты" }), { button: 0 });
    await screen.findByRole("option", { name: "Чат" });
    fireEvent.change(screen.getByLabelText("Приложение без бюджета"), { target: { value: "app-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Задать бюджет" }));
    const dlg = await screen.findByRole("dialog", { name: "Бюджет: Чат" });
    fireEvent.change(within(dlg).getByLabelText("Бюджет в месяц, ₽"), { target: { value: "0" } });
    expect((within(dlg).getByRole("button", { name: "Сохранить бюджет" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Бюджет в месяц, ₽"), { target: { value: "500.50" } });
    fireEvent.change(within(dlg).getByLabelText("Режим"), { target: { value: "hard" } });
    expect(within(dlg).getByText(/отказом 429/)).toBeTruthy();
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить бюджет" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mode: "hard", monthly_limit: "500.50" }));
  });
});
