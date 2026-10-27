import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { ReportsScreen } from "./ReportsScreen";

const me = (permissions: string[], own_scope: string[] = []): Me =>
  ({
    user: { id: "u1", login: "a", display_name: "Админ", role: "system_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    own_scope,
  }) as Me;

const schedule = {
  id: "s-1", name: "Недельная сводка", report: "summary", frequency: "weekly", weekday: 1, at: "09:00", format: "xlsx",
  channel_id: "c-1", enabled: true, next_run_at: "2026-10-26T06:00:00Z", version: 3,
  created_at: "2026-10-01T00:00:00Z", created_by: "a", updated_at: "2026-10-01T00:00:00Z", updated_by: "a",
};

interface Call { method: string; url: string; body: unknown }
const calls: Call[] = [];

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const ok = (b: unknown, code = 200) => Promise.resolve(new Response(code === 204 ? null : JSON.stringify(b), { status: code }));
      if (url === "/api/v1/report-schedules" && method === "GET") return ok({ items: [schedule] });
      if (url === "/api/v1/report-schedules" && method === "POST") return ok({ ...schedule, id: "s-2" }, 201);
      if (url === "/api/v1/report-schedules/s-1" && method === "PUT") return ok(schedule);
      if (url === "/api/v1/report-schedules/s-1/runs") return ok({ items: [{ id: "r-1", due_at: "2026-10-19T06:00:00Z", period_first: "2026-10-12", period_last: "2026-10-18", status: "failed", attempts: 5, error: "smtp", created_at: "2026-10-19T06:00:00Z" }] });
      if (url.startsWith("/api/v1/applications?")) return ok({ items: [{ id: "app-1", slug: "bot", name: "Бот", status: "active" }], next_cursor: "" });
      // Администратор системы без права на каналы уведомлений (3Н46 ревью 3.r4): каналы для расписания — отдельным списком.
      if (url === "/api/v1/notify-channels") return ok({ status: 403, code: "forbidden", detail: "Недостаточно прав." }, 403);
      if (url === "/api/v1/report-channels") return ok({ items: [{ id: "c-1", name: "Почта SOC" }] });
      return ok({ status: 404, code: "not_found", detail: "нет" }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[], ownScope: string[] = []) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ReportsScreen me={me(permissions, ownScope)} />
    </QueryClientProvider>,
  );
const all = ["reports.read", "applications.read", "reports.schedules.read", "reports.schedules.manage"];

describe("экран «Отчёты»", () => {
  it("предпросмотр открывается в рамке без разрешений, скачивание — ссылками на сервер", () => {
    renderScreen(all);
    fireEvent.change(screen.getByLabelText("С даты"), { target: { value: "2026-10-01" } });
    fireEvent.change(screen.getByLabelText("По дату"), { target: { value: "2026-10-07" } });
    expect(screen.getByRole("link", { name: "Скачать CSV" }).getAttribute("href")).toBe("/api/v1/reports/summary?format=csv&delimiter=semicolon&from=2026-10-01&to=2026-10-07");
    expect(screen.getByRole("link", { name: "Скачать XLSX" }).getAttribute("href")).toContain("format=xlsx");
    fireEvent.click(screen.getByRole("button", { name: "Показать отчёт" }));
    const frame = screen.getByTitle("Предпросмотр отчёта");
    expect(frame.getAttribute("sandbox")).toBe("");
    expect(frame.getAttribute("src")).toContain("format=html");
  });

  it("разделитель CSV: по умолчанию «;», запятая — по выбору; на XLSX и HTML не влияет", () => {
    renderScreen(all);
    expect(screen.getByRole("link", { name: "Скачать CSV" }).getAttribute("href")).toContain("delimiter=semicolon");
    fireEvent.change(screen.getByLabelText("Разделитель CSV"), { target: { value: "comma" } });
    expect(screen.getByRole("link", { name: "Скачать CSV" }).getAttribute("href")).toContain("delimiter=comma");
    expect(screen.getByRole("link", { name: "Скачать XLSX" }).getAttribute("href")).not.toContain("delimiter");
  });

  it("начало позже конца блокирует показ и скачивание", () => {
    renderScreen(all);
    fireEvent.change(screen.getByLabelText("С даты"), { target: { value: "2026-10-09" } });
    fireEvent.change(screen.getByLabelText("По дату"), { target: { value: "2026-10-01" } });
    expect(screen.getByText("Начало периода не может быть позже конца.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Показать отчёт" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("link", { name: "Скачать CSV" })).toBeNull();
  });

  it("без дат — последние 30 суток; одна дата без другой блокирует выгрузку", () => {
    renderScreen(all);
    expect(screen.getByRole("link", { name: "Скачать CSV" }).getAttribute("href")).toBe("/api/v1/reports/summary?format=csv&delimiter=semicolon");
    fireEvent.change(screen.getByLabelText("С даты"), { target: { value: "2026-10-01" } });
    expect(screen.getByText("Укажите обе даты или оставьте обе пустыми.")).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Скачать CSV" })).toBeNull();
  });

  it("владелец приложения видит только сводный отчёт и без вкладки рассылки", () => {
    // reports.read и applications.read у него только на свои объекты (own_scope), 3Н46 ревью 3.r4.
    renderScreen(["reports.read", "applications.read"], ["applications.read", "reports.read"]);
    expect(screen.queryByRole("tab", { name: "Рассылка" })).toBeNull();
    const sel = screen.getByLabelText("Отчёт") as HTMLSelectElement;
    expect([...sel.options].map((o) => o.value)).toEqual(["summary"]);
    expect((screen.getByRole("button", { name: "Показать отчёт" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("расписания: читатель не видит кнопок изменения, журнал отправок открывается", async () => {
    renderScreen(["reports.read", "applications.read", "reports.schedules.read"]);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Рассылка" }), { button: 0 });
    await screen.findByText("Недельная сводка");
    expect(screen.queryByRole("button", { name: "Добавить расписание" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Удалить расписание/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Журнал отправок" }));
    const t = await screen.findByRole("table", { name: "Журнал отправок" });
    expect(within(t).getByText("не доставлено")).toBeTruthy();
  });

  it("новое расписание отправляется только с почтовым каналом", async () => {
    renderScreen(all);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Рассылка" }), { button: 0 });
    await screen.findByText("Недельная сводка");
    fireEvent.click(screen.getByRole("button", { name: "Добавить расписание" }));
    const create = screen.getByRole("button", { name: "Создать расписание" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    await screen.findByRole("option", { name: "Почта SOC" });
    expect(screen.queryByRole("option", { name: "Хук" })).toBeNull();
    fireEvent.change(screen.getByLabelText("Название"), { target: { value: "Сводка" } });
    fireEvent.change(screen.getByLabelText("Почтовый канал"), { target: { value: "c-1" } });
    fireEvent.click(create);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Сводка", report: "summary", frequency: "weekly", weekday: 1, at: "09:00", format: "xlsx", channel_id: "c-1", enabled: true }));
  });

  it("изменение передаёт версию расписания", async () => {
    renderScreen(all);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Рассылка" }), { button: 0 });
    await screen.findByText("Недельная сводка");
    fireEvent.click(screen.getByRole("button", { name: "Изменить расписание Недельная сводка" }));
    await screen.findByRole("option", { name: "Почта SOC" });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить расписание" }));
    await waitFor(() => expect((calls.find((c) => c.method === "PUT")?.body as { version: number }).version).toBe(3));
  });
});
