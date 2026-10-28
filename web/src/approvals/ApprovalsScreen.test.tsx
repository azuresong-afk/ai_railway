import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { Approval } from "./api";
import { ApprovalsScreen } from "./ApprovalsScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

const ap = (o: Partial<Approval> = {}): Approval => ({
  id: "ap-1", state: "pending", path: "mcp", application: "crm-bot", agent: "helper", user: "u-aaa", session: "sess-1", server: "files", tool: "delete_file",
  risk: "high", rule: "delete-needs-human", severity: "high", args_hash: "h1", gateway_id: "g-1",
  created_at: new Date().toISOString(), deadline: new Date(Date.now() + 125_000).toISOString(), waited_ms: 0, ...o,
});

type Call = { method: string; url: string; body: ReturnType<typeof JSON.parse> };
const calls: Call[] = [];
let list: Approval[];
let detail: Approval;
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });

beforeEach(() => {
  calls.length = 0;
  list = [ap()];
  detail = ap({ args: '{"path":"<script>x</script>"}' });
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      if (url.startsWith("/api/v1/approvals?")) return Promise.resolve(json({ items: list }));
      if (url === "/api/v1/approvals/ap-1" && method === "GET") return Promise.resolve(json(detail));
      if (url === "/api/v1/approvals/ap-1/approve") return Promise.resolve(json(ap({ state: "approved" })));
      if (url === "/api/v1/approvals/ap-1/deny") return Promise.resolve(json(ap({ state: "denied" })));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ApprovalsScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const decider = ["approvals.read", "approvals.decide", "events.read"];

describe("экран «Подтверждения»", () => {
  it("показывает запрос, аргументы текстом, отсчёт и ссылку на хронологию", async () => {
    renderScreen(decider);
    expect(await screen.findByText("delete-needs-human")).toBeTruthy();
    expect(within(screen.getByLabelText(/Подтверждение: delete_file/)).getByText("Ждёт решения")).toBeTruthy();
    expect(screen.getByText(/^2:0\d$/)).toBeTruthy();
    const args = await screen.findByText(/<script>x<\/script>/);
    expect(args.tagName).toBe("PRE");
    expect(document.querySelector("script")).toBeNull();
    const link = screen.getByRole("link", { name: /Хронология сессии sess-1/ });
    expect(link.getAttribute("href")).toBe("/session/sess-1");
  });

  it("одобрение передаёт args_hash показанного запроса", async () => {
    renderScreen(decider);
    await screen.findByText(/<script>/);
    fireEvent.click(screen.getByRole("button", { name: "Одобрить вызов" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/approve"))?.body).toEqual({ args_hash: "h1" }));
  });

  it("риск critical требует пароль или код", async () => {
    list = [ap({ risk: "critical" })];
    detail = ap({ risk: "critical", args: "{}" });
    renderScreen(decider, true);
    await screen.findByText("{}");
    const btn = screen.getByRole("button", { name: "Одобрить вызов" }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    expect(btn.disabled).toBe(false);
    fireEvent.click(btn);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/approve"))?.body).toEqual({ args_hash: "h1", code: "123456" }));
  });

  it("скрытые управляющие символы в аргументах: маркеры, предупреждение и повторная проверка (4В20 ревью 4.r2)", async () => {
    list = [ap({ risk: "low" })];
    detail = ap({ risk: "low", args: '{"path": "/tmp/\u202Etxt.exe"}' });
    renderScreen(decider, true);
    const args = await screen.findByText(/⟦U\+202E⟧txt\.exe/);
    expect(args.textContent).not.toContain("\u202E");
    expect(screen.getByText(/В аргументах есть скрытые управляющие символы/)).toBeTruthy();
    const btn = screen.getByRole("button", { name: "Одобрить вызов" }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(btn);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/approve"))?.body).toEqual({ args_hash: "h1", code: "123456" }));
  });

  it("409: запрос изменился — сообщение и обновление данных", async () => {
    handler = (c) => (c.url.endsWith("/approve") ? problem(409, "conflict", "args_hash") : undefined);
    renderScreen(decider);
    await screen.findByText(/<script>/);
    const before = calls.filter((c) => c.url === "/api/v1/approvals/ap-1").length;
    fireEvent.click(screen.getByRole("button", { name: "Одобрить вызов" }));
    expect(await screen.findByText(/Запрос изменился или уже закрыт/)).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.url === "/api/v1/approvals/ap-1").length).toBeGreaterThan(before));
  });

  it("отклонение с комментарием", async () => {
    renderScreen(decider);
    await screen.findByText(/<script>/);
    fireEvent.change(screen.getByLabelText("Комментарий"), { target: { value: "не нужно" } });
    fireEvent.click(screen.getByRole("button", { name: "Отклонить вызов" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/deny"))?.body).toEqual({ comment: "не нужно" }));
  });

  it("403 сервера показывается сообщением", async () => {
    handler = (c) => (c.url.endsWith("/deny") ? problem(403, "forbidden", "Решение вам недоступно.") : undefined);
    renderScreen(decider);
    await screen.findByText(/<script>/);
    fireEvent.click(screen.getByRole("button", { name: "Отклонить вызов" }));
    expect(await screen.findByText(/Решение вам недоступно/)).toBeTruthy();
  });

  it("без approvals.decide: только просмотр, аргументы не запрашиваются", async () => {
    renderScreen(["approvals.read"]);
    await screen.findByText("delete-needs-human");
    expect(screen.queryByRole("button", { name: /Одобрить вызов|Отклонить вызов/ })).toBeNull();
    expect(screen.getByText(/доступен только просмотр/)).toBeTruthy();
    expect(calls.some((c) => c.url === "/api/v1/approvals/ap-1")).toBe(false);
    // Без events.read ссылки на хронологию нет, псевдоним — текстом.
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("пустая очередь и ошибка списка", async () => {
    list = [];
    const { unmount } = renderScreen(decider);
    expect(await screen.findByText("Вызовов, ожидающих решения, нет")).toBeTruthy();
    unmount();
    handler = (c) => (c.url.startsWith("/api/v1/approvals?") ? problem(503, "unavailable", "x") : undefined);
    renderScreen(decider);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });

  it("ожидающие стоят выше остальных при фильтре «Все»", async () => {
    list = [ap({ id: "ap-2", state: "denied", tool: "old_tool" }), ap()];
    renderScreen(decider);
    fireEvent.change(await screen.findByLabelText("Состояние"), { target: { value: "" } });
    await waitFor(() => expect(calls.some((c) => c.url === "/api/v1/approvals?limit=100")).toBe(true));
    const cards = await screen.findAllByLabelText(/Подтверждение:/);
    expect(cards[0]!.getAttribute("aria-label")).toBe("Подтверждение: delete_file");
    expect(cards[1]!.getAttribute("aria-label")).toBe("Подтверждение: old_tool");
  });

  it("отсчёт доходит до нуля: срок истёк, кнопки решения выключены", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    list = [ap({ deadline: new Date(Date.now() + 3000).toISOString() })];
    renderScreen(decider);
    await screen.findByText("delete-needs-human");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000);
    });
    const card = screen.getByLabelText(/Подтверждение: delete_file/);
    expect(within(card).getByText(/Срок истёк\. Запрос/)).toBeTruthy();
    expect((within(card).getByRole("button", { name: "Одобрить вызов" }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(card).getByRole("button", { name: "Отклонить вызов" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("опрос списка раз в 5 секунд", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderScreen(decider);
    await screen.findByText("delete-needs-human");
    const n = () => calls.filter((c) => c.url.startsWith("/api/v1/approvals?")).length;
    const before = n();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5200);
    });
    expect(n()).toBeGreaterThan(before);
  });
});
