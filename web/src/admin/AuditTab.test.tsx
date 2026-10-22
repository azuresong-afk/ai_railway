import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AdminScreen } from "./AdminScreen";
import { parseActions } from "./AuditTab";

const me = (permissions: string[]): Me => ({
  user: { id: "u-me", login: "auditor", display_name: "Аудитор", role: "auditor", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  permissions,
});

const record = (seq: number, action: string, title: string) => ({
  seq,
  id: `01900000-0000-7000-8000-${String(seq).padStart(12, "0")}`,
  ts: "2026-10-21T12:00:00Z",
  actor: { type: "user", id: "u-1", name: "admin" },
  source_ip: "192.0.2.10",
  action,
  action_title: title,
  object: { type: "user", id: "u-2" },
  result: "success",
  // Разметка в подробностях — только текст (ТЗ 6.9).
  details: { reason: "[скрыто]", note: "<img src=x onerror=alert(1)>" },
  hash: "ab".repeat(32),
});

const urls: string[] = [];
let verify: unknown;

beforeEach(() => {
  urls.length = 0;
  verify = { checked_at: "2026-10-21T12:00:00Z", ok: false, checked: 41, last_seq: 41, reason: "rewritten", broken_seq: 42 };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      urls.push(`${init.method ?? "GET"} ${url}`);
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url.startsWith("/api/v1/audit?")) {
        return url.includes("cursor=")
          ? json({ items: [record(1, "auth.login", "Вход в консоль")] })
          : json({ items: [record(3, "user.create", "Создание учётной записи"), record(2, "auth.login", "Вход в консоль")], next_cursor: "Mjo=" });
      }
      if (url === "/api/v1/audit/verify") return json(verify);
      return json({ code: "not_found", detail: "нет", status: 404 }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AdminScreen me={me(permissions)} />
    </QueryClientProvider>,
  );

describe("журнал аудита", () => {
  it("вкладка видна только с audit.read", () => {
    renderScreen(["users.read"]);
    expect(screen.queryByRole("tab", { name: "Журнал аудита" })).toBeNull();
  });

  it("записи, подгрузка по курсору и подробности как текст", async () => {
    renderScreen(["audit.read"]);
    expect(await screen.findByText("Создание учётной записи")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Проверить цепочку" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Показать ещё" }));
    await waitFor(() => expect(screen.getAllByText("Вход в консоль")).toHaveLength(2));
    expect(urls.some((u) => u.includes("cursor=Mjo%3D"))).toBe(true);
    fireEvent.click(screen.getAllByRole("button", { name: "Подробности" })[0]!);
    expect(screen.getByText(/onerror=alert/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("фильтр уходит в запрос, неверный код не отправляется", async () => {
    renderScreen(["audit.read"]);
    await screen.findByText("Создание учётной записи");
    fireEvent.change(screen.getByLabelText("Коды событий"), { target: { value: "auth" } });
    expect(screen.getByRole("alert")).toHaveTextContent("не код события");
    expect(screen.getByRole("button", { name: "Показать" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Коды событий"), { target: { value: "auth.*, user.create" } });
    fireEvent.change(screen.getByLabelText("Субъект"), { target: { value: " admin " } });
    fireEvent.change(screen.getByLabelText("Результат"), { target: { value: "denied" } });
    fireEvent.click(screen.getByRole("button", { name: "Показать" }));
    await waitFor(() => expect(urls.some((u) => u.includes("action=auth.*&action=user.create&actor=admin&result=denied"))).toBe(true));
  });

  it("проверка цепочки по кнопке показывает разрыв", async () => {
    renderScreen(["audit.read", "audit.verify"]);
    fireEvent.click(await screen.findByRole("button", { name: "Проверить цепочку" }));
    expect(await screen.findByText(/Цепочка нарушена на записи № 42: журнал изменён после прошлой проверки/)).toBeInTheDocument();
    expect(urls).toContain("POST /api/v1/audit/verify");
    // Список перечитывается с новым концом периода — видна запись итога проверки.
    await waitFor(() => expect(urls.filter((u) => u.startsWith("GET /api/v1/audit?")).length).toBe(2));
  });

  it("цела — сообщение с числом записей", async () => {
    verify = { checked_at: "2026-10-21T12:00:00Z", ok: true, checked: 1200, last_seq: 1200, reason: "ok", broken_seq: null };
    renderScreen(["audit.read", "audit.verify"]);
    fireEvent.click(await screen.findByRole("button", { name: "Проверить цепочку" }));
    expect(await screen.findByText(/Цепочка цела: проверено 1\s200 записей/)).toBeInTheDocument();
  });

  it("разбор кодов", () => {
    expect(parseActions(" auth.*, user.create ").actions).toEqual(["auth.*", "user.create"]);
    expect(parseActions("").actions).toEqual([]);
    expect(parseActions("auth").error).toBeDefined();
    expect(parseActions("auth.%").error).toBeDefined();
    expect(parseActions(Array(21).fill("auth.login").join(",")).error).toBeDefined();
  });
});
