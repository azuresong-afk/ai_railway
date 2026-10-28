import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { ComplianceBaseView, ComplianceItem, ComplianceOverview } from "./api";
import { ComplianceScreen } from "./ComplianceScreen";

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

const auto: ComplianceItem = {
  id: "f117.p60.filter", source: "fstec-117", source_title: "Приказ ФСТЭК № 117", clause: "п. 60", title: "Фильтрация входа и выхода", summary: "Пересказ требования",
  applies: ["gis", "ispdn"], draft: false, manual: false, status: "partial",
  checks: [{ name: "filter_enforced", title: "Фильтрация включена", status: "partial", detail: "5 из 7 приложений промышленной среды" }],
  evidence: [
    { kind: "screen", title: "Приложения: политика и режим", path: "/apps" },
    { kind: "events", title: "События: отказы в доступе", path: "/events", query: { f: "type = auth_failure" } },
  ],
};
const manual: ComplianceItem = {
  id: "pdn.org.order", source: "152-fz", source_title: "152-ФЗ", clause: "ст. 19", title: "Приказ о мерах защиты", summary: "Организационная мера",
  applies: ["ispdn"], draft: false, manual: true, status: "manual",
};
const overview = (items: ComplianceItem[]): ComplianceOverview => ({
  generated_at: "2026-10-28T10:00:00Z", base: { version: 1, date: "2026-10-28", origin: "builtin", requirements: 2 },
  sources: [{ id: "fstec-117", title: "Приказ ФСТЭК № 117" }, { id: "152-fz", title: "152-ФЗ" }],
  summary: { percent: items.length ? 25 : null, counts: { met: 0, partial: 1, not_met: 0, not_applicable: 0, manual: 1 }, counted: items.length, drafts: 0 },
  items, unavailable: [],
});
const baseView: ComplianceBaseView = {
  active: { version: 1, date: "2026-10-28", origin: "builtin", requirements: 2 },
  builtin: { version: 1, date: "2026-10-28", origin: "builtin", requirements: 2 },
};

type Call = { method: string; url: string; body: unknown };
const calls: Call[] = [];
let items: ComplianceItem[];
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });

beforeEach(() => {
  calls.length = 0;
  items = [auto, manual];
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: typeof init.body === "string" ? JSON.parse(init.body) : init.body };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const path = url.split("?")[0] ?? url;
      if (path === "/api/v1/compliance" && method === "GET") return Promise.resolve(json(overview(items)));
      if (path === "/api/v1/compliance/base" && method === "GET") return Promise.resolve(json(baseView));
      if (path.endsWith("/mark") && method === "PUT") return Promise.resolve(json({ ...manual, status: "met", mark: { requirement_id: manual.id, status: "met", comment: "ok", set_at: "2026-10-28T10:00:00Z", set_by: "user:u-me" } }));
      if (path.endsWith("/mark") && method === "DELETE") return Promise.resolve(json(manual));
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
        <ComplianceScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const reader = ["compliance.read"];
const marker = ["compliance.read", "compliance.mark", "reports.read"];

describe("экран «Соответствие»", () => {
  it("показывает процент, статусы словами и таблицу требований", async () => {
    renderScreen(reader);
    const table = await screen.findByRole("table", { name: "Требования" });
    expect(within(table).getByText("Фильтрация входа и выхода")).toBeTruthy();
    expect(within(table).getByText("Частично")).toBeTruthy();
    expect(within(table).getByText("Нужна отметка")).toBeTruthy();
    expect(screen.getByText("25 %")).toBeTruthy();
    expect(screen.getByText(/версия 1 от 2026-10-28, встроенная/)).toBeTruthy();
  });

  it("раскрывает пункт: проверки словами и ссылки на доказательства внутри консоли", async () => {
    renderScreen(reader);
    fireEvent.click(await screen.findByRole("button", { name: /Показать подробности: Фильтрация входа и выхода/ }));
    const card = await screen.findByRole("region", { name: "Пункт п. 60" });
    expect(within(card).getByText(/5 из 7 приложений промышленной среды/)).toBeTruthy();
    const link = within(card).getByRole("link", { name: "События: отказы в доступе" });
    expect(link.getAttribute("href")).toBe("/events?f=type+%3D+auth_failure");
  });

  it("без права compliance.mark и reports.read нет кнопок отметки и отчёта", async () => {
    renderScreen(reader);
    fireEvent.click(await screen.findByRole("button", { name: /Показать подробности: Приказ о мерах защиты/ }));
    await screen.findByRole("region", { name: "Пункт ст. 19" });
    expect(screen.queryByRole("button", { name: "Поставить отметку" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Открыть отчёт" })).toBeNull();
    expect(screen.queryByText("Загрузить базу")).toBeNull();
  });

  it("ставит ручную отметку: комментарий обязателен, запрос уходит с телом", async () => {
    renderScreen(marker);
    expect(screen.getByRole("link", { name: "Открыть отчёт" }).getAttribute("href")).toBe("/api/v1/reports/compliance?format=html");
    fireEvent.click(await screen.findByRole("button", { name: /Показать подробности: Приказ о мерах защиты/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Поставить отметку" }));
    const save = await screen.findByRole("button", { name: "Сохранить отметку" });
    expect((save as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Комментарий"), { target: { value: "Приказ № 5 подписан" } });
    fireEvent.change(screen.getByLabelText("Документ-основание"), { target: { value: "Приказ № 5" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url.endsWith("/requirements/pdn.org.order/mark"))).toBe(true));
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toEqual({ status: "met", comment: "Приказ № 5 подписан", document: "Приказ № 5" });
  });

  it("у пункта с проверками можно выбрать только «Не применимо»", async () => {
    renderScreen(marker);
    fireEvent.click(await screen.findByRole("button", { name: /Показать подробности: Фильтрация входа и выхода/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Поставить отметку" }));
    const select = (await screen.findByLabelText("Состояние")) as HTMLSelectElement;
    expect([...select.options].map((o) => o.text)).toEqual(["Не применимо"]);
  });

  it("показывает отказ сервера в диалоге отметки", async () => {
    handler = (c) => (c.method === "PUT" ? problem(403, "forbidden", "Нет права на ручные отметки") : undefined);
    renderScreen(marker);
    fireEvent.click(await screen.findByRole("button", { name: /Показать подробности: Приказ о мерах защиты/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Поставить отметку" }));
    fireEvent.change(await screen.findByLabelText("Комментарий"), { target: { value: "ок" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить отметку" }));
    expect(await screen.findByText(/Нет права на ручные отметки/)).toBeTruthy();
  });

  it("пустой список — подсказка со сбросом фильтров; ошибка списка — баннер", async () => {
    items = [];
    renderScreen(reader);
    expect(await screen.findByText("По выбранным условиям пунктов нет")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("ошибка загрузки показывается баннером", async () => {
    handler = (c) => (c.url.startsWith("/api/v1/compliance?") || c.url === "/api/v1/compliance" ? problem(500, "internal", "Сбой сервера") : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/Внутренняя ошибка сервера/)).toBeTruthy();
  });

  it("предупреждает о недоступных группах сведений", async () => {
    handler = (c) => (c.url === "/api/v1/compliance" ? json({ ...overview(items), unavailable: ["audit_chain"] }) : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/Не удалось прочитать: цепочка журнала аудита/)).toBeTruthy();
  });

  it("вкладка базы: сведения и загрузка только с правом compliance.base.load", async () => {
    renderScreen([...reader, "compliance.base.load"]);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "База требований" }), { button: 0 });
    expect(await screen.findByText(/встроенная в сборку/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Загрузить базу" })).toBeTruthy();
  });
});
