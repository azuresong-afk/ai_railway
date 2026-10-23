import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventCard } from "./EventCard";
import { fields, parseFilter, buildFilter } from "./filter";

const ev = {
  id: "0190f3a2-0000-7000-8000-000000000001", time: "2026-10-21T12:00:00Z", received_at: "2026-10-21T12:00:01Z",
  gateway_id: "0190f3a2-0000-7000-8000-0000000000aa", type: "gateway_request", app: "crm-bot", storage: "none", threats: ["DM-01"],
  stream: false, non_text_unchecked: false, has_content: false, details: {},
} as Record<string, unknown>;

type Call = { method: string; url: string; body: unknown };
const calls: Call[] = [];
let event: Record<string, unknown>;
let draft: Record<string, unknown>;
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, detail: string) => json({ status, code, detail }, status);

const baseDraft = {
  event_id: ev.id, policy: "mine", policy_version: 2, base_version: 2, template: false,
  items: [
    { detector: "pii.snils", category: "pii.snils", pattern: "snils-rule", fragment: "abcdef0123456789", app: "crm-bot", expires_in_days: 30 },
    { detector: "pii.phone", category: "pii.phone", pattern: "phone-rule", app: "crm-bot" },
  ],
};

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  event = { ...ev };
  draft = baseDraft;
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const c: Call = { method: init.method ?? "GET", url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      if (url.endsWith("/mark")) return Promise.resolve(c.body && (c.body as { mark: string }).mark === "none" ? new Response(null, { status: 204 }) : json({ event_id: ev.id, mark: { mark: "false_positive", marked_at: "2026-10-22T10:00:00Z", marked_by: "user:u1" } }));
      if (url.endsWith("/exception-draft")) return Promise.resolve(json(draft));
      if (url.endsWith("/policies/mine/exceptions")) return Promise.resolve(json({ policy: { id: "mine", name: "Моя политика", mode: "enforce", template: false, current_version: 3, spec: {} } }));
      return Promise.resolve(json(event));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderCard = (rights: { canMark?: boolean; canException?: boolean; mfa?: boolean }) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <EventCard id={ev.id as string} canReadContent={false} rights={rights} onClose={() => {}} />
    </QueryClientProvider>,
  );

describe("отметка и исключение в карточке события", () => {
  it("без прав кнопок нет", async () => {
    renderCard({});
    await screen.findByRole("heading", { name: "Почему принято решение" });
    for (const n of ["Ложное срабатывание", "Подтверждено", "Создать исключение"]) expect(screen.queryByRole("button", { name: n })).toBeNull();
  });

  it("«Ложное срабатывание» с комментарием отправляет PUT /mark", async () => {
    renderCard({ canMark: true });
    fireEvent.click(await screen.findByRole("button", { name: "Ложное срабатывание" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Комментарий"), { target: { value: "тестовый СНИЛС" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Поставить отметку" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mark: "false_positive", comment: "тестовый СНИЛС" }));
    expect(calls.find((c) => c.method === "PUT")?.url).toBe(`/api/v1/events/${ev.id}/mark`);
  });

  it("поставленная отметка видна, ее можно снять", async () => {
    event = { ...ev, mark: { mark: "confirmed", comment: "реальная утечка", marked_at: "2026-10-22T10:00:00Z", marked_by: "user:u1", marked_by_name: "Аналитик" } };
    renderCard({ canMark: true });
    await screen.findByText(/Подтверждено: .*Аналитик/);
    expect(screen.getByText("реальная утечка")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Снять отметку" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mark: "none" }));
  });

  it("отказ сервера на отметку (403) показывается в окне", async () => {
    handler = (c) => (c.url.endsWith("/mark") ? problem(403, "forbidden", "Недостаточно прав.") : undefined);
    renderCard({ canMark: true });
    fireEvent.click(await screen.findByRole("button", { name: "Подтверждено" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Поставить отметку" }));
    await within(dlg).findByText(/Сервер отказал в действии. Недостаточно прав./);
  });

  it("исключение: выбор условий, срок, пароль → POST с base_version и event_id", async () => {
    renderCard({ canException: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog", { name: "Создать исключение" });
    await within(dlg).findByText("Условия исключения (соединяются «и»)");
    const submit = within(dlg).getByRole("button", { name: "Добавить исключение" });
    expect(submit).toBeDisabled(); // нет пароля
    // Снимаем фрагмент и категорию: остаются правило и приложение.
    fireEvent.click(within(dlg).getByRole("checkbox", { name: /Фрагмент текста/ }));
    fireEvent.click(within(dlg).getByRole("checkbox", { name: /Категория находки/ }));
    fireEvent.change(within(dlg).getByLabelText("Срок, суток"), { target: { value: "14" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      detector: "pii.snils", pattern: "snils-rule", app: "crm-bot", reason: "Ложное срабатывание", expires_in_days: 14, event_id: ev.id, base_version: 2, password: "Correct-Horse-1",
    }));
    await within(dlg).findByText(/версия 3 политики «Моя политика»/);
  });

  it("с подключённым TOTP вместо пароля отправляется код", async () => {
    renderCard({ canException: true, mfa: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(await within(dlg).findByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Добавить исключение" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ code: "123456" }));
    expect(calls.find((c) => c.method === "POST")?.body).not.toHaveProperty("password");
  });

  it("без условий, ограничивающих область, отправка заблокирована", async () => {
    renderCard({ canException: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog");
    for (const n of [/Правило детектора/, /Фрагмент текста/, /Приложение/]) fireEvent.click(await within(dlg).findByRole("checkbox", { name: n }));
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "x" } });
    await within(dlg).findByText(/Оставьте хотя бы одно из условий/);
    expect(within(dlg).getByRole("button", { name: "Добавить исключение" })).toBeDisabled();
  });

  it("срок вне 1–365 не принимается", async () => {
    renderCard({ canException: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(await within(dlg).findByLabelText("Срок, суток"), { target: { value: "400" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "x" } });
    expect(within(dlg).getByText("Введите целое число от 1 до 365.")).toBeInTheDocument();
    expect(within(dlg).getByRole("button", { name: "Добавить исключение" })).toBeDisabled();
  });

  it("политика события — шаблон: добавить исключение нельзя", async () => {
    draft = { ...baseDraft, template: true };
    renderCard({ canException: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByText(/шаблон менять нельзя/);
    expect(within(dlg).getByRole("button", { name: "Добавить исключение" })).toBeDisabled();
  });

  it("отказ сервера (403) при добавлении выводится в окне, пароль стирается", async () => {
    handler = (c) => (c.method === "POST" ? problem(403, "reauthentication_failed", "Неверный пароль.") : undefined);
    renderCard({ canException: true });
    fireEvent.click(await screen.findByRole("button", { name: "Создать исключение" }));
    const dlg = await screen.findByRole("dialog");
    const pass = await within(dlg).findByLabelText("Текущий пароль");
    fireEvent.change(pass, { target: { value: "bad" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Добавить исключение" }));
    await within(dlg).findByText(/Неверный пароль/);
    expect(pass).toHaveValue("");
  });
});

describe("фильтры «отметка» и «исключение»", () => {
  it("поля есть в языке фильтра и разбираются в чипы", () => {
    expect(fields.map((f) => f.id)).toEqual(expect.arrayContaining(["mark", "exception"]));
    const chips = parseFilter('mark = "false_positive" and exception = "exc-1"');
    expect(chips).toEqual([
      { field: "mark", negate: false, values: ["false_positive"] },
      { field: "exception", negate: false, values: ["exc-1"] },
    ]);
    expect(buildFilter(chips!)).toBe('mark = "false_positive" and exception = "exc-1"');
  });
});
