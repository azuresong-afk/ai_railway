import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { PolicyRule, PolicySpec } from "./api";
import { localDiff } from "./localDiff";
import { PoliciesScreen } from "./PoliciesScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "boss", display_name: "Босс", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

const rule: PolicyRule = { id: "pii-ru", detector: "pii.ru", action: "redact", severity: "high", threshold: 0.8 };
const injection: PolicyRule = { id: "inj", detector: "injection.rules", action: "block", severity: "critical" };
const spec = { name: "Моя политика", mode: "enforce", non_text: "allow_inline", response_check: "incremental", rules: [rule, injection] } as PolicySpec;
const mine = { id: "mine", name: "Моя политика", mode: "enforce", template: false, current_version: 2, updated_at: "2026-10-02T10:00:00Z" };
const exc = (o: Record<string, unknown>) => ({ id: "exc-1", detector: "pii.snils", pattern: "snils-rule", app: "crm-bot", reason: "тестовые данные", author: "boss", expires_at: "2026-11-20T10:00:00Z", status: "active", event_id: "ev-1", ...o });

type Call = { method: string; url: string; body: ReturnType<typeof JSON.parse> };
const calls: Call[] = [];
let exceptions: unknown[];
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, detail: string, errors?: unknown) => json({ status, code, detail, ...(errors ? { errors } : {}) }, status);

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  handler = () => undefined;
  exceptions = [exc({}), exc({ id: "exc-2", pattern: undefined, fragment: "0123456789abcdef", expires_at: "2026-10-01T10:00:00Z", status: "expired", event_id: undefined })];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const c: Call = { method: init.method ?? "GET", url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const r = (x: Response) => Promise.resolve(x);
      if (url === "/api/v1/policies") return r(json({ items: [mine] }));
      if (url === "/api/v1/policies/mine" && c.method === "GET") return r(json({ ...mine, spec }));
      if (url === "/api/v1/policies/mine" && c.method === "PUT") return r(json({ ...mine, current_version: 3, spec: c.body.spec }));
      if (url === "/api/v1/policies/mine/versions") return r(json({ items: [] }));
      if (url === "/api/v1/policies/mine/exceptions") return r(json({ policy: "mine", version: 2, items: exceptions }));
      if (url === "/api/v1/policies/mine/exceptions/exc-1/extend") return r(json({ policy: { ...mine, current_version: 3, spec } }));
      if (url.startsWith("/api/v1/policies/mine/exceptions/exc-2?")) return r(json({ policy: { ...mine, current_version: 3, spec } }));
      if (url === "/api/v1/policies/import") return r(json({ ...mine, current_version: 3, spec }));
      return r(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <PoliciesScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const openTab = async (name: string) => {
  await screen.findByText("Моя политика");
  fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
  fireEvent.mouseDown(await screen.findByRole("tab", { name }), { button: 0 });
};
const manage = ["policies.read", "policies.manage", "events.read"];

describe("экран исключений политики", () => {
  it("действующие и истёкшие — отдельными таблицами", async () => {
    renderScreen(manage);
    await openTab("Исключения");
    const active = await screen.findByRole("region", { name: "Действующие исключения" });
    const expired = screen.getByRole("region", { name: "Истёкшие исключения" });
    expect(within(active).getByText(/правило snils-rule; приложение crm-bot/)).toBeInTheDocument();
    expect(within(active).getByRole("link", { name: "Открыть" }).getAttribute("href")).toContain("event=ev-1");
    expect(within(expired).getByText(/фрагмент …89abcdef/)).toBeInTheDocument();
    expect(within(expired).queryByText(/snils-rule/)).toBeNull();
  });

  it("без policies.manage кнопок продления и удаления нет", async () => {
    renderScreen(["policies.read"]);
    await openTab("Исключения");
    await screen.findByRole("region", { name: "Действующие исключения" });
    expect(screen.queryByRole("button", { name: /Продлить исключение/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Удалить исключение/ })).toBeNull();
    expect(screen.queryByRole("link", { name: "Открыть" })).toBeNull(); // нет events.read
  });

  it("продление требует пароль и шлёт base_version и срок", async () => {
    renderScreen(manage);
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Продлить исключение exc-1" }));
    const dlg = await screen.findByRole("dialog");
    const submit = within(dlg).getByRole("button", { name: "Продлить исключение" });
    expect(submit).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Срок, суток"), { target: { value: "60" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/extend"))?.body).toEqual({ base_version: 2, expires_in_days: 60, password: "Correct-Horse-1" }));
  });

  it("продление: срок больше 365 не принимается, отказ 403 показывается", async () => {
    handler = (c) => (c.url.endsWith("/extend") ? problem(403, "reauthentication_failed", "Неверный пароль.") : undefined);
    renderScreen(manage);
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Продлить исключение exc-1" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Срок, суток"), { target: { value: "366" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "x" } });
    expect(within(dlg).getByRole("button", { name: "Продлить исключение" })).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Срок, суток"), { target: { value: "365" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Продлить исключение" }));
    await within(dlg).findByText(/Неверный пароль/);
  });

  it("удаление не просит пароль и шлёт base_version запросом", async () => {
    renderScreen(manage);
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Удалить исключение exc-2" }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).queryByLabelText("Текущий пароль")).toBeNull();
    fireEvent.change(within(dlg).getByLabelText("Комментарий (необязательно)"), { target: { value: "истёк" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Удалить исключение" }));
    await waitFor(() => expect(calls.find((c) => c.method === "DELETE")?.url).toContain("base_version=2"));
    expect(calls.find((c) => c.method === "DELETE")?.url).toContain("comment=%D0%B8%D1%81%D1%82%D1%91%D0%BA");
  });

  it("пусто и ошибка загрузки", async () => {
    exceptions = [];
    const { unmount } = renderScreen(manage);
    await openTab("Исключения");
    await screen.findByText(/Исключений нет/);
    unmount();
    handler = (c) => (c.url.endsWith("/exceptions") ? problem(500, "internal", "x") : undefined);
    renderScreen(manage);
    await openTab("Исключения");
    await screen.findByText(/Внутренняя ошибка сервера/);
  });
});

describe("редактор правил (Н46)", () => {
  it("вкладка только с policies.manage", async () => {
    renderScreen(["policies.read"]);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    await screen.findByRole("tab", { name: "Исключения" });
    expect(screen.queryByRole("tab", { name: "Редактор правил" })).toBeNull();
  });

  it("до отправки показывает различия и пометку ослабления; сохранение — PUT с base_version", async () => {
    renderScreen(manage);
    await openTab("Редактор правил");
    await screen.findByText("Изменений нет.");
    const save = screen.getByRole("button", { name: "Сохранить новую версию" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Действие правила inj"), { target: { value: "log" } });
    const diff = await screen.findByRole("region", { name: "Различия с текущей версией" });
    expect(diff).toHaveTextContent(/Изменение ослабляет защиту: действие правила смягчено \(inj\)/);
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ base_version: 2, spec: { rules: [rule, { ...injection, action: "log" }] } }));
    // Исключения версии редактор не отправляет — сервер сохраняет их сам.
    expect(calls.find((c) => c.method === "PUT")?.body.spec).not.toHaveProperty("exceptions");
  });

  it("сервер просит подтверждение: пароль запрашивается, затем уходит в теле", async () => {
    let first = true;
    handler = (c) => {
      if (c.method === "PUT" && first) {
        first = false;
        return problem(400, "invalid_request", "Проверьте введённые данные.", [{ field: "password", detail: "Введите текущий пароль." }]);
      }
      return undefined;
    };
    renderScreen(manage);
    await openTab("Редактор правил");
    fireEvent.click(await screen.findByRole("button", { name: "Убрать правило inj" }));
    await screen.findByText(/правило удалено \(inj\)/);
    fireEvent.click(screen.getByRole("button", { name: "Сохранить новую версию" }));
    const pass = await screen.findByLabelText("Текущий пароль");
    fireEvent.change(pass, { target: { value: "Correct-Horse-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить новую версию" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT").at(-1)?.body.password).toBe("Correct-Horse-1"));
  });

  it("неверный порог блокирует сохранение", async () => {
    renderScreen(manage);
    await openTab("Редактор правил");
    fireEvent.change(await screen.findByLabelText("Порог правила pii-ru"), { target: { value: "1,5" } });
    expect(screen.getByText("Число больше 0 и не больше 1.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeDisabled();
  });

  it("новое правило: ID проверяется, правило попадает в различия", async () => {
    renderScreen(manage);
    await openTab("Редактор правил");
    fireEvent.change(await screen.findByLabelText("ID правила"), { target: { value: "Bad_ID" } });
    expect(screen.getByRole("button", { name: "Добавить правило" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("ID правила"), { target: { value: "new-rule" } });
    fireEvent.change(screen.getByLabelText("Детектор"), { target: { value: "pii.cards" } });
    fireEvent.click(screen.getByRole("button", { name: "Добавить правило" }));
    expect(await screen.findByText("Добавлены правила")).toBeInTheDocument();
  });
});

describe("загрузка YAML: различия до отправки (Н46, задача 3.35)", () => {
  const openImport = async () => {
    renderScreen(manage);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.click(await screen.findByRole("button", { name: "Загрузить новую версию из YAML" }));
    return screen.findByRole("dialog");
  };
  const emptyDiff = { from: 2, to: 3, fields: [], rules_added: [], rules_removed: [], rules_changed: [], reordered: false, weakening: false,
    weakening_reasons: [], exceptions_added: [], exceptions_removed: [], exceptions_changed: [] };

  it("любой YAML: различия и ослабление считает сервер без сохранения", async () => {
    handler = (c) =>
      c.url === "/api/v1/policies/import?dry_run=true"
        ? json({ dry_run: true, policy: "mine", created: false, current_version: 2,
            diff: { ...emptyDiff, fields: [{ field: "mode", before: "enforce", after: "monitor" }], weakening: true, weakening_reasons: [{ kind: "mode_monitor" }] } })
        : undefined;
    const dlg = await openImport();
    const yaml = "id: mine\nname: Моя политика\nversion: 2\nmode: monitor\nrules: []\n";
    fireEvent.change(within(dlg).getByLabelText("Или вставьте текст"), { target: { value: yaml } });
    const diff = await within(dlg).findByRole("region", { name: "Различия с текущей версией" });
    expect(diff).toHaveTextContent(/политика переведена в режим мониторинга/);
    expect(diff).toHaveTextContent(/понадобится пароль или код/);
    const dry = calls.filter((c) => c.url === "/api/v1/policies/import?dry_run=true");
    expect(dry.at(-1)?.body).toEqual({ document: yaml, base_version: 2 });
    // Проверка ничего не загружает: запроса без dry_run нет.
    expect(calls.some((c) => c.url === "/api/v1/policies/import")).toBe(false);
  });

  it("ошибка разбора видна до отправки, документ другой политики — предупреждение", async () => {
    let bad = true;
    handler = (c) => {
      if (c.url !== "/api/v1/policies/import?dry_run=true") return undefined;
      return bad
        ? problem(400, "invalid_request", "Файл политики не прошёл проверку: неизвестное поле extra.")
        : json({ dry_run: true, policy: "other", created: false, current_version: 5, diff: emptyDiff });
    };
    const dlg = await openImport();
    fireEvent.change(within(dlg).getByLabelText("Или вставьте текст"), { target: { value: "id: mine\nextra: 1\n" } });
    expect(await within(dlg).findByText(/неизвестное поле extra/)).toBeInTheDocument();
    bad = false;
    fireEvent.change(within(dlg).getByLabelText("Или вставьте текст"), { target: { value: "id: other\nname: x\n" } });
    expect(await within(dlg).findByText(/Документ относится к другой политике: «other»/)).toBeInTheDocument();
  });
});

describe("сравнение в браузере", () => {
  const base = spec;
  it("одинаковые содержимые — различий нет", () => {
    const d = localDiff(base, JSON.parse(JSON.stringify(base)) as PolicySpec);
    expect(d.weakening).toBe(false);
    expect(d.rules_changed).toEqual([]);
    expect(d.reordered).toBe(false);
  });
  it("причины ослабления: режим, удаление, действие, порог, детектор", () => {
    const after: PolicySpec = {
      ...base, mode: "monitor",
      rules: [{ ...rule, threshold: 0.95, detector: "pii.other" }, { ...injection, action: "allow" }],
    };
    const kinds = localDiff(base, after).weakening_reasons.map((r) => r.kind);
    expect(kinds).toEqual(expect.arrayContaining(["mode_monitor", "threshold_raised", "detector_changed", "action_weakened"]));
    expect(localDiff(base, { ...base, rules: [rule] }).weakening_reasons).toEqual([{ kind: "rule_removed", rule: "inj" }]);
  });
  it("усиление защиты не помечается", () => {
    const d = localDiff({ ...base, mode: "monitor" }, { ...base, rules: [rule, { ...injection }, { id: "new", detector: "x", action: "block", severity: "low" }] });
    expect(d.weakening).toBe(false);
    expect(d.rules_added).toHaveLength(1);
  });
  it("порядок правил", () => {
    expect(localDiff(base, { ...base, rules: [injection, rule] }).reordered).toBe(true);
  });
});
