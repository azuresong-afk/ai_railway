import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { PoliciesScreen } from "./PoliciesScreen";

const me = (permissions: string[]): Me => ({
  user: { id: "u-me", login: "boss", display_name: "Босс", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
});

const rule = { id: "pii-ru", detector: "pii.ru", action: "redact", severity: "high" };
const spec = { name: "Моя политика", mode: "enforce", non_text: "allow_inline", response_check: "incremental", rules: [rule] };
const summaries = [
  { id: "base", name: "Базовая защита", mode: "enforce", template: true },
  { id: "mine", name: "Моя политика", mode: "enforce", template: false, current_version: 2, updated_at: "2026-10-02T10:00:00Z" },
];
const versions = [
  { version: 2, hash: "bb", hash_alg: "sha256", source: "api", comment: "строже", created_at: "2026-10-02T10:00:00Z", created_by: "boss" },
  { version: 1, hash: "aa", hash_alg: "sha256", source: "template", comment: "", created_at: "2026-10-01T10:00:00Z", created_by: "boss" },
];
const diff = {
  from: 2, to: 1, fields: [{ field: "mode", before: "enforce", after: "monitor" }], rules_added: [], rules_removed: [rule], rules_changed: [],
  reordered: false, weakening: true, weakening_reasons: [{ kind: "rule_removed", rule: "pii-ru" }],
  exceptions_added: [], exceptions_removed: [], exceptions_changed: [],
};

const calls: { method: string; url: string; body: unknown }[] = [];
let testStatus = 200;

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  testStatus = 200;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url === "/api/v1/policies") return json({ items: summaries });
      if (url === "/api/v1/policies/mine") return json({ ...summaries[1], spec });
      if (url === "/api/v1/policies/base") return json({ ...summaries[0], spec });
      if (url === "/api/v1/policies/mine/versions") return json({ items: versions });
      if (url.startsWith("/api/v1/policies/mine/diff")) return json(diff);
      if (url === "/api/v1/policies/mine/rollback") return json({ ...summaries[1], current_version: 3, spec }, 200);
      if (url === "/api/v1/policies/test") {
        return testStatus === 200
          ? json({ policy_id: "mine", draft: false, direction: "input", mode: "enforce", decision: "redact", action: "redact", blocked: false, fail_block: false, incomplete: false, unchecked: false, failures: [], findings: [{ detector: "pii.ru", category: "pii.phone", score: 0.9, start: 0, end: 5, location: "text", rule: "pii-ru", action: "redact", apply: "redact" }], texts: [{ location: "text", text: "Позвоните <PHONE>", changed: true }] })
          : json({ code: "unprocessable", detail: "Категория lists.vip: словаря нет у приложения.", status: 422 }, 422);
      }
      if (url.startsWith("/api/v1/applications?")) return json({ items: [] });
      return json({ code: "not_found", detail: "нет", status: 404 }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PoliciesScreen me={me(permissions)} />
    </QueryClientProvider>,
  );

describe("экран «Политики»", () => {
  it("без права управления нет кнопок создания, загрузки и отката", async () => {
    renderScreen(["policies.read"]);
    await screen.findByText("Моя политика");
    expect(screen.queryByRole("button", { name: "Создать политику" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Загрузить YAML" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Версии" }), { button: 0 });
    await screen.findByText("строже");
    expect(screen.queryByRole("button", { name: /Откатить к версии/ })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Песочница" })).toBeNull();
  });

  it("у шаблона нет версий и отката", async () => {
    renderScreen(["policies.read", "policies.manage"]);
    await screen.findByText("Базовая защита");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Базовая защита" }));
    await screen.findByText(/Шаблон меняться не может/);
    expect(screen.queryByRole("tab", { name: "Версии" })).toBeNull();
  });

  it("откат показывает различия с признаком ослабления и идёт через подтверждение", async () => {
    renderScreen(["policies.read", "policies.manage"]);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Версии" }), { button: 0 });
    fireEvent.click(await screen.findByRole("button", { name: "Откатить к версии 1" }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByText(/Изменение ослабляет защиту/);
    expect(calls.some((c) => c.url.endsWith("/rollback"))).toBe(false);
    fireEvent.click(within(dlg).getByRole("button", { name: "Откатить к версии 1" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/rollback"))?.body).toEqual({ version: 1, base_version: 2 }));
  });

  it("сравнение версий выводит различия", async () => {
    renderScreen(["policies.read"]);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Версии" }), { button: 0 });
    fireEvent.click(await screen.findByRole("button", { name: "Сравнить версию 2 с предыдущей" }));
    await screen.findByRole("region", { name: "Различия версий 2 и 1" });
    expect(screen.getByText("Удалены правила")).toBeInTheDocument();
  });

  it("песочница: результат с текстом после защиты", async () => {
    renderScreen(["policies.read", "policies.test"]);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Песочница" }), { button: 0 });
    fireEvent.change(await screen.findByLabelText("Проверяемый текст"), { target: { value: "Позвоните +7 900 000-00-00" } });
    fireEvent.click(screen.getByRole("button", { name: "Проверить текст" }));
    await screen.findByRole("region", { name: "Результат проверки" });
    expect(screen.getByText("Позвоните <PHONE>")).toBeInTheDocument();
    expect(calls.find((c) => c.url === "/api/v1/policies/test")?.body).toEqual({ policy_id: "mine", request: { direction: "input", text: "Позвоните +7 900 000-00-00" } });
  });

  it("песочница: 422 из-за словаря объясняется подсказкой со ссылкой на приложения", async () => {
    testStatus = 422;
    renderScreen(["policies.read", "policies.test"]);
    await screen.findByText("Моя политика");
    fireEvent.click(screen.getByRole("button", { name: "Открыть политику Моя политика" }));
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Песочница" }), { button: 0 });
    fireEvent.change(await screen.findByLabelText("Проверяемый текст"), { target: { value: "текст" } });
    fireEvent.click(screen.getByRole("button", { name: "Проверить текст" }));
    const hint = await screen.findByText(/словаря нет у приложения/);
    expect(hint.closest("div")?.textContent).toContain("разделе «Приложения»");
    expect(screen.getByRole("link", { name: "разделе «Приложения»" })).toHaveAttribute("href", "#/apps");
  });
});
