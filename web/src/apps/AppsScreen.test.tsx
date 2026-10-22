import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AppsScreen } from "./AppsScreen";
import { gatewayExample, slugPattern, splitList, suggestSlug } from "./api";

const me = (permissions: string[]): Me => ({
  user: { id: "u-me", login: "owner", display_name: "Владелец", role: "app_owner", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
});

const app = {
  id: "a-1", slug: "support-bot", name: "Бот поддержки", description: "", department: "", owner_id: "u-me", env: "prod", provider_id: "p-1",
  models: ["gpt-4o"], aliases: {}, policy: "base", policy_mode: "enforce", storage: "masked", fail_mode: "fail_closed", user_from: "none",
  quotas: {}, lists: [], exfil_allow_domains: [], status: "active", created_at: "2026-10-01T10:00:00Z", updated_at: "2026-10-01T10:00:00Z",
};
const key = { id: "k-1", application_id: "a-1", name: "основной", prefix: "aisec_abcd1234", status: "active", allowed_cidrs: [], expires_at: "2027-10-01T00:00:00Z", created_at: "2026-10-01T10:00:00Z" };
const SECRET = "aisec_abcd1234_SECRETSECRETSECRETSECRETSECRETSECRETSECRET1";

const calls: { method: string; url: string; body: unknown }[] = [];

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url.startsWith("/api/v1/applications?")) return json({ items: [app] });
      if (url === "/api/v1/applications" && method === "POST") return json({ ...app, id: "a-2", slug: body.slug, name: body.name }, 201);
      if (url === "/api/v1/applications/a-1/keys" && method === "GET") return json({ items: [key] });
      if (url.endsWith("/keys") && method === "POST") return json({ app_key: key, key: SECRET }, 201);
      if (url === "/api/v1/app-keys/k-1/revoke") return json({ ...key, status: "revoked" });
      if (url === "/api/v1/app-keys/k-1/rotate") return json({ app_key: key, key: SECRET, previous: key }, 201);
      if (url === "/api/v1/providers") return json({ items: [{ id: "p-1", slug: "main", name: "Основной", type: "openai", base_url: "/llm", ca_pem: "", timeouts: {}, external: true, credential_set: true, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" }] });
      if (url === "/api/v1/policies") return json({ items: [{ id: "base", name: "Базовая защита", mode: "enforce", template: true }] });
      return json({ code: "not_found", detail: "нет", status: 404 }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AppsScreen me={me(permissions)} />
    </QueryClientProvider>,
  );

describe("экран «Приложения»", () => {
  it("владелец с правом только на чтение: список есть, кнопок управления нет", async () => {
    renderScreen(["applications.read"]);
    await screen.findByText("Бот поддержки");
    expect(screen.queryByRole("button", { name: "Подключить приложение" })).toBeNull();
    expect(screen.queryByRole("button", { name: /В архив/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Ключи приложения Бот поддержки" }));
    await screen.findByText("aisec_abcd1234");
    expect(screen.queryByRole("button", { name: /Отозвать ключ/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Выпустить ключ" })).toBeNull();
  });

  it("отзыв ключа требует подтверждения в диалоге", async () => {
    renderScreen(["applications.read", "app_keys.manage"]);
    await screen.findByText("Бот поддержки");
    fireEvent.click(screen.getByRole("button", { name: "Ключи приложения Бот поддержки" }));
    fireEvent.click(await screen.findByRole("button", { name: "Отозвать ключ основной" }));
    expect(calls.some((c) => c.url.endsWith("/revoke"))).toBe(false);
    const dlg = await screen.findByRole("alertdialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Отозвать ключ" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/v1/app-keys/k-1/revoke" && c.method === "POST")).toBe(true));
  });

  it("ротация показывает новый ключ один раз и стирает его при закрытии", async () => {
    renderScreen(["applications.read", "app_keys.manage"]);
    await screen.findByText("Бот поддержки");
    fireEvent.click(screen.getByRole("button", { name: "Ключи приложения Бот поддержки" }));
    fireEvent.click(await screen.findByRole("button", { name: "Заменить ключ основной" }));
    fireEvent.click(await screen.findByRole("button", { name: "Выпустить новый ключ" }));
    const shown = (await screen.findByLabelText("Ключ приложения")) as HTMLInputElement;
    expect(shown.value).toBe(SECRET);
    expect(calls.find((c) => c.url.endsWith("/rotate"))?.body).toEqual({ overlap_hours: 24, expires_in_days: 365 });
    fireEvent.click(screen.getByRole("button", { name: "Я сохранил ключ" }));
    await waitFor(() => expect(screen.queryByLabelText("Ключ приложения")).toBeNull());
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("мастер: создаёт приложение и ключ, ключ виден один раз, пример без ключа", async () => {
    renderScreen(["applications.read", "applications.manage", "app_keys.manage"]);
    await screen.findByText("Бот поддержки");
    fireEvent.click(screen.getByRole("button", { name: "Подключить приложение" }));
    const name = await screen.findByLabelText("Название");
    fireEvent.change(name, { target: { value: "Помощник HR" } });
    expect((screen.getByLabelText("ID приложения") as HTMLInputElement).value).toBe("pomoshchnik-hr");
    fireEvent.click(screen.getByRole("button", { name: "Далее: провайдер и политика" }));
    await screen.findByRole("option", { name: "Основной (внешний)" });
    fireEvent.change(screen.getByLabelText("Провайдер"), { target: { value: "p-1" } });
    fireEvent.change(screen.getByLabelText("Разрешённые модели"), { target: { value: "gpt-4o, gpt-4o-mini" } });
    // Без права applications.policy полей защиты нет.
    expect(screen.queryByLabelText("Политика")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Далее: ключ" }));
    fireEvent.click(await screen.findByRole("button", { name: "Создать приложение и выпустить ключ" }));
    const shown = (await screen.findByLabelText("Ключ приложения")) as HTMLInputElement;
    expect(shown.value).toBe(SECRET);
    const create = calls.find((c) => c.url === "/api/v1/applications" && c.method === "POST");
    expect(create?.body).toEqual({ slug: "pomoshchnik-hr", name: "Помощник HR", env: "prod", provider_id: "p-1", models: ["gpt-4o", "gpt-4o-mini"], user_from: "none" });
    const example = screen.getByRole("region", { name: "Пример запроса" });
    expect(example.textContent).toContain("$AISEC_KEY");
    expect(example.textContent).toContain("gpt-4o");
    expect(example.textContent).not.toContain(SECRET);
    fireEvent.click(screen.getByRole("button", { name: "Я сохранил ключ" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("мастер: при праве политики отправляет поля защиты", async () => {
    renderScreen(["applications.read", "applications.manage", "applications.policy"]);
    await screen.findByText("Бот поддержки");
    fireEvent.click(screen.getByRole("button", { name: "Подключить приложение" }));
    fireEvent.change(await screen.findByLabelText("Название"), { target: { value: "Тест" } });
    fireEvent.click(screen.getByRole("button", { name: "Далее: провайдер и политика" }));
    await screen.findByRole("option", { name: "Основной (внешний)" });
    fireEvent.change(screen.getByLabelText("Провайдер"), { target: { value: "p-1" } });
    fireEvent.change(screen.getByLabelText("Разрешённые модели"), { target: { value: "m1" } });
    await screen.findByRole("option", { name: "Базовая защита (шаблон)" });
    fireEvent.change(screen.getByLabelText("Политика"), { target: { value: "base" } });
    fireEvent.change(screen.getByLabelText("Режим политики"), { target: { value: "monitor" } });
    fireEvent.click(screen.getByRole("button", { name: "Далее: ключ" }));
    fireEvent.click(await screen.findByRole("button", { name: "Создать приложение" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/v1/applications" && c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.url === "/api/v1/applications" && c.method === "POST")?.body).toMatchObject({ policy: "base", policy_mode: "monitor" });
    // Права на ключи нет: ключ не выпускался.
    expect(calls.some((c) => c.url.endsWith("/keys") && c.method === "POST")).toBe(false);
  });
});

describe("помощники мастера", () => {
  it("ID из названия подходит под шаблон сервера", () => {
    for (const n of ["Бот поддержки", "  Щука & Ёж! ", "A--B", "Привет, мир 2"]) expect(slugPattern.test(suggestSlug(n))).toBe(true);
    expect(suggestSlug("Щука")).toBe("shchuka");
  });
  it("splitList делит по пробелам и запятым и убирает повторы", () => {
    expect(splitList("a, b\nc  a;d")).toEqual(["a", "b", "c", "d"]);
    expect(splitList(" ")).toEqual([]);
  });
  it("пример запроса не содержит ключа и экранирует модель в JSON", () => {
    const ex = gatewayExample('m"1');
    expect(ex).toContain("$AISEC_KEY");
    expect(ex).toContain('"model":"m\\"1"');
  });
});
