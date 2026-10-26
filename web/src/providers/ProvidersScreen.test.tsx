import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { type Provider } from "./api";
import { ProvidersScreen } from "./ProvidersScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

const PEM = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----";
const provider = (o: Partial<Provider> = {}): Provider => ({
  id: "p-1", slug: "main", name: "Основной", type: "openai", base_url: `https://llm.corp.example/v1`, ca_pem: PEM, timeouts: {},
  external: false, credential_set: true, credential_set_at: "2026-10-01T10:00:00Z", created_at: "2026-10-01T10:00:00Z", updated_at: "2026-10-01T10:00:00Z", ...o,
});
const ASCII_KEY = "sk-test-0123456789";

type JsonBody = ReturnType<typeof JSON.parse>;
type Call = { method: string; url: string; body: JsonBody };
const calls: Call[] = [];
let list: Provider[];
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, detail: string) => new Response(JSON.stringify({ status, code, detail }), { status });

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  list = [provider()];
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      if (url === "/api/v1/providers" && method === "GET") return Promise.resolve(json({ items: list }));
      if (url === "/api/v1/providers" && method === "POST") return Promise.resolve(json(provider({ id: "p-2", slug: c.body.slug, name: c.body.name, external: true, credential_set: false }), 201));
      if (url === "/api/v1/providers/p-1/credentials") return Promise.resolve(json(provider()));
      if (url === "/api/v1/providers/p-1/external") return Promise.resolve(json(provider({ external: c.body.external })));
      if (url === "/api/v1/providers/p-1" && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProvidersScreen me={me(permissions, mfa)} />
    </QueryClientProvider>,
  );
const all = ["providers.read", "providers.manage", "providers.external"];

describe("экран «Провайдеры»", () => {
  it("читатель видит список, но не кнопки управления", async () => {
    renderScreen(["providers.read"]);
    await screen.findByText("Основной");
    expect(screen.getByText(/Заданы \(/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Создать провайдера" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Учётные данные/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Признак «внешний»/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Удалить/ })).toBeNull();
  });

  it("администратор без providers.external не видит кнопки признака", async () => {
    renderScreen(["providers.read", "providers.manage"]);
    await screen.findByText("Основной");
    expect(screen.getByRole("button", { name: "Учётные данные Основной" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Признак «внешний»/ })).toBeNull();
  });

  it("создание провайдера: ID из названия, адрес только https, отправка", async () => {
    renderScreen(all);
    fireEvent.click(await screen.findByRole("button", { name: "Создать провайдера" }));
    const dlg = await screen.findByRole("dialog", { name: "Новый провайдер" });
    const create = within(dlg).getByRole("button", { name: "Создать провайдера" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Название"), { target: { value: "Локальная модель" } });
    expect((within(dlg).getByLabelText("ID провайдера") as HTMLInputElement).value).toBe("lokalnaya-model");
    fireEvent.change(within(dlg).getByLabelText("Адрес API"), { target: { value: `http://plain.example/v1` } });
    fireEvent.change(within(dlg).getByLabelText(/Корневые сертификаты/), { target: { value: PEM } });
    expect(create.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Адрес API"), { target: { value: `https://llm.corp.example/v1` } });
    expect(create.disabled).toBe(false);
    fireEvent.click(create);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({
      slug: "lokalnaya-model", name: "Локальная модель", type: "openai", base_url: `https://llm.corp.example/v1`, ca_pem: PEM,
    }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("предупреждение о сбросе учётных данных — только при смене узла, как у сервера (3Н38 ревью 3.r2)", async () => {
    renderScreen(all);
    fireEvent.click(await screen.findByRole("button", { name: "Изменить провайдера Основной" }));
    const dlg = await screen.findByRole("dialog");
    const addr = within(dlg).getByLabelText("Адрес API");
    for (const same of ["https://llm.corp.example/v2", "https://LLM.corp.example:443/v1", "https://llm.corp.example./v1/"]) {
      fireEvent.change(addr, { target: { value: same } });
      expect(within(dlg).queryByText(/сбрасывает учётные данные/)).toBeNull();
    }
    for (const other of ["https://llm2.corp.example/v1", "https://llm.corp.example:8443/v1"]) {
      fireEvent.change(addr, { target: { value: other } });
      expect(within(dlg).getByText(/сбрасывает учётные данные/)).toBeTruthy();
    }
  });

  it("учётные данные: ввод скрыт, уходят один раз, значение не остаётся на экране", async () => {
    renderScreen(all);
    fireEvent.click(await screen.findByRole("button", { name: "Учётные данные Основной" }));
    const dlg = await screen.findByRole("dialog");
    const input = within(dlg).getByLabelText("Ключ API или авторизационные данные") as HTMLInputElement;
    expect(input.type).toBe("password");
    // Браузер не подставляет и не предлагает сохранить пароль консоли (3В20 ревью 3.r2).
    expect(input.autocomplete).toBe("new-password");
    fireEvent.change(input, { target: { value: "кириллица" } });
    expect((within(dlg).getByRole("button", { name: "Сохранить учётные данные" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(input, { target: { value: ASCII_KEY } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить учётные данные" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/credentials"))?.body).toEqual({ credential: ASCII_KEY }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(ASCII_KEY);
  });

  it("снятие признака «внешний»: нужны причина и пароль", async () => {
    list = [provider({ external: true })];
    renderScreen(["providers.read", "providers.external"], false);
    fireEvent.click(await screen.findByRole("button", { name: "Признак «внешний» Основной" }));
    const dlg = await screen.findByRole("dialog", { name: /Снять признак «внешний»/ });
    const go = within(dlg).getByRole("button", { name: "Снять признак «внешний»" }) as HTMLButtonElement;
    expect(go.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Причина"), { target: { value: "Модель в контуре заказчика" } });
    expect(go.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-проверки-1" } });
    expect(go.disabled).toBe(false);
    fireEvent.click(go);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/external"))?.body).toEqual({ external: false, reason: "Модель в контуре заказчика", password: "Пароль-для-проверки-1" }));
  });

  it("при включённом TOTP вместо пароля — код; возврат признака пароля не требует", async () => {
    list = [provider({ external: true })];
    const { unmount } = renderScreen(["providers.read", "providers.external"], true);
    fireEvent.click(await screen.findByRole("button", { name: "Признак «внешний» Основной" }));
    const dlg = await screen.findByRole("dialog");
    expect(within(dlg).getByLabelText("Код из приложения-аутентификатора")).toBeTruthy();
    unmount();
    list = [provider({ external: false })];
    renderScreen(["providers.read", "providers.external"]);
    fireEvent.click(await screen.findByRole("button", { name: "Признак «внешний» Основной" }));
    const d2 = await screen.findByRole("dialog", { name: /Вернуть признак/ });
    expect(within(d2).queryByLabelText("Текущий пароль")).toBeNull();
    fireEvent.change(within(d2).getByLabelText("Причина"), { target: { value: "Снова внешний" } });
    fireEvent.click(within(d2).getByRole("button", { name: "Вернуть признак" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/external"))?.body).toEqual({ external: true, reason: "Снова внешний" }));
  });

  it("отказ сервера при снятии признака (403) показан в диалоге, диалог не закрывается", async () => {
    list = [provider({ external: true })];
    handler = (c) => (c.url.endsWith("/external") ? problem(403, "reauthentication_failed", "Пароль или код не принят.") : undefined);
    renderScreen(["providers.read", "providers.external"]);
    fireEvent.click(await screen.findByRole("button", { name: "Признак «внешний» Основной" }));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Причина"), { target: { value: "нужно" } });
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "неверный" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Снять признак «внешний»" }));
    await within(dlg).findByText(/Сервер отказал в действии. Пароль или код не принят./);
    expect((within(dlg).getByLabelText("Текущий пароль") as HTMLInputElement).value).toBe("");
  });

  it("удаление требует подтверждения; пустой и ошибочный ответы", async () => {
    renderScreen(all);
    fireEvent.click(await screen.findByRole("button", { name: "Удалить провайдера Основной" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    const dlg = await screen.findByRole("alertdialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Удалить провайдера" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/v1/providers/p-1")).toBe(true));
  });

  it("список пуст — подсказка; сбой загрузки — сообщение", async () => {
    list = [];
    const { unmount } = renderScreen(["providers.read"]);
    await screen.findByText("Провайдеров пока нет");
    unmount();
    handler = () => problem(503, "unavailable", "x");
    renderScreen(["providers.read"]);
    await screen.findByText(/Сервер временно недоступен/);
  });
});
