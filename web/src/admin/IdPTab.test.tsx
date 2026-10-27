import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AdminScreen } from "./AdminScreen";

// Вкладка «Вход через IdP» (ADR-0025, задача 4.17).

const me = (permissions: string[], mfa = false): Me => ({
  user: { id: "u-me", login: "boss", display_name: "Босс", email: "", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
  mfa: { enabled: mfa, required: mfa },
});

// Адреса — от источника страницы jsdom: внешних адресов в тестах нет.
const origin = window.location.origin;
const configured = {
  configured: true,
  enabled: true,
  display_name: "Корпоративный вход",
  issuer: `${origin}/realms/aisec`,
  client_id: "aisec-console",
  console_url: origin,
  redirect_uri: `${origin}/api/v1/auth/oidc/callback`,
  ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  scopes: ["profile"],
  groups_claim: "groups",
  required_acr: [],
  required_amr: ["otp"],
  group_roles: [{ group: "aisec-analysts", role: "analyst" }],
  version: 2,
};

const calls: { method: string; url: string; body: Record<string, unknown> | undefined }[] = [];
let state: Record<string, unknown> = { configured: false, enabled: false, scopes: [], required_acr: [], required_amr: [], group_roles: [] };

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  state = { configured: false, enabled: false, scopes: [], required_acr: [], required_amr: [], group_roles: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ method: init.method ?? "GET", url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(status === 204 ? null : JSON.stringify(b), { status }));
      if (url === "/api/v1/auth/idp") {
        if (init.method === "PUT") {
          if (body?.issuer === "bad-issuer") {
            return json({ code: "invalid_request", detail: "Проверьте введённые данные.", status: 400, errors: [{ field: "issuer", detail: "Адрес издателя: нужен https." }] }, 400);
          }
          state = { ...configured };
          return json(state);
        }
        if (init.method === "DELETE") return json(null, 204);
        return json(state);
      }
      if (url.startsWith("/api/v1/roles")) return json({ items: [{ id: "analyst" }, { id: "auditor" }, { id: "security_admin" }] });
      return json({ items: [] });
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderTab = (permissions: string[], mfa = false) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AdminScreen me={me(permissions, mfa)} />
    </QueryClientProvider>,
  );

const openTab = async () => {
  const tab = screen.getByRole("tab", { name: "Вход через IdP" });
  fireEvent.mouseDown(tab);
  fireEvent.click(tab);
  return screen.findByLabelText("Адрес издателя (issuer)");
};

describe("вход через IdP", () => {
  it("вкладка видна только с правом auth_idp.read", () => {
    renderTab(["users.read"]);
    expect(screen.queryByRole("tab", { name: "Вход через IdP" })).toBeNull();
  });

  it("сохранение требует пароль и отправляет секрет только при вводе", async () => {
    renderTab(["auth_idp.read", "auth_idp.manage", "roles.read"]);
    await openTab();
    const save = screen.getByRole("button", { name: "Сохранить настройки" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Название на кнопке входа"), { target: { value: "Корпоративный вход" } });
    fireEvent.change(screen.getByLabelText("Адрес издателя (issuer)"), { target: { value: ` ${origin}/realms/aisec ` } });
    fireEvent.change(screen.getByLabelText("Идентификатор клиента (client_id)"), { target: { value: "aisec-console" } });
    fireEvent.change(screen.getByLabelText("Секрет клиента (client_secret)"), { target: { value: "synthetic-client-credential-1" } });
    fireEvent.change(screen.getByLabelText("Допустимые значения amr"), { target: { value: "otp  hwk" } });
    fireEvent.click(screen.getByRole("button", { name: "Добавить группу" }));
    fireEvent.change(screen.getByLabelText("Группа 1"), { target: { value: "aisec-analysts" } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Синтетический-Пароль-42" } });
    expect(save).toBeEnabled();
    fireEvent.click(save);
    expect(await screen.findByText(/Настройки сохранены/)).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toMatchObject({
      enabled: true,
      issuer: `${origin}/realms/aisec`,
      client_secret: "synthetic-client-credential-1",
      required_amr: ["otp", "hwk"],
      group_roles: [{ group: "aisec-analysts", role: "analyst" }],
      password: "Синтетический-Пароль-42",
    });
    // Пароль стирается после успеха; секрет клиента не показывается.
    await waitFor(() => expect(screen.getByLabelText("Текущий пароль")).toHaveValue(""));
    expect(screen.getByLabelText("Секрет клиента (client_secret)")).toHaveValue("");
    expect(screen.getByText(configured.redirect_uri)).toBeInTheDocument();
  });

  it("с подключённым вторым фактором подтверждение — кодом", async () => {
    state = { ...configured };
    renderTab(["auth_idp.read", "auth_idp.manage"], true);
    await openTab();
    fireEvent.change(screen.getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    await screen.findByText(/Настройки сохранены/);
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toMatchObject({ code: "123456", client_secret: "" });
    expect(put?.body).not.toHaveProperty("password");
  });

  it("ошибка поля от сервера показывается у поля", async () => {
    renderTab(["auth_idp.read", "auth_idp.manage"]);
    await openTab();
    fireEvent.change(screen.getByLabelText("Адрес издателя (issuer)"), { target: { value: "bad-issuer" } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    expect(await screen.findByText("Адрес издателя: нужен https.")).toBeInTheDocument();
  });

  it("без права auth_idp.manage — только просмотр", async () => {
    state = { ...configured };
    renderTab(["auth_idp.read"]);
    const issuer = await openTab();
    expect(issuer).toBeDisabled();
    expect(issuer).toHaveValue(configured.issuer);
    expect(screen.queryByRole("button", { name: "Сохранить настройки" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Удалить настройки" })).toBeNull();
    expect(screen.getByText("Менять настройки может администратор безопасности.")).toBeInTheDocument();
  });

  it("удаление — через подтверждение и с паролем", async () => {
    state = { ...configured };
    renderTab(["auth_idp.read", "auth_idp.manage"]);
    await openTab();
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Синтетический-Пароль-42" } });
    fireEvent.click(screen.getByRole("button", { name: "Удалить настройки" }));
    fireEvent.click(await screen.findByRole("button", { name: "Удалить" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(calls.find((c) => c.method === "DELETE")?.body).toEqual({ password: "Синтетический-Пароль-42" });
  });
});
