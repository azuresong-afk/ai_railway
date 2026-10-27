import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AdminScreen } from "./AdminScreen";

// Вкладка «Вход через LDAP» (ADR-0025, задача 4.16).

const me = (permissions: string[], mfa = false): Me => ({
  user: { id: "u-me", login: "boss", display_name: "Босс", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
  mfa: { enabled: mfa, required: mfa },
});

const analysts = "cn=aisec-analysts,cn=groups,dc=example,dc=test";
const configured = {
  configured: true,
  enabled: true,
  url: "ldaps://ipa.example.test",
  ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
  bind_dn: "uid=aisec-svc,cn=sysaccounts,dc=example,dc=test",
  user_base_dn: "cn=users,dc=example,dc=test",
  user_filter: "(&(objectClass=person)(uid={login}))",
  id_attribute: "ipaUniqueID",
  display_attribute: "displayName",
  group_mode: "member_of",
  group_base_dn: "",
  group_roles: [{ group: analysts, role: "analyst" }],
  version: 2,
};

const calls: { method: string; url: string; body: Record<string, unknown> | undefined }[] = [];
let state: Record<string, unknown> = { configured: false, enabled: false, group_roles: [] };

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  state = { configured: false, enabled: false, group_roles: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ method: init.method ?? "GET", url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(status === 204 ? null : JSON.stringify(b), { status }));
      if (url === "/api/v1/auth/ldap") {
        if (init.method === "PUT") {
          if (body?.url === "ldap://bad") {
            return json({ code: "invalid_request", detail: "Проверьте введённые данные.", status: 400, errors: [{ field: "url", detail: "Каталог недоступен с сервера." }] }, 400);
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
  const tab = screen.getByRole("tab", { name: "Вход через LDAP" });
  fireEvent.mouseDown(tab);
  fireEvent.click(tab);
  return screen.findByLabelText("Адрес каталога");
};

describe("вход через LDAP", () => {
  it("вкладка видна только с правом auth_idp.read", () => {
    renderTab(["users.read"]);
    expect(screen.queryByRole("tab", { name: "Вход через LDAP" })).toBeNull();
  });

  it("сохранение требует пароль и отправляет пароль сервисной записи только при вводе", async () => {
    renderTab(["auth_idp.read", "auth_idp.manage", "roles.read"]);
    await openTab();
    const save = screen.getByRole("button", { name: "Сохранить настройки" });
    expect(save).toBeDisabled();
    // Ветка групп нужна только для поиска групп.
    expect(screen.queryByLabelText("Ветка групп")).toBeNull();
    fireEvent.change(screen.getByLabelText("Адрес каталога"), { target: { value: " ldaps://ipa.example.test " } });
    fireEvent.change(screen.getByLabelText("DN сервисной учётной записи"), { target: { value: configured.bind_dn } });
    fireEvent.change(screen.getByLabelText("Пароль сервисной учётной записи"), { target: { value: "synthetic-service-credential-1" } });
    fireEvent.change(screen.getByLabelText("Ветка пользователей"), { target: { value: configured.user_base_dn } });
    fireEvent.change(screen.getByLabelText("Атрибут постоянного идентификатора"), { target: { value: "ipaUniqueID" } });
    fireEvent.click(screen.getByRole("button", { name: "Добавить группу" }));
    fireEvent.change(screen.getByLabelText("DN группы 1"), { target: { value: analysts } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Синтетический-Пароль-42" } });
    expect(save).toBeEnabled();
    fireEvent.click(save);
    expect(await screen.findByText(/Настройки сохранены/)).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toMatchObject({
      enabled: true,
      url: "ldaps://ipa.example.test",
      bind_password: "synthetic-service-credential-1",
      user_filter: "(&(objectClass=person)(uid={login}))",
      id_attribute: "ipaUniqueID",
      group_mode: "member_of",
      group_base_dn: "",
      group_roles: [{ group: analysts, role: "analyst" }],
      password: "Синтетический-Пароль-42",
    });
    // Пароли стираются после успеха и не показываются.
    await waitFor(() => expect(screen.getByLabelText("Текущий пароль")).toHaveValue(""));
    expect(screen.getByLabelText("Пароль сервисной учётной записи")).toHaveValue("");
  });

  it("поиск групп спрашивает ветку групп", async () => {
    state = { ...configured };
    renderTab(["auth_idp.read", "auth_idp.manage"], true);
    await openTab();
    fireEvent.change(screen.getByLabelText("Как получать группы"), { target: { value: "ad_nested" } });
    fireEvent.change(screen.getByLabelText("Ветка групп"), { target: { value: "cn=groups,dc=example,dc=test" } });
    fireEvent.change(screen.getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    await screen.findByText(/Настройки сохранены/);
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toMatchObject({ group_mode: "ad_nested", group_base_dn: "cn=groups,dc=example,dc=test", code: "123456", bind_password: "" });
    expect(put?.body).not.toHaveProperty("password");
  });

  it("ошибка проверки каталога показывается у адреса", async () => {
    renderTab(["auth_idp.read", "auth_idp.manage"]);
    await openTab();
    fireEvent.change(screen.getByLabelText("Адрес каталога"), { target: { value: "ldap://bad" } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    expect(await screen.findByText("Каталог недоступен с сервера.")).toBeInTheDocument();
  });

  it("без права auth_idp.manage — только просмотр", async () => {
    state = { ...configured };
    renderTab(["auth_idp.read"]);
    const url = await openTab();
    expect(url).toBeDisabled();
    expect(url).toHaveValue(configured.url);
    expect(screen.queryByRole("button", { name: "Сохранить настройки" })).toBeNull();
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
