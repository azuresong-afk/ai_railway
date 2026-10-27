import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AdminScreen } from "./AdminScreen";
import { tokenGrantable } from "./TokensTab";

const me = (permissions: string[]): Me => ({
  user: { id: "u-me", login: "boss", display_name: "Босс", email: "", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
});

const user = (id: string, login: string) => ({
  id,
  login,
  display_name: `Имя ${login}`,
  email: "",
  role: "analyst",
  status: "active",
  locked: false,
  must_change_password: false,
  password_changed_at: "2026-10-01T00:00:00Z",
  created_at: "2026-10-01T00:00:00Z",
});
const role = (id: string, perms: string[]) => ({
  id,
  display_name: id,
  description: "",
  builtin: id !== "custom",
  mfa_required: false,
  users: 1,
  permissions: perms.map((permission) => ({ permission, scope: "all" })),
});

const calls: { method: string; url: string; body: unknown }[] = [];
let roleStatus = 200;

beforeEach(() => {
  // jsdom не знает ResizeObserver, а флажки Radix его используют.
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  roleStatus = 200;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method: init.method ?? "GET", url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url.startsWith("/api/v1/users?")) return json({ items: [user("u-me", "boss"), user("u-2", "petrov")] });
      if (url.endsWith("/email")) {
        return init.method === "PUT" && (body as { email: string }).email === "плохой"
          ? json({ code: "invalid_request", detail: "E-mail: вида user@example.ru.", status: 400 }, 400)
          : json({ ...user("u-2", "petrov"), email: (body as { email: string }).email });
      }
      if (url.endsWith("/role")) {
        return roleStatus === 200
          ? json({ user: user("u-2", "petrov"), revoked_sessions: 1 })
          : json({ code: "forbidden", detail: "Нельзя выдать права шире своих.", status: 403 }, 403);
      }
      if (url.startsWith("/api/v1/roles")) return json({ items: [role("analyst", ["events.read"]), role("security_admin", ["events.read", "integrity.verify"])] });
      if (url.startsWith("/api/v1/permissions")) {
        return json({
          items: [
            { name: "events.read", title: "Просмотр событий", group: "События", security: false, ownable: false },
            { name: "roles.manage", title: "Управление ролями", group: "Роли", security: true, ownable: false },
            { name: "api_tokens.manage", title: "Управление токенами", group: "Токены", security: false, ownable: false },
          ],
        });
      }
      if (url.startsWith("/api/v1/api-tokens")) {
        if (init.method === "POST") {
          return json({ api_token: {}, token: "aisec_pat_abcd1234_SECRETVALUE" }, 201);
        }
        return json({ items: [] });
      }
      if (url === "/api/v1/events/settings") {
        const b = body as { metadata_days?: number; content_days?: number; password?: string } | undefined;
        if (init.method === "PUT" && b?.password === "неверный") {
          return json({ code: "reauthentication_failed", detail: "Пароль или код не принят.", status: 403 }, 403);
        }
        return json({ metadata_days: b?.metadata_days ?? 365, content_days: b?.content_days ?? 90, updated_at: "2026-10-01T00:00:00Z" });
      }
      if (url === "/api/v1/system/settings") {
        const b = body as { timezone?: string; retention_mode?: string; password?: string } | undefined;
        if (init.method === "PUT" && b?.retention_mode === "full" && !b.password) {
          return json({ code: "invalid_request", detail: "Проверьте введённые данные.", status: 400, errors: [{ field: "password", reason: "Введите пароль." }] }, 400);
        }
        return json({ timezone: b?.timezone ?? "Europe/Moscow", retention_mode: b?.retention_mode ?? "masked" });
      }
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

describe("администрирование", () => {
  it("вкладки видны по правам, без прав — сообщение", () => {
    renderScreen(["users.read"]);
    expect(screen.getByRole("tab", { name: "Пользователи" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Роли и разрешения" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Токены API" })).toBeNull();
  });

  it("совсем без прав вкладок нет", () => {
    renderScreen(["session"]);
    expect(screen.getByText("Нет доступа к администрированию")).toBeInTheDocument();
  });

  it("кнопки управления без права users.manage не показываются", async () => {
    renderScreen(["users.read"]);
    await screen.findByText("petrov");
    expect(screen.queryByRole("button", { name: "Создать пользователя" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Сбросить пароль/ })).toBeNull();
  });

  it("свою учётную запись менять нельзя: разделение обязанностей", async () => {
    renderScreen(["users.read", "users.manage", "roles.read", "roles.manage"]);
    await screen.findByText("petrov");
    expect(screen.getByRole("button", { name: "Сменить роль: boss" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Сбросить пароль: boss" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Деактивировать: boss" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Сменить роль: petrov" })).toBeEnabled();
  });

  it("e-mail пользователя задаёт держатель users.manage; без права кнопки нет", async () => {
    renderScreen(["users.read"]);
    await screen.findByText("petrov");
    expect(screen.queryByRole("button", { name: /E-mail:/ })).toBeNull();
    expect(screen.getAllByText("не задан").length).toBeGreaterThan(0);
  });

  it("диалог e-mail: пробелы по краям убираются, пустое значение допустимо, ошибка сервера остаётся в диалоге", async () => {
    renderScreen(["users.read", "users.manage"]);
    await screen.findByText("petrov");
    fireEvent.click(screen.getByRole("button", { name: "E-mail: petrov" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("E-mail"), { target: { value: "плохой" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
    expect(await within(dialog).findByText(/вида user@example.ru/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("E-mail"), { target: { value: " petrov@example.ru " } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.body)).toEqual([{ email: "плохой" }, { email: "petrov@example.ru" }]);
  });

  it("смена роли идёт через диалог, отказ сервера показывается", async () => {
    roleStatus = 403;
    renderScreen(["users.read", "roles.read", "roles.manage"]);
    await screen.findByText("petrov");
    fireEvent.click(screen.getByRole("button", { name: "Сменить роль: petrov" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Новая роль"), { target: { value: "security_admin" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Назначить роль и завершить сессии" }));
    expect(await within(dialog).findByText(/Нельзя выдать права шире своих/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.body)).toEqual([{ role: "security_admin" }]);
  });

  it("роль с правами шире своих в списке недоступна", async () => {
    renderScreen(["users.read", "roles.read", "roles.manage", "events.read"]);
    await screen.findByText("petrov");
    fireEvent.click(screen.getByRole("button", { name: "Сменить роль: petrov" }));
    const dialog = await screen.findByRole("dialog");
    const opt = await within(dialog).findByRole("option", { name: /security_admin/ });
    expect(opt).toBeDisabled();
  });

  it("токен показывается один раз и стирается при закрытии окна", async () => {
    renderScreen(["api_tokens.read", "api_tokens.manage", "roles.read", "events.read"]);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "Токены API" }), { button: 0 });
    fireEvent.click(await screen.findByRole("button", { name: "Выпустить токен" }));
    const form = await screen.findByRole("dialog");
    fireEvent.change(within(form).getByLabelText("Название"), { target: { value: "ci" } });
    fireEvent.click(await within(form).findByRole("checkbox", { name: "Просмотр событий" }));
    fireEvent.change(within(form).getByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    fireEvent.click(within(form).getByRole("button", { name: "Выпустить токен" }));
    const secret = await screen.findByDisplayValue("aisec_pat_abcd1234_SECRETVALUE");
    expect(secret).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toMatchObject({ name: "ci", password: "Correct-Horse-1", permissions: [{ permission: "events.read", scope: "all" }] });
    fireEvent.click(screen.getByRole("button", { name: "Я сохранил значение" }));
    await waitFor(() => expect(screen.queryByDisplayValue("aisec_pat_abcd1234_SECRETVALUE")).toBeNull());
    expect(document.body.textContent).not.toContain("SECRETVALUE");
  });
});

describe("сроки хранения", () => {
  const renderRetention = async () => {
    renderScreen(["events.read", "events.retention.manage"]);
    return screen.findByLabelText("Срок хранения содержимого запросов и ответов, суток");
  };

  it("увеличение срока — без повторной проверки", async () => {
    fireEvent.change(await renderRetention(), { target: { value: "120" } });
    fireEvent.change(screen.getByLabelText("Срок хранения метаданных событий, суток"), { target: { value: "400" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить сроки" }));
    await screen.findByText(/Сроки сохранены/);
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ metadata_days: 400, content_days: 120 });
  });

  it("сокращение срока требует пароль, отказ сервера остаётся в диалоге (В13)", async () => {
    fireEvent.change(await renderRetention(), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить сроки" }));
    const dialog = await screen.findByRole("dialog");
    const action = within(dialog).getByRole("button", { name: "Сократить срок и удалить старые данные" });
    expect(action).toBeDisabled();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "неверный" } });
    fireEvent.click(action);
    await within(dialog).findByText(/Пароль или код не принят/);
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    fireEvent.click(action);
    await screen.findByText(/Сроки сохранены/);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const puts = calls.filter((c) => c.method === "PUT");
    expect(puts.at(-1)?.body).toEqual({ metadata_days: 365, content_days: 30, password: "Correct-Horse-1" });
  });
});

// В26 ревью 2.r5: часовой пояс и режим хранения по умолчанию; full — с паролем по ответу сервера.
describe("настройки установки", () => {
  it("смена пояса без проверки, full — с паролем", async () => {
    renderScreen(["events.read", "system.read", "settings.manage"]);
    const tz = await screen.findByLabelText("Часовой пояс показа времени");
    fireEvent.change(tz, { target: { value: "Asia/Omsk" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    await screen.findByText(/Настройки сохранены/);
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ timezone: "Asia/Omsk", retention_mode: "masked" });
    fireEvent.change(screen.getByLabelText("Хранение содержимого для новых приложений"), { target: { value: "full" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    fireEvent.change(await screen.findByLabelText("Текущий пароль"), { target: { value: "Correct-Horse-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить настройки" }));
    await screen.findByText(/Настройки сохранены/);
    expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toEqual({ timezone: "Asia/Omsk", retention_mode: "full", password: "Correct-Horse-1" });
  });

  it("без права settings.manage поля недоступны", async () => {
    renderScreen(["events.read", "system.read"]);
    expect(await screen.findByLabelText("Часовой пояс показа времени")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Сохранить настройки" })).toBeNull();
  });
});

describe("разрешения токена", () => {
  const p = (name: string, security = false) => ({ name, title: name, group: "g", security, ownable: false });
  it("нет разрешений безопасности, на токены и чужих", () => {
    const mine = new Set(["events.read", "roles.manage", "api_tokens.manage"]);
    expect(tokenGrantable(p("events.read"), mine)).toBe(true);
    expect(tokenGrantable(p("roles.manage", true), mine)).toBe(false);
    expect(tokenGrantable(p("api_tokens.manage"), mine)).toBe(false);
    expect(tokenGrantable(p("users.read"), mine)).toBe(false);
  });
});
