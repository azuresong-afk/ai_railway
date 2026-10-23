import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App, makeQueryClient } from "./App";

type Handler = (init: RequestInit) => Response;
const routes = new Map<string, Handler>();
const json = (status: number, body?: unknown) => () =>
  new Response(body === undefined ? null : JSON.stringify(body), { status });

const user = { id: "1", login: "ivanov", display_name: "Иван Иванов" };
const meOf = (session_state: string, permissions: string[] = ["session"]) => ({ user, session_state, permissions });

beforeEach(() => {
  routes.clear();
  vi.stubGlobal(
    "fetch",
    vi.fn((path: string, init: RequestInit) => {
      const h = routes.get(`${init.method} ${path}`);
      return Promise.resolve(h ? h(init) : new Response(null, { status: 500 }));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  document.documentElement.removeAttribute("data-theme");
});

const renderApp = () => render(<App client={makeQueryClient()} />);

describe("консоль: вход", () => {
  it("без сессии показывает вход, одинаковая ошибка для любого отказа", async () => {
    routes.set("GET /api/v1/me", json(401, { code: "unauthorized", detail: "x" }));
    routes.set("GET /api/v1/auth/setup", json(200, { setup_required: false }));
    routes.set("POST /api/v1/auth/login", json(401, { code: "unauthorized", detail: "Пользователь не найден" }));
    renderApp();
    fireEvent.change(await Promise.resolve(await screen.findByLabelText("Логин")), { target: { value: "nobody" } });
    fireEvent.change(await Promise.resolve(screen.getByLabelText("Пароль")), { target: { value: "bad" } });
    fireEvent.click(await Promise.resolve(screen.getByRole("button", { name: "Войти" })));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Неверный логин или пароль");
    expect(alert).not.toHaveTextContent("не найден");
  });

  it("успешный вход открывает каркас; разделы скрыты по правам", async () => {
    routes.set("GET /api/v1/me", json(401, { code: "unauthorized", detail: "x" }));
    routes.set("GET /api/v1/auth/setup", json(200, { setup_required: false }));
    routes.set("POST /api/v1/auth/login", json(200, meOf("active", ["session", "system.read", "dashboards.read"])));
    renderApp();
    fireEvent.change(await Promise.resolve(await screen.findByLabelText("Логин")), { target: { value: "ivanov" } });
    fireEvent.change(await Promise.resolve(screen.getByLabelText("Пароль")), { target: { value: "secret" } });
    fireEvent.click(await Promise.resolve(screen.getByRole("button", { name: "Войти" })));
    expect(await screen.findByRole("link", { name: /Состояние системы/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Администрирование/ })).toBeNull();
    expect(screen.getByRole("link", { name: /Обзор/ })).toBeInTheDocument();
  });

  it("mfa_pending: код отправляется, неверный код — общий текст", async () => {
    routes.set("GET /api/v1/me", json(200, meOf("mfa_pending")));
    routes.set("POST /api/v1/auth/mfa/verify", json(400, { code: "invalid_request", detail: "Код неверен" }));
    renderApp();
    fireEvent.change(await Promise.resolve(await screen.findByLabelText("Код из приложения")), { target: { value: "123456" } });
    fireEvent.click(await Promise.resolve(screen.getByRole("button", { name: "Подтвердить" })));
    expect(await screen.findByRole("alert")).toHaveTextContent("Код не подошёл");
  });

  it("password_change: несовпадение повтора не уходит на сервер", async () => {
    routes.set("GET /api/v1/me", json(200, meOf("password_change")));
    const change = vi.fn(json(204));
    routes.set("POST /api/v1/auth/password", change);
    renderApp();
    fireEvent.change(await Promise.resolve(await screen.findByLabelText("Текущий пароль")), { target: { value: "old" } });
    fireEvent.change(await Promise.resolve(screen.getByLabelText("Новый пароль")), { target: { value: "newpass-1" } });
    fireEvent.change(await Promise.resolve(screen.getByLabelText("Новый пароль ещё раз")), { target: { value: "newpass-2" } });
    fireEvent.click(await Promise.resolve(screen.getByRole("button", { name: "Сменить пароль" })));
    expect(await screen.findByRole("alert")).toHaveTextContent("не совпадают");
    expect(change).not.toHaveBeenCalled();
  });

  it("первичная настройка показывается, пока нет учётных записей", async () => {
    routes.set("GET /api/v1/me", json(401, { code: "unauthorized", detail: "x" }));
    routes.set("GET /api/v1/auth/setup", json(200, { setup_required: true }));
    renderApp();
    expect(await screen.findByRole("heading", { name: "Первичная настройка" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText("Токен настройки")).toBeInTheDocument());
  });

  it("mfa_setup: QR выводится SVG-рисунком", async () => {
    routes.set("GET /api/v1/me", json(200, meOf("mfa_setup")));
    routes.set("POST /api/v1/auth/mfa/setup", json(200, { secret: "ABCDEF", otpauth_uri: "x", qr: ["101", "010"] }));
    renderApp();
    fireEvent.click(await Promise.resolve(await screen.findByRole("button", { name: "Показать QR-код" })));
    expect(await screen.findByRole("img", { name: /QR-код/ })).toBeInTheDocument();
    expect(screen.getByLabelText("Секрет для ручного ввода")).toHaveValue("ABCDEF");
  });
});
