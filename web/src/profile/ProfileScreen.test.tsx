import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { ProfileScreen } from "./ProfileScreen";

const me = (email: string): Me => ({
  user: { id: "u1", login: "petrov", display_name: "Петров", email, role: "analyst", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions: ["session", "self"],
});

const calls: { method: string; url: string; body: unknown }[] = [];
let failure = false;

beforeEach(() => {
  calls.length = 0;
  failure = false;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ method: init.method ?? "GET", url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      return Promise.resolve(
        failure
          ? new Response(JSON.stringify({ code: "invalid_request", detail: "E-mail: вида user@example.ru.", status: 400 }), { status: 400 })
          : new Response("{}", { status: 200 }),
      );
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (email: string) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProfileScreen me={me(email)} />
    </QueryClientProvider>,
  );

describe("профиль", () => {
  it("показывает свои данные и сохраняет e-mail своим маршрутом", async () => {
    renderScreen("");
    expect(screen.getByText("petrov")).toBeInTheDocument();
    const save = screen.getByRole("button", { name: "Сохранить" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/E-mail для рассылки/), { target: { value: " petrov@example.ru " } });
    // Без пароля сохранить нельзя (ревью 4.r1, 4В12).
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "секрет" } });
    fireEvent.click(save);
    expect(await screen.findByText("Сохранено.")).toBeInTheDocument();
    expect(calls).toEqual([{ method: "PUT", url: "/api/v1/me/email", body: { email: "petrov@example.ru", password: "секрет" } }]);
  });

  it("пустое поле убирает адрес", async () => {
    renderScreen("petrov@example.ru");
    fireEvent.change(screen.getByLabelText(/E-mail для рассылки/), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "секрет" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(calls.at(-1)?.body).toEqual({ email: "", password: "секрет" }));
  });

  it("ошибка сервера показывается", async () => {
    failure = true;
    renderScreen("");
    fireEvent.change(screen.getByLabelText(/E-mail для рассылки/), { target: { value: "плохой" } });
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "секрет" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/вида user@example.ru/);
  });
});
