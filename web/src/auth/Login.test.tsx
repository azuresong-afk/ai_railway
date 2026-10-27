import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Login, oidcErrorText } from "./Login";

// Экран входа: кнопка «Войти через …» и отказ входа через IdP (ADR-0025).

let option: { enabled: boolean; display_name?: string } = { enabled: false };

beforeEach(() => {
  option = { enabled: false };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) =>
      Promise.resolve(new Response(JSON.stringify(url === "/api/v1/auth/oidc" ? option : {}), { status: 200 })),
    ),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

const renderLogin = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Login />
    </QueryClientProvider>,
  );

describe("вход через IdP на экране входа", () => {
  it("кнопка — ссылка на начало входа, если IdP включён", async () => {
    option = { enabled: true, display_name: "Корпоративный вход" };
    renderLogin();
    const link = await screen.findByRole("link", { name: "Войти через Корпоративный вход" });
    expect(link).toHaveAttribute("href", "/api/v1/auth/oidc/start");
  });

  it("без IdP кнопки нет", async () => {
    renderLogin();
    await screen.findByRole("button", { name: "Войти" });
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("код отказа из адреса показывается и убирается из адреса", () => {
    window.history.replaceState(null, "", "/?oidc=denied");
    renderLogin();
    expect(screen.getByText(/Вход через IdP отклонён/)).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });

  it("тексты отказов не раскрывают причину", () => {
    expect(oidcErrorText(null)).toBeUndefined();
    expect(oidcErrorText("unavailable")).toMatch(/недоступен/);
    expect(oidcErrorText("failed")).toMatch(/Начните вход заново/);
    // Неизвестный код не попадает в текст как есть.
    expect(oidcErrorText("<script>")).not.toContain("<script>");
  });
});
