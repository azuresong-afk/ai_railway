import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PromptBaselineDialog } from "./PromptBaselineDialog";
import type { Application } from "./api";

const app = {
  id: "a-1", slug: "support-bot", name: "Бот поддержки", description: "", department: "", owner_id: "u-me", env: "prod", provider_id: "p-1",
  models: ["gpt-4o"], aliases: {}, policy: "base", policy_mode: "enforce", storage: "masked", fail_mode: "fail_closed", user_from: "none",
  quotas: {}, lists: [], exfil_allow_domains: [], status: "active", created_at: "2026-10-01T10:00:00Z", updated_at: "2026-10-01T10:00:00Z",
} as Application;
const PROMPT = "Ты — помощник поддержки. Отвечай только о тарифах.";
const stored = { configured: true, mode: "block", hash: "ab".repeat(32), bytes: 90, text: PROMPT, updated_at: "2026-10-27T10:00:00Z" };

const calls: { method: string; url: string; body: Record<string, unknown> | undefined }[] = [];
let current: Record<string, unknown> = { configured: false };

beforeEach(() => {
  calls.length = 0;
  current = { configured: false };
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, url, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(b === undefined ? null : JSON.stringify(b), { status }));
      const reauth = () =>
        json({ code: "invalid_request", detail: "Проверьте введённые данные.", status: 400, errors: [{ field: "password", detail: "нужен пароль" }] }, 400);
      if (method === "GET") return json(current);
      if (method === "PUT") {
        if (current.mode === "block" && body.mode !== "block" && !body.password) return reauth();
        current = { ...stored, mode: body.mode, text: body.text ?? current.text };
        return json(current);
      }
      if (method === "DELETE") {
        if (!body?.password) return reauth();
        current = { configured: false };
        return json(undefined, 204);
      }
      return json({ code: "not_found", detail: "нет", status: 404 }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderDialog = (onClose = () => {}) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PromptBaselineDialog app={app} mfa={false} onClose={onClose} />
    </QueryClientProvider>,
  );

describe("эталон системного промпта", () => {
  it("задаёт эталон: текст и режим уходят на сервер, пустой текст не отправляется", async () => {
    const onClose = vi.fn();
    renderDialog(onClose);
    const text = await screen.findByLabelText("Системный промпт");
    expect(screen.getByRole("button", { name: "Сохранить эталон" }).hasAttribute("disabled")).toBe(true);
    fireEvent.change(text, { target: { value: PROMPT } });
    fireEvent.change(screen.getByLabelText("Режим контроля"), { target: { value: "block" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить эталон" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mode: "block", text: PROMPT });
  });

  it("понижение режима и снятие просят пароль по ответу сервера", async () => {
    current = stored;
    const onClose = vi.fn();
    renderDialog(onClose);
    await screen.findByText(/Хеш эталона/);
    fireEvent.change(screen.getByLabelText("Режим контроля"), { target: { value: "alert" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить эталон" }));
    const pw = await screen.findByLabelText("Текущий пароль");
    // Текст не менялся — на сервер уходит только режим.
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mode: "alert" });
    fireEvent.change(pw, { target: { value: "секрет" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить эталон" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toEqual({ mode: "alert", password: "секрет" });
  });

  it("снятие эталона без пароля не проходит, с паролем — проходит", async () => {
    current = stored;
    const onClose = vi.fn();
    renderDialog(onClose);
    // Кнопка в форме открывает подтверждение, удаляет — кнопка подтверждения.
    const confirm = async () => {
      fireEvent.click(await screen.findByRole("button", { name: "Снять эталон" }));
      const dlg = await screen.findByRole("alertdialog");
      fireEvent.click(within(dlg).getByRole("button", { name: "Снять эталон" }));
    };
    await confirm();
    const pw = await screen.findByLabelText("Текущий пароль");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    fireEvent.change(pw, { target: { value: "секрет" } });
    await confirm();
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.filter((c) => c.method === "DELETE").map((c) => c.body)).toEqual([{}, { password: "секрет" }]);
  });
});
