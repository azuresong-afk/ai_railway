import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserAccessDialog, splitGroups } from "./UserAccessDialog";
import type { Application } from "./api";

const app = {
  id: "a-1", slug: "support-bot", name: "Бот поддержки", description: "", department: "", owner_id: "u-me", env: "prod", provider_id: "p-1",
  models: ["gpt-4o"], aliases: { smart: "gpt-4o" }, policy: "base", policy_mode: "enforce", storage: "masked", fail_mode: "fail_closed",
  user_from: "header", quotas: {}, lists: [], exfil_allow_domains: [], status: "active", created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
} as Application;
const ISS = "https://idp.example.test/realms/aisec";
const defaults = { configured: false, mode: "off", issuer: "", audience: "", groups_claim: "groups", leeway: 60, model_groups: {} };

const calls: { method: string; body: Record<string, unknown> | undefined }[] = [];
let current: Record<string, unknown> = defaults;

beforeEach(() => {
  calls.length = 0;
  current = defaults;
  vi.stubGlobal(
    "fetch",
    vi.fn((_url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (method === "GET") return json(current);
      if (current.mode === "required" && body.mode !== "required" && !body.password) {
        return json({ code: "invalid_request", detail: "Проверьте введённые данные.", status: 400, errors: [{ field: "password", detail: "нужен пароль" }] }, 400);
      }
      current = { ...body, configured: true, updated_at: "2026-10-27T10:00:00Z" };
      return json(current);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderDialog = (onClose = () => {}) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <UserAccessDialog app={app} mfa={false} onClose={onClose} />
    </QueryClientProvider>,
  );

describe("пользователи и группы приложения", () => {
  it("включает JWT и группы модели; издатель обязателен", async () => {
    const onClose = vi.fn();
    renderDialog(onClose);
    fireEvent.change(await screen.findByLabelText("Пользователь запроса"), { target: { value: "required" } });
    expect(screen.getByRole("button", { name: "Сохранить" }).hasAttribute("disabled")).toBe(true);
    fireEvent.change(screen.getByLabelText("Издатель JWT (iss)"), { target: { value: ISS } });
    fireEvent.change(screen.getByLabelText("Аудитория (aud)"), { target: { value: "aisec-gateway" } });
    fireEvent.change(screen.getByLabelText("Группы для gpt-4o"), { target: { value: "Аналитики ИБ, admins, admins" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
      mode: "required", issuer: ISS, audience: "aisec-gateway", groups_claim: "groups", leeway: 60,
      model_groups: { "gpt-4o": ["Аналитики ИБ", "admins"] },
    });
  });

  it("смягчение режима просит пароль по ответу сервера", async () => {
    current = { ...defaults, configured: true, mode: "required", issuer: ISS, audience: "aisec-gateway", model_groups: { smart: ["a"] } };
    const onClose = vi.fn();
    renderDialog(onClose);
    expect(((await screen.findByLabelText("Группы для smart")) as HTMLInputElement).value).toBe("a");
    fireEvent.change(screen.getByLabelText("Пользователь запроса"), { target: { value: "optional" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    const pw = await screen.findByLabelText("Текущий пароль");
    fireEvent.change(pw, { target: { value: "секрет" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toMatchObject({ mode: "optional", password: "секрет" });
  });

  it("группы без JWT не отправляются", async () => {
    renderDialog();
    fireEvent.change(await screen.findByLabelText("Группы для gpt-4o"), { target: { value: "a" } });
    expect(screen.getByText(/работает только с JWT/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Сохранить" }).hasAttribute("disabled")).toBe(true);
  });

  it("разбор групп: запятые и переводы строк, пробелы внутри имени сохраняются", () => {
    expect(splitGroups(" a b ,c\nc;; ")).toEqual(["a b", "c"]);
  });
});
