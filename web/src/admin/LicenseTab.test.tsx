import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { AdminScreen } from "./AdminScreen";
import type { LicenseInfo } from "./api";
import { licenseNotice } from "./licenseText";

// Вкладка «Лицензия» и тексты баннера (ТЗ 5.15, задача 4.27, ADR-0026).

const me = (permissions: string[], mfa = false): Me => ({
  user: { id: "u-me", login: "sysadm", display_name: "Сисадмин", email: "", role: "system_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
  mfa: { enabled: mfa, required: mfa },
});

const none: LicenseInfo = { state: "none", restricted: false, clock_behind: false, number: 0, modules: ["agents", "shadow_ai", "compliance", "ml"] };
// Синтетическая лицензия: ИНН региона 00 не принадлежит реальной организации.
const active: LicenseInfo = {
  state: "active",
  restricted: false,
  clock_behind: false,
  number: 3,
  type: "commercial",
  licensee: { organization: "ООО «Тестовый заказчик»", inn: "0012345673" },
  issued_at: "2026-10-28T00:00:00Z",
  valid_from: "2026-10-28T00:00:00Z",
  valid_until: "2027-10-28T00:00:00Z",
  grace_until: "2027-11-27T00:00:00Z",
  days_left: 364,
  grace_days_left: 394,
  limits: { gateways: 10, applications: 0 },
  usage: { gateways: 2, applications: 7 },
  modules: ["shadow_ai"],
  subkey_serial: 2,
  subkey_not_after: "2031-09-30T00:00:00Z",
  fingerprint: "2ecb:0ad2",
  loaded_at: "2026-10-28T09:00:00Z",
};

const calls: { method: string; body: Record<string, unknown> | undefined }[] = [];
let state: LicenseInfo = none;

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  state = none;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const body = init.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ method: init.method ?? "GET", body });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url === "/api/v1/license" && init.method === "PUT") {
        if (body?.license === "плохой файл") {
          return json({ code: "unprocessable", detail: "Файл не является лицензией AISec или повреждён.", status: 422 }, 422);
        }
        state = active;
        return json(state);
      }
      if (url === "/api/v1/license") return json(state);
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
  const tab = screen.getByRole("tab", { name: "Лицензия" });
  fireEvent.mouseDown(tab);
  fireEvent.click(tab);
  return screen.findByRole("heading", { name: "Лицензия" });
};

const chooseFile = (text: string) => {
  const input = screen.getByLabelText("Файл лицензии") as HTMLInputElement;
  const f = new File([text], "license.aiseclic", { type: "application/json" });
  Object.defineProperty(input, "files", { value: [f], configurable: true });
};

describe("лицензия", () => {
  it("вкладка видна только с правом license.read", () => {
    renderTab(["users.read"]);
    expect(screen.queryByRole("tab", { name: "Лицензия" })).toBeNull();
  });

  it("без лицензии — режим пилота, без права license.manage загрузки нет", async () => {
    renderTab(["license.read"]);
    await openTab();
    expect(await screen.findByText(/режиме «пилот по договору»/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Загрузить лицензию" })).toBeNull();
  });

  it("загрузка отправляет текст файла и пароль, пароль стирается", async () => {
    renderTab(["license.read", "license.manage"]);
    await openTab();
    const upload = await screen.findByRole("button", { name: "Загрузить лицензию" });
    expect(upload).toBeDisabled();
    chooseFile('{"format":"aisec-license-v1"}');
    fireEvent.change(screen.getByLabelText("Текущий пароль"), { target: { value: "Синтетический-Пароль-42" } });
    fireEvent.click(upload);
    expect(await screen.findByText(/Лицензия № 3 загружена/)).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ license: '{"format":"aisec-license-v1"}', password: "Синтетический-Пароль-42" });
    await waitFor(() => expect(screen.getByLabelText("Текущий пароль")).toHaveValue(""));
    expect(screen.getByText("ООО «Тестовый заказчик», ИНН 0012345673")).toBeInTheDocument();
    expect(screen.getByText("с 28.10.2026 до 28.10.2027")).toBeInTheDocument();
    expect(screen.getByText("10, используется 2")).toBeInTheDocument();
    expect(screen.getByText("без ограничения, используется 7")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Заменить лицензию" })).toBeInTheDocument();
  });

  it("со вторым фактором — код; отказ сервера показывается", async () => {
    renderTab(["license.read", "license.manage"], true);
    await openTab();
    chooseFile("плохой файл");
    fireEvent.change(await screen.findByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Загрузить лицензию" }));
    expect(await screen.findByText(/Файл не является лицензией AISec/)).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toMatchObject({ code: "123456" });
    expect(put?.body).not.toHaveProperty("password");
  });

  it("без файла запрос не уходит", async () => {
    renderTab(["license.read", "license.manage"]);
    await openTab();
    fireEvent.change(await screen.findByLabelText("Текущий пароль"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Загрузить лицензию" }));
    expect(await screen.findByText("Выберите файл лицензии.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });
});

describe("баннер лицензии", () => {
  it("по стадиям срока", () => {
    expect(licenseNotice(none)).toBeNull();
    expect(licenseNotice(active)).toBeNull();
    expect(licenseNotice({ ...active, state: "expiring", days_left: 20 })).toMatchObject({ kind: "info" });
    expect(licenseNotice({ ...active, state: "expiring", days_left: 6 })?.text).toContain("заканчивается 28.10.2027 (осталось суток: 6)");
    expect(licenseNotice({ ...active, state: "grace", grace_days_left: 12 })?.text).toContain("льготный период до 27.11.2027");
    expect(licenseNotice({ ...active, state: "restricted", restricted: true })).toMatchObject({ kind: "error" });
    expect(licenseNotice({ ...none, state: "invalid", number: 3, restricted: true })?.text).toContain("не прошла проверку подписи");
    expect(licenseNotice({ ...active, clock_behind: true })?.text).toContain("Часы сервера отстают");
  });
});
