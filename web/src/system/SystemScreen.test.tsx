import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { formatBytes } from "./format";
import { SystemScreen } from "./SystemScreen";

const me = (permissions: string[]): Me => ({
  user: { id: "u1", login: "a", display_name: "A", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
  session_state: "active",
  timezone: "Europe/Moscow",
  permissions,
});

const status = {
  generated_at: "2026-10-21T12:00:00Z",
  server: { version: "0.2.0", started_at: "2026-10-21T10:00:00Z", selftest: { ok: true, checked_at: "2026-10-21T10:00:01Z", failed: 0 }, integrity: [] },
  gateways: [
    { id: "g1", name: "gw-1", state: "offline", last_seen_at: "2026-10-21T11:00:00Z", version: "0.2.0", bundle_etag: "x", cert_not_after: null, selftest: null, integrity: null, events: null },
  ],
  events: { dropped: 12, rejected: 3 },
  time: { server_time: "2026-10-21T12:00:00Z", timezone: "Europe/Moscow", sync: "unsynchronized", error_micros: null },
  storage: { available: true, audit_bytes: 1073741824, limit_bytes: 21474836480, used_percent: 5, warn_percent: 80, warn_exceeded: false },
  audit_chain: { checked_at: "2026-10-21T11:30:00Z", ok: false, checked: 100, last_seq: 100, reason: "hash_mismatch", broken_seq: 42 },
  notifications: [{ condition: "time_sync", requirement: "ВРМ.1", title: "Время не синхронизировано", active: true, since: "2026-10-21T11:00:00Z", count: null }],
  unavailable: ["events"],
};
let verifyStatus = 200;

beforeEach(() => {
  verifyStatus = 200;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      if (url === "/api/v1/system/integrity/verify" && init.method === "POST") {
        if (verifyStatus !== 200) return Promise.resolve(new Response(JSON.stringify({ code: "forbidden", detail: "Нужен второй фактор." }), { status: verifyStatus }));
        return Promise.resolve(
          new Response(
            JSON.stringify({
              component: "server", trigger: "manual", checked_at: "2026-10-21T12:05:00Z", ok: false, reason: "files_mismatch",
              manifest_version: "0.2.0", test_signed: false, checked_files: 40, failures: [{ path: "web/index.html", problem: "modified" }], omitted: 2,
            }),
          ),
        );
      }
      return Promise.resolve(new Response(JSON.stringify(status)));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[]) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SystemScreen me={me(permissions)} />
    </QueryClientProvider>,
  );

describe("состояние системы", () => {
  it("показывает разделы, уведомления и нарушение цепочки словами", async () => {
    renderScreen(["system.read"]);
    expect(await screen.findByText("Время не синхронизировано (ВРМ.1)", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("Нет связи")).toBeInTheDocument();
    expect(screen.getByText(/Europe\/Moscow/)).toBeInTheDocument();
    expect(screen.getByText(/docs\/install\/time-sync\.md/)).toBeInTheDocument();
    expect(screen.getByText(/хеш записи не совпал/)).toBeInTheDocument();
    expect(screen.getByText(/нарушение на записи 42/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Заполнение журнала аудита" })).toHaveAttribute("aria-valuenow", "5");
    expect(screen.getByText(/Не удалось собрать разделы: events/)).toBeInTheDocument();
  });

  it("без права integrity.verify кнопки проверки нет", async () => {
    renderScreen(["system.read"]);
    await screen.findByText("Сервер");
    expect(screen.queryByRole("button", { name: "Проверить целостность" })).toBeNull();
  });

  it("проверка целостности по кнопке показывает дату и нарушения", async () => {
    renderScreen(["system.read", "integrity.verify"]);
    fireEvent.click(await screen.findByRole("button", { name: "Проверить целостность" }));
    expect(await screen.findByText(/Проверка от 21\.10\.2026/)).toBeInTheDocument();
    expect(screen.getByText("web/index.html")).toBeInTheDocument();
    expect(screen.getByText(/и ещё 2/)).toBeInTheDocument();
  });

  it("отказ сервера объясняется", async () => {
    verifyStatus = 403;
    renderScreen(["system.read", "integrity.verify"]);
    fireEvent.click(await screen.findByRole("button", { name: "Проверить целостность" }));
    expect(await screen.findByText(/Сервер отказал в действии. Нужен второй фактор./)).toBeInTheDocument();
  });
});

describe("размеры", () => {
  it("форматируются в двоичных единицах", () => {
    expect(formatBytes(0)).toBe("0 Б");
    expect(formatBytes(1536)).toBe("1,5 КиБ");
    expect(formatBytes(21474836480)).toBe("20 ГиБ");
  });
});
