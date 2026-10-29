import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import { formatBytes } from "./format";
import { SystemScreen } from "./SystemScreen";

const me = (permissions: string[]): Me => ({
  user: { id: "u1", login: "a", display_name: "A", email: "", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
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
              gateways_requested: 2,
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
    // Н38 ревью 2.r4: запрос проверки передан шлюзам.
    expect(screen.getByText(/Запрос проверки передан шлюзам: 2/)).toBeInTheDocument();
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

  it("раздел приёма syslog теневого ИИ — только когда слушатель включён", async () => {
    renderScreen(["system.read"]);
    expect(await screen.findByRole("region", { name: "Сервер" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Приём журналов теневого ИИ по syslog" })).toBeNull();
    const limits = { max_connections: 256, max_connections_per_address: 16, max_frame_bytes: 16384, lines_per_second: 5000, idle_timeout_seconds: 300, frame_timeout_seconds: 30 };
    const syslog = {
      enabled: true, running: true, accept_errors: 0, address: "0.0.0.0:6514", format: "squid", tls: false, client_cert_required: false, allowed_networks: ["10.0.0.0/8"], connections: 1, limits,
      accepted: 4, rejected_network: 0, rejected_limit: 7, tls_failed: 0, frame_too_large: 0, bad_frame: 0, idle_timeouts: 0, read_timeouts: 0, lines: 10,
      matched: 5, unmatched: 5, errors: 0, excluded: 0, outdated: 0, no_catalog: 0, dropped: 0, throttled: 0, unlicensed: 0, license_module: true, pending: 2, flush_failures: 0, last_flush_failed: false,
    };
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ ...status, shadow_ai_syslog: syslog }))));
    cleanup();
    renderScreen(["system.read"]);
    const region = await screen.findByRole("region", { name: "Приём журналов теневого ИИ по syslog" });
    expect(region).toHaveTextContent("Приём без TLS");
    expect(region).toHaveTextContent("Отказ: сверх предела соединений7");
  });
});
