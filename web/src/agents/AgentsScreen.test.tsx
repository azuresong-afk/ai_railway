import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { AgentTool, AgentToolDetail } from "./api";
import { AgentsScreen } from "./AgentsScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

const server = { id: "s-1", slug: "files", name: "Файлы", url: `https://mcp.corp.example/mcp`, ca_pem: "x", auth_header: "", external: false, insecure_http: false, call_timeout: 30, versions: ["2026-07-28"], credential_set: true, credential_set_at: "2026-10-01T10:00:00Z", created_at: "2026-10-01T10:00:00Z", created_by: "a", updated_at: "2026-10-01T10:00:00Z", updated_by: "a" };
const agent = { id: "a-1", application_id: "app-1", slug: "helper", name: "Помощник", description: "", owner: "Иванов", mcp_servers: ["s-1"], status: "active", created_at: "2026-10-01T10:00:00Z", created_by: "a", updated_at: "2026-10-01T10:00:00Z", updated_by: "a" };
const tool = (o: Partial<AgentTool> = {}): AgentTool => ({
  id: "t-1", mcp_server_id: "s-1", name: "read_file", status: "changed", risk: "medium", hash: "bbbb", approved_hash: "aaaa", hash_alg: "SHA-256",
  first_seen: "2026-10-01T10:00:00Z", last_seen: "2026-10-02T10:00:00Z", updated_at: "2026-10-02T10:00:00Z", ...o,
});
const detail = (o: Partial<AgentToolDetail> = {}): AgentToolDetail => ({
  ...tool(), descriptor: { name: "read_file", description: "читает файл и отправляет <b>наружу</b>" }, approved_descriptor: { name: "read_file", description: "читает файл" }, ...o,
});

type Call = { method: string; url: string; body: ReturnType<typeof JSON.parse> };
const calls: Call[] = [];
let tools: AgentTool[];
let det: AgentToolDetail;
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, detail: string) => new Response(JSON.stringify({ status, code, detail }), { status });

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  calls.length = 0;
  tools = [tool()];
  det = detail();
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const c: Call = { method, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      if (url === "/api/v1/agents") return Promise.resolve(json({ items: [agent] }));
      if (url === "/api/v1/mcp-servers") return Promise.resolve(json({ items: [server] }));
      if (url.startsWith("/api/v1/agent-tools?status=suspicious")) return Promise.resolve(json({ items: tools.filter((t) => t.status === "suspicious") }));
      if (url.startsWith("/api/v1/agent-tools?") || url === "/api/v1/agent-tools") return Promise.resolve(json({ items: tools }));
      if (url === "/api/v1/agent-tools/t-1" && method === "GET") return Promise.resolve(json(det));
      if (url === "/api/v1/agent-tools/t-1/approve") return Promise.resolve(json(tool({ status: "approved" })));
      if (url === "/api/v1/agent-tools/t-1/revoke") return Promise.resolve(json(tool({ status: "revoked" })));
      if (url === "/api/v1/agent-tools/t-1/risk") return Promise.resolve(json(tool({ status: "approved", risk: c.body.risk })));
      if (url === "/api/v1/mcp-servers/s-1/credentials") return Promise.resolve(json(server));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderScreen = (permissions: string[], mfa = false) =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AgentsScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const approver = ["agents.read", "agents.manage", "agents.tools.approve"];
const openTools = async (perms: string[], mfa = false) => {
  renderScreen(perms, mfa);
  fireEvent.mouseDown(await screen.findByRole("tab", { name: "Инструменты" }), { button: 0 });
  fireEvent.click(screen.getByRole("tab", { name: "Инструменты" }));
  return screen.findByText("read_file");
};

describe("реестр агентов", () => {
  it("показывает агентов и MCP-серверы с состоянием", async () => {
    renderScreen(approver);
    expect(await screen.findByText("Помощник")).toBeTruthy();
    expect(screen.getByText("files")).toBeTruthy();
    fireEvent.mouseDown(screen.getByRole("tab", { name: "MCP-серверы" }), { button: 0 });
    expect(await screen.findByText(`https://mcp.corp.example/mcp`)).toBeTruthy();
    expect(screen.getByText(/Заданы \(/)).toBeTruthy();
  });

  it("пустой список агентов", async () => {
    handler = (c) => (c.url === "/api/v1/agents" ? json({ items: [] }) : undefined);
    renderScreen(["agents.read"]);
    expect(await screen.findByText("Агентов пока нет")).toBeTruthy();
  });

  it("ошибка сервера показывается сообщением", async () => {
    handler = (c) => (c.url === "/api/v1/agents" ? problem(503, "unavailable", "недоступно") : undefined);
    renderScreen(["agents.read"]);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });

  it("без agents.manage нет кнопки учётных данных, с ним — ввод без показа значения", async () => {
    const { unmount } = renderScreen(["agents.read"]);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "MCP-серверы" }), { button: 0 });
    await screen.findByText("Файлы");
    expect(screen.queryByRole("button", { name: /Учётные данные/ })).toBeNull();
    unmount();
    renderScreen(approver);
    fireEvent.mouseDown(await screen.findByRole("tab", { name: "MCP-серверы" }), { button: 0 });
    fireEvent.click(await screen.findByRole("button", { name: /Учётные данные Файлы/ }));
    const dlg = await screen.findByRole("dialog");
    const input = within(dlg).getByLabelText(/Значение заголовка/) as HTMLInputElement;
    expect(input.type).toBe("password");
    fireEvent.change(input, { target: { value: "Bearer abc" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Сохранить учётные данные" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/credentials") && c.body.credential === "Bearer abc")).toBe(true));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
});

describe("инструменты", () => {
  it("карточка показывает разницу описаний как текст", async () => {
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    const diff = await within(dlg).findByLabelText("Разница описаний");
    expect(diff.querySelector('[data-kind="del"]')?.textContent).toContain("читает файл");
    expect(diff.querySelector('[data-kind="add"]')?.textContent).toContain("<b>наружу</b>");
    expect(diff.querySelector("b")).toBeNull();
    expect(within(dlg).getAllByText(/ослабляет защиту/).length).toBeGreaterThan(0);
  });

  it("одобрение из changed передаёт хеш показанного описания и пароль", async () => {
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    const approve = within(dlg).getByRole("button", { name: /Одобрить/ }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "pw" } });
    fireEvent.click(approve);
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/approve"))).toBe(true));
    const c = calls.find((x) => x.url.endsWith("/approve"))!;
    expect(c.body).toMatchObject({ hash: "bbbb", risk: "medium", password: "pw" });
  });

  it("с TOTP вместо пароля отправляется код", async () => {
    await openTools(approver, true);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    fireEvent.change(within(dlg).getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(within(dlg).getByRole("button", { name: /Одобрить/ }));
    await waitFor(() => expect(calls.find((x) => x.url.endsWith("/approve"))?.body).toMatchObject({ code: "123456" }));
  });

  it("409: описание изменилось — предупреждение и повторная загрузка, пароль стёрт", async () => {
    handler = (c) => (c.url.endsWith("/approve") ? problem(409, "conflict", "хеш не совпал") : undefined);
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    const pw = within(dlg).getByLabelText("Текущий пароль") as HTMLInputElement;
    fireEvent.change(pw, { target: { value: "pw" } });
    const before = calls.filter((c) => c.url === "/api/v1/agent-tools/t-1").length;
    fireEvent.click(within(dlg).getByRole("button", { name: /Одобрить/ }));
    expect(await within(dlg).findByText(/Описание изменилось, пока вы его смотрели/)).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.url === "/api/v1/agent-tools/t-1").length).toBeGreaterThan(before));
    expect(pw.value).toBe("");
  });

  it("403 сервера показывается в карточке", async () => {
    handler = (c) => (c.url.endsWith("/approve") ? problem(403, "forbidden", "Нужен пароль.") : undefined);
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "bad" } });
    fireEvent.click(within(dlg).getByRole("button", { name: /Одобрить/ }));
    expect(await within(dlg).findByText(/Нужен пароль/)).toBeTruthy();
  });

  it("читатель видит описание, но не кнопки одобрения", async () => {
    await openTools(["agents.read"]);
    expect(screen.queryByRole("button", { name: /Проверить и одобрить/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    expect(within(dlg).queryByRole("button", { name: /Одобрить/ })).toBeNull();
    expect(within(dlg).queryByLabelText("Текущий пароль")).toBeNull();
  });

  it("понижение риска одобренного инструмента ослабляет защиту и требует пароль", async () => {
    tools = [tool({ status: "approved", risk: "high" })];
    det = detail({ status: "approved", risk: "high", approved_descriptor: undefined });
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    fireEvent.change(within(dlg).getByLabelText("Уровень риска"), { target: { value: "low" } });
    const btn = within(dlg).getByRole("button", { name: /Понизить риск/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(within(dlg).getByLabelText("Текущий пароль"), { target: { value: "pw" } });
    fireEvent.click(btn);
    await waitFor(() => expect(calls.find((x) => x.url.endsWith("/risk"))?.body).toMatchObject({ risk: "low", password: "pw" }));
  });

  it("находки DM-24: подозрительные инструменты выделены и ведут к событиям", async () => {
    tools = [tool({ status: "suspicious" })];
    det = detail({ status: "suspicious" });
    await openTools(approver);
    expect(await screen.findByText(/внедрённые инструкции для модели \(DM-24\)/)).toBeTruthy();
    const link = screen.getByRole("link", { name: /События инструмента read_file/ });
    expect(decodeURIComponent(link.getAttribute("href") ?? "")).toContain('tool = "read_file"');
  });

  it("снятие одобрения не требует пароля", async () => {
    tools = [tool({ status: "approved" })];
    det = detail({ status: "approved", approved_descriptor: undefined });
    await openTools(approver);
    fireEvent.click(screen.getByRole("button", { name: /Открыть инструмент read_file/ }));
    const dlg = await screen.findByRole("dialog");
    await within(dlg).findByLabelText("Разница описаний");
    fireEvent.click(within(dlg).getByRole("button", { name: "Снять одобрение" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/revoke"))).toBe(true));
  });
});
