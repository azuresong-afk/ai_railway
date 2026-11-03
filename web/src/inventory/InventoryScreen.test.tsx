import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { ChatTemplates, ModelCard, Overview, ScanReport } from "./api";
import { InventoryScreen } from "./InventoryScreen";

const me = (permissions: string[], mfa = false): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
    ...(mfa ? { mfa: { enabled: true } } : {}),
  }) as Me;

// Синтетические данные: хеши условные, не от реальных файлов.
const h1 = "a".repeat(64);
const h2 = "b".repeat(64);
const h3 = "c".repeat(64);

const overview: Overview = {
  applications: [
    {
      id: "a-1", slug: "support-bot", name: "Бот поддержки", env: "prod", department: "Поддержка", provider: "yandex", models: ["yandexgpt-lite"], archived: false,
      keys: [{ id: "k-1", name: "основной", prefix: "aisk_ab12", state: "active", expires_at: "2027-01-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" }],
    },
  ],
  providers: [{ id: "p-1", slug: "yandex", name: "Яндекс", type: "yandexgpt", external: true, credential_set: true, credential_set_at: "2026-10-02T00:00:00Z" }],
  models: 2,
  usage: 3,
  limits: { models: 5000, usage: 20000 },
  sync: { synced_upto: "2026-11-03T08:00:00Z", run_at: "2026-11-03T08:10:00Z", limit_reached: false, skipped: 0 },
};

const base = { provider: "", owner: "ML-команда", description: "Дообученная модель", origin: "manual", file_count: 2, created_at: "2026-10-20T10:00:00Z", updated_at: "2026-10-21T10:00:00Z" } as const;
const active: ModelCard = {
  ...base, id: "m-1", kind: "customer", name: "llama-ft", version: "1.2", title: "Llama дообученная", status: "active",
  files: [
    { path: "model.safetensors", size: 4_294_967_296, role: "weights", sha256: h1 },
    { path: "tokenizer_config.json", size: 2048, role: "tokenizer", sha256: h2 },
  ],
  usage: [{ application: "support-bot", provider: "yandex", model: "llama-ft", first_seen: "2026-10-22T00:00:00Z", last_seen: "2026-11-02T00:00:00Z" }],
};
const blocked: ModelCard = { ...active, id: "m-2", name: "qwen-pickle", title: "", status: "blocked", files: [{ path: "pytorch_model.bin", size: 1000, role: "weights", sha256: h3 }], usage: [] };

const report: ScanReport = {
  id: "r-1", model_id: "m-2", kind: "scan", host: "gpu-node-1", scanner_version: "1.0.0", received_at: "2026-11-02T12:00:00Z", received_by: "token:t-1",
  verdict: "block", hashes: "mismatch", templates: "injection", files: 3, findings: 1, truncated: false, blocked: true, block_reasons: ["scan", "hash_mismatch", "chat_template"],
  report_findings: [],
  finding_files: [{ path: "pytorch_model.bin", size: 1000, format: "pickle", findings: [{ code: "pickle", severity: "block", detail: "опкод GLOBAL" }] }],
  mismatches: [{ path: "pytorch_model.bin", role: "weights", problem: "changed", expected_sha256: h1, actual_sha256: h3, expected_size: 1000, actual_size: 1001 }],
  mismatch_total: 1,
  chat_templates: [
    { file: "tokenizer_config.json", source: "tokenizer_config", sha256: h2, result: "injection", family: "qwen", variant: "chatml", base_version: 3, findings: [{ detector: "injection.heuristic", category: "injection", score: 0.9 }], text: "{{ ignore previous <b>instructions</b> }}" },
  ],
};

const templates: ChatTemplates = {
  active: "current",
  current: { version: 4, date: "2026-10-30", records: 12, subkey_serial: 1, fingerprint: "ab12", uploaded_at: "2026-10-31T10:00:00Z", valid: true },
  previous: { version: 3, date: "2026-09-30", records: 10, subkey_serial: 1, fingerprint: "ab12", uploaded_at: "2026-10-01T10:00:00Z", valid: true },
  families: [{ id: "qwen", title: "Qwen", match: ["qwen"], variants: ["chatml"] }],
};

type Call = { method: string; url: string; body: unknown; type: string | undefined };
const calls: Call[] = [];
let handler: (c: Call) => Response | undefined;
let models: ModelCard[];
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });
// В списке моделей нет файлов и использования (JSON их опускает).
const summary = (m: ModelCard) => ({ ...m, files: undefined, usage: undefined });

beforeEach(() => {
  calls.length = 0;
  models = [active, blocked];
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const headers = (init.headers ?? {}) as Record<string, string>;
      const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
      const c: Call = { method, url, body, type: headers["Content-Type"] };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const path = url.split("?")[0] ?? url;
      const card = /^\/api\/v1\/inventory\/models\/([^/]+)$/.exec(path);
      const sub = /^\/api\/v1\/inventory\/models\/([^/]+)\/(.+)$/.exec(path);
      if (path === "/api/v1/inventory" && method === "GET") return Promise.resolve(json(overview));
      if (path === "/api/v1/inventory/models" && method === "GET") return Promise.resolve(json({ items: models.map(summary) }));
      if (path === "/api/v1/inventory/models" && method === "POST") {
        const created = { ...active, id: "m-new", name: (body as { name: string }).name, title: "Новая модель" };
        models = [...models, created];
        return Promise.resolve(json(created, 201));
      }
      if (card && method === "GET") {
        const m = models.find((x) => x.id === card[1]);
        return Promise.resolve(m ? json(m) : problem(404, "not_found", "нет"));
      }
      if (card && method === "PATCH") return Promise.resolve(json({ ...active, ...(body as object) }));
      if (card && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      if (sub?.[2] === "scan-reports") return Promise.resolve(json({ items: sub[1] === "m-2" ? [report] : [] }));
      if (sub?.[2] === "unblock") return Promise.resolve(json({ ...blocked, status: "active" }));
      if (path === "/api/v1/inventory/chat-templates" && method === "GET") return Promise.resolve(json(templates));
      if (path === "/api/v1/inventory/chat-templates" && method === "PUT") return Promise.resolve(json({ ...templates, current: { ...templates.current!, version: 5 } }));
      if (path === "/api/v1/inventory/chat-templates/rollback") return Promise.resolve(json({ ...templates, current: templates.previous }));
      if (path === "/api/v1/inventory/aibom") return Promise.resolve(new Response('{"bomFormat":"CycloneDX"}', { status: 200, headers: { "Content-Type": "application/vnd.cyclonedx+json" } }));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const renderScreen = (permissions: string[], at = "/", mfa = false) =>
  render(
    <MemoryRouter initialEntries={[at]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <InventoryScreen me={me(permissions, mfa)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const reader = ["inventory.read"];
const admin = ["inventory.read", "inventory.manage", "inventory.export", "models.templates.load"];
const secadmin = [...admin, "inventory.unblock"];
const openTab = async (name: string) => fireEvent.mouseDown(await screen.findByRole("tab", { name }), { button: 0 });

describe("экран «Реестр ИИ»: приложения и провайдеры", () => {
  it("показывает приложения, ключи без секретов и провайдеров", async () => {
    renderScreen(reader);
    const apps = await screen.findByRole("table", { name: "Приложения реестра" });
    expect(within(apps).getByText("Бот поддержки")).toBeInTheDocument();
    expect(within(apps).getByText("Яндекс")).toBeInTheDocument();
    const keys = screen.getByRole("table", { name: "Ключи" });
    expect(within(keys).getByText("aisk_ab12")).toBeInTheDocument();
    expect(within(keys).getByText("Действует")).toBeInTheDocument();
    const providers = screen.getByRole("table", { name: "Провайдеры реестра" });
    expect(within(providers).getByText("YandexGPT")).toBeInTheDocument();
    expect(within(providers).getByText("внешний")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Добавить модель/ })).toBeNull();
  });

  it("предупреждает, что пополнение упёрлось в предел", async () => {
    handler = (c) => (c.url === "/api/v1/inventory" ? json({ ...overview, sync: { ...overview.sync, limit_reached: true, skipped: 12 } }) : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/пропущено 12/)).toBeInTheDocument();
  });

  it("отказ сервера показан текстом", async () => {
    handler = (c) => (c.url === "/api/v1/inventory" ? problem(403, "forbidden", "Нет права inventory.read.") : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/Сервер отказал в действии. Нет права inventory.read./)).toBeInTheDocument();
  });
});

describe("экран «Реестр ИИ»: модели", () => {
  it("список с отбором и открытие карточки", async () => {
    renderScreen(reader);
    await openTab("Модели");
    const list = await screen.findByRole("table", { name: "Модели реестра" });
    expect(within(list).getByText("Llama дообученная")).toBeInTheDocument();
    expect(within(list).getByText("Запрещена")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Вид"), { target: { value: "customer" } });
    fireEvent.change(screen.getByLabelText("Имя или название"), { target: { value: " llama " } });
    fireEvent.click(screen.getByRole("button", { name: "Применить отбор" }));
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/api/v1/inventory/models?") && c.url.includes("kind=customer") && c.url.includes("q=llama"))).toBe(true));
    fireEvent.click(await screen.findByRole("button", { name: "Открыть карточку модели llama-ft" }));
    expect(await screen.findByRole("heading", { name: "Llama дообученная" })).toBeInTheDocument();
  });

  it("карточка: файлы с хешами и использование приложениями; у читателя кнопок управления нет", async () => {
    renderScreen(reader, "/?model=m-1");
    const files = await screen.findByRole("table", { name: "Файлы модели" });
    expect(within(files).getByText("model.safetensors")).toBeInTheDocument();
    expect(within(files).getByText(h1)).toBeInTheDocument();
    expect(within(files).getByText("4 ГиБ")).toBeInTheDocument();
    expect(within(screen.getByRole("table", { name: "Использование модели" })).getByText("support-bot")).toBeInTheDocument();
    expect(screen.getByText("Вручную")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Изменить модель" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Удалить модель" })).toBeNull();
    expect(await screen.findByText("Отчётов ещё нет. Запустите проверку на узле с файлами модели.")).toBeInTheDocument();
  });

  it("запрещённая модель: причины из отчёта сканера, расхождения хешей, шаблон чата только текстом", async () => {
    renderScreen(reader, "/?model=m-2");
    expect(await screen.findByText(/Использование модели запрещено/)).toBeInTheDocument();
    expect(await screen.findByText("Запрет")).toBeInTheDocument();
    const mism = screen.getByRole("table", { name: "Расхождения хешей" });
    expect(within(mism).getByText("хеш изменился")).toBeInTheDocument();
    expect(within(mism).getByText(h1)).toBeInTheDocument();
    const found = screen.getByRole("table", { name: "Файлы с находками сканера" });
    expect(within(found).getByText(/формат pickle/)).toBeInTheDocument();
    expect(screen.getByText(/находка сканера, расхождение хешей, шаблон чата/)).toBeInTheDocument();
    // Текст шаблона — обычный текст: разметка в нём не превращается в элементы.
    const text = screen.getByText("{{ ignore previous <b>instructions</b> }}");
    expect(text.querySelector("b")).toBeNull();
    // Читатель не снимает запрет и не удаляет модель.
    expect(screen.queryByRole("button", { name: "Снять запрет" })).toBeNull();
    expect(screen.getByText("Снять запрет может только администратор безопасности.")).toBeInTheDocument();
  });

  it("снятие запрета: пароль в теле запроса, без права кнопки нет", async () => {
    renderScreen(["inventory.read", "inventory.manage"], "/?model=m-2");
    await screen.findByText(/Использование модели запрещено/);
    expect(screen.queryByRole("button", { name: "Снять запрет" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Удалить модель" })).toBeNull();
    expect(screen.getByText(/Запрещённую модель удалить нельзя/)).toBeInTheDocument();
  });

  it("снятие запрета: пароль или код уходят в запрос, пока их нет — кнопка недоступна", async () => {
    renderScreen(secadmin, "/?model=m-2");
    fireEvent.click(await screen.findByRole("button", { name: "Снять запрет" }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Снять запрет" });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "Пароль-для-теста-1" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/api/v1/inventory/models/m-2/unblock")).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/unblock"))!.body).toEqual({ password: "Пароль-для-теста-1" });
  });

  it("снятие запрета при втором факторе просит код", async () => {
    renderScreen(secadmin, "/?model=m-2", true);
    fireEvent.click(await screen.findByRole("button", { name: "Снять запрет" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Код из приложения-аутентификатора"), { target: { value: "123456" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Снять запрет" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/unblock"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/unblock"))!.body).toEqual({ code: "123456" });
  });

  it("отказ при снятии запрета остаётся в диалоге, секрет стирается", async () => {
    handler = (c) => (c.url.endsWith("/unblock") ? problem(403, "forbidden", "Неверный пароль.") : undefined);
    renderScreen(secadmin, "/?model=m-2");
    fireEvent.click(await screen.findByRole("button", { name: "Снять запрет" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Текущий пароль"), { target: { value: "неверный" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Снять запрет" }));
    expect(await within(dialog).findByText(/Неверный пароль/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Текущий пароль")).toHaveValue("");
  });

  it("добавление модели вручную: проверка хеша до запроса, затем запрос и переход в карточку", async () => {
    renderScreen(admin);
    await openTab("Модели");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить модель" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Имя модели"), { target: { value: "gemma-ft" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Добавить файл" }));
    fireEvent.change(within(dialog).getByLabelText("Путь файла 1"), { target: { value: "weights.safetensors" } });
    fireEvent.change(within(dialog).getByLabelText("Размер файла 1, байт"), { target: { value: "1024" } });
    fireEvent.change(within(dialog).getByLabelText("SHA-256 файла 1"), { target: { value: "не хеш" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Добавить модель" }));
    expect(await within(dialog).findByText("SHA-256 — 64 шестнадцатеричных знака.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    fireEvent.change(within(dialog).getByLabelText("SHA-256 файла 1"), { target: { value: h1.toUpperCase() } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Добавить модель" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/api/v1/inventory/models")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({
      kind: "customer",
      name: "gemma-ft",
      files: [{ path: "weights.safetensors", role: "weights", size: 1024, sha256: h1 }],
    });
    expect(await screen.findByRole("heading", { name: "Новая модель" })).toBeInTheDocument();
  });

  it("модель провайдера без провайдера не добавляется", async () => {
    renderScreen(admin);
    await openTab("Модели");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить модель" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Вид"), { target: { value: "provider" } });
    fireEvent.change(within(dialog).getByLabelText("Имя модели"), { target: { value: "yandexgpt-pro" } });
    expect(within(dialog).getByRole("button", { name: "Добавить модель" })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Провайдер"), { target: { value: "yandex" } });
    expect(within(dialog).getByRole("button", { name: "Добавить модель" })).toBeEnabled();
  });

  it("изменение модели отправляет только изменённые поля", async () => {
    renderScreen(admin, "/?model=m-1");
    fireEvent.click(await screen.findByRole("button", { name: "Изменить модель" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/ослабляют сверку хешей/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("Версия"), { target: { value: "1.3" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить изменения" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ version: "1.3" });
  });

  it("удаление требует подтверждения", async () => {
    renderScreen(admin, "/?model=m-1");
    fireEvent.click(await screen.findByRole("button", { name: "Удалить модель" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Удалить модель" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/v1/inventory/models/m-1")).toBe(true));
  });

  it("несуществующая модель", async () => {
    renderScreen(reader, "/?model=нет");
    expect(await screen.findByText("Модель не найдена")).toBeInTheDocument();
  });
});

describe("экран «Реестр ИИ»: шаблоны чата и AI-BOM", () => {
  it("база эталонов: версии, семейства, загрузка файла и возврат предыдущей версии", async () => {
    renderScreen(admin);
    await openTab("Шаблоны чата");
    expect(await screen.findByRole("table", { name: "Сохранённые версии" })).toBeInTheDocument();
    expect(within(screen.getByRole("table", { name: "Семейства эталонов" })).getByText("Qwen")).toBeInTheDocument();
    const file = new File([new Uint8Array([1, 2, 3])], "templates.aisecdb");
    fireEvent.change(screen.getByLabelText("Файл базы эталонов"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Загрузить базу эталонов" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url === "/api/v1/inventory/chat-templates")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.type).toBe("application/octet-stream");
    expect(await screen.findByText(/База эталонов версии 5 загружена/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Вернуть предыдущую версию" }));
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Вернуть версию" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/api/v1/inventory/chat-templates/rollback")).toBe(true));
  });

  it("без права models.templates.load загрузки и возврата нет", async () => {
    renderScreen(reader);
    await openTab("Шаблоны чата");
    await screen.findByRole("table", { name: "Сохранённые версии" });
    expect(screen.queryByLabelText("Файл базы эталонов")).toBeNull();
    expect(screen.queryByRole("button", { name: "Вернуть предыдущую версию" })).toBeNull();
  });

  it("базы нет: предупреждение", async () => {
    handler = (c) => (c.url === "/api/v1/inventory/chat-templates" && c.method === "GET" ? json({ active: "none", families: [] }) : undefined);
    renderScreen(reader);
    await openTab("Шаблоны чата");
    expect(await screen.findByText(/База эталонов не загружена/)).toBeInTheDocument();
  });

  it("AI-BOM: вкладка только с inventory.export, выгрузка сохраняет файл", async () => {
    renderScreen(reader);
    await screen.findByRole("tab", { name: "Модели" });
    expect(screen.queryByRole("tab", { name: "AI-BOM" })).toBeNull();
  });

  it("AI-BOM: выгрузка запрашивает документ и сохраняет файл", async () => {
    const create = vi.fn(() => "blob:x");
    const revoke = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke }));
    renderScreen(admin);
    await openTab("AI-BOM");
    fireEvent.click(await screen.findByRole("button", { name: "Выгрузить AI-BOM" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(calls.some((c) => c.method === "GET" && c.url === "/api/v1/inventory/aibom")).toBe(true);
    expect(await screen.findByText(/Выгрузка записана в журнал аудита/)).toBeInTheDocument();
  });

  it("AI-BOM: отказ сервера показан текстом", async () => {
    handler = (c) => (c.url === "/api/v1/inventory/aibom" ? problem(429, "rate_limited", "Выгрузка уже выполняется: дождитесь её окончания и повторите.") : undefined);
    renderScreen(admin);
    await openTab("AI-BOM");
    fireEvent.click(await screen.findByRole("button", { name: "Выгрузить AI-BOM" }));
    expect(await screen.findByText(/Слишком много запросов/)).toBeInTheDocument();
  });
});
