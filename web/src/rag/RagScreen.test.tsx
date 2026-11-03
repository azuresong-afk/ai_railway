import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Me } from "../api/client";
import type { CollectionCard, CollectionList } from "./api";
import { RagScreen } from "./RagScreen";

const me = (permissions: string[]): Me =>
  ({
    user: { id: "u-me", login: "sec", display_name: "Безопасник", role: "security_admin", status: "active", locked: false, must_change_password: false, password_changed_at: "2026-10-01T00:00:00Z", created_at: "2026-10-01T00:00:00Z" },
    session_state: "active",
    timezone: "Europe/Moscow",
    permissions,
  }) as Me;

// Синтетические данные: хеши условные.
const h = (c: string) => c.repeat(64);
const none = { added: 0, changed: 0, removed: 0, added_ids: [], changed_ids: [], removed_ids: [] };
const kb: CollectionCard = {
  slug: "kb-hr", version: 3, documents: 3, size: 3 * 1024 * 1024, excluded: 1, exclusions: 1, loaded_at: "2026-11-02T10:00:00Z", loaded_by: "token:t-idx", prev_loaded_at: "2026-11-01T10:00:00Z",
  diff: { added: 1, changed: 1, removed: 1, added_ids: ["docs/new.md"], changed_ids: ["docs/<b>policy</b>.md"], removed_ids: ["docs/old.md"] },
  created_at: "2026-10-20T10:00:00Z",
  exclusion_list: [{ id: "e-1", document_id: "docs/secret.md", reason: "содержит инструкции", created_at: "2026-11-01T12:00:00Z", created_by: "user:u-me" }],
};
const quiet: CollectionCard = { ...kb, slug: "kb-it", version: 1, diff: none, excluded: 0, exclusions: 0, exclusion_list: [] };
const restored: CollectionCard = { ...kb, slug: "kb-old", version: 0, documents: 0, size: 0, excluded: 0, diff: none };
const limits = { collections: 100, documents: 100000, body_bytes: 16777216, document_id_bytes: 512, exclusions: 1000, diff_sample_ids: 100 };

type Call = { method: string; url: string; body: unknown };
const calls: Call[] = [];
let cards: CollectionCard[];
let handler: (c: Call) => Response | undefined;
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
const problem = (status: number, code: string, d: string) => new Response(JSON.stringify({ status, code, detail: d }), { status });

beforeEach(() => {
  calls.length = 0;
  cards = [kb, quiet];
  handler = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
      const c: Call = { method, url, body };
      calls.push(c);
      const custom = handler(c);
      if (custom) return Promise.resolve(custom);
      const path = url.split("?")[0] ?? url;
      if (path === "/api/v1/rag/collections") {
        // В списке исключений нет (JSON опускает undefined).
        const list = { items: cards.map((c) => ({ ...c, exclusion_list: undefined })), limits } as unknown as CollectionList;
        return Promise.resolve(json(list));
      }
      const rest = path.startsWith("/api/v1/rag/collections/") ? path.slice("/api/v1/rag/collections/".length).split("/") : [];
      const card = cards.find((x) => x.slug === decodeURIComponent(rest[0] ?? ""));
      const sub = rest.length > 1 ? `/${rest.slice(1).join("/")}` : "";
      if (!card) return Promise.resolve(problem(404, "not_found", "нет"));
      if (!sub && method === "GET") return Promise.resolve(json(card));
      if (sub === "/manifest" && method === "GET") {
        const after = new URLSearchParams(url.split("?")[1]).get("after");
        if (after) return Promise.resolve(json({ version: card.version, items: [{ id: "docs/z.md", sha256: h("d"), size: 5, excluded: false, blocked: false }] }));
        return Promise.resolve(
          json({
            version: card.version,
            items: [
              { id: "docs/a.md", sha256: h("a"), size: 2048, excluded: false, blocked: false },
              { id: "docs/secret.md", sha256: h("b"), size: 10, excluded: false, blocked: true },
              { id: "docs/bad.md", sha256: h("c"), size: 10, excluded: true, blocked: false },
            ],
            next_after: "docs/bad.md",
          }),
        );
      }
      if (sub === "/exclusions" && method === "POST") return Promise.resolve(json({ id: "e-2", document_id: (body as { document_id: string }).document_id, reason: "", created_at: "2026-11-03T10:00:00Z", created_by: "user:u-me" }, 201));
      if (sub.startsWith("/exclusions/") && method === "DELETE") return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(problem(404, "not_found", "нет"));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const renderScreen = (permissions: string[], at = "/") =>
  render(
    <MemoryRouter initialEntries={[at]}>
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RagScreen me={me(permissions)} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
const reader = ["rag.read"];
const manager = ["rag.read", "rag.manage"];
const secadmin = ["rag.read", "rag.manage", "rag.unexclude"];
const openTab = async (name: string) => fireEvent.mouseDown(await screen.findByRole("tab", { name }), { button: 0 });

describe("экран «Коллекции RAG»", () => {
  it("список: версии, размер, изменения в последней версии", async () => {
    renderScreen(reader);
    const table = await screen.findByRole("table", { name: "Коллекции RAG" });
    const rows = within(table).getAllByRole("row");
    expect(within(rows[1]!).getByText("kb-hr")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("добавлено 1, изменено 1, удалено 1")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("3 МиБ")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("—", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText(/Предел — 100 коллекций/)).toBeInTheDocument();
  });

  it("пустой список подсказывает, как появляется коллекция", async () => {
    cards = [];
    renderScreen(reader);
    expect(await screen.findByText("Коллекций RAG пока нет")).toBeInTheDocument();
  });

  it("карточка: изменённые документы показаны текстом, читателю кнопок управления нет", async () => {
    renderScreen(reader);
    fireEvent.click(await screen.findByRole("button", { name: "Открыть коллекцию kb-hr" }));
    expect(await screen.findByRole("heading", { name: "kb-hr" })).toBeInTheDocument();
    expect(screen.getByText(/добавлено 1, изменено 1, удалено 1/)).toBeInTheDocument();
    // ID документа — обычный текст, разметка в нём не становится элементом.
    const id = screen.getByText("docs/<b>policy</b>.md");
    expect(id.querySelector("b")).toBeNull();
    expect(screen.getByText("docs/old.md")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Исключить документ/ })).toBeNull();
  });

  it("документы: страницы по next_after, состояния исключений", async () => {
    renderScreen(reader, "/?c=kb-hr");
    await openTab("Документы");
    const table = await screen.findByRole("table", { name: "Документы манифеста" });
    expect(within(table).getByText("исключён администратором")).toBeInTheDocument();
    expect(within(table).getByText("исключён индексатором")).toBeInTheDocument();
    expect(within(table).getByText("2 КиБ")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Показать ещё" }));
    expect(await within(screen.getByRole("table", { name: "Документы манифеста" })).findByText("docs/z.md")).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("/manifest?") && c.url.includes("after=docs%2Fbad.md"))).toBe(true);
  });

  it("исключение документа администратором: запрос с ID и причиной", async () => {
    renderScreen(manager, "/?c=kb-hr");
    fireEvent.click(await screen.findByRole("button", { name: "Исключить документ docs/new.md" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText("ID документа")).toHaveValue("docs/new.md");
    fireEvent.change(within(dialog).getByLabelText("Причина"), { target: { value: "не проверен" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Исключить документ" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.url).toBe("/api/v1/rag/collections/kb-hr/exclusions");
    expect(post.body).toEqual({ document_id: "docs/new.md", reason: "не проверен" });
  });

  it("исключения: список, снятие только с правом безопасности и после подтверждения", async () => {
    renderScreen(manager, "/?c=kb-hr");
    await openTab("Исключения");
    const table = await screen.findByRole("table", { name: "Исключения" });
    expect(within(table).getByText("содержит инструкции")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Снять исключение/ })).toBeNull();
    expect(screen.getByText("Снять исключение может только администратор безопасности.")).toBeInTheDocument();
  });

  it("снятие исключения администратором безопасности", async () => {
    renderScreen(secadmin, "/?c=kb-hr");
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Снять исключение docs/secret.md" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/ослабление защиты/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Снять исключение" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/v1/rag/collections/kb-hr/exclusions/e-1")).toBe(true));
  });

  it("отказ сервера при снятии остаётся в диалоге", async () => {
    handler = (c) => (c.method === "DELETE" ? problem(403, "forbidden", "Нужно право rag.unexclude.") : undefined);
    renderScreen(secadmin, "/?c=kb-hr");
    await openTab("Исключения");
    fireEvent.click(await screen.findByRole("button", { name: "Снять исключение docs/secret.md" }));
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Снять исключение" }));
    expect(await within(dialog).findByText(/Нужно право rag.unexclude./)).toBeInTheDocument();
  });

  it("коллекция без манифеста (версия 0) и первая версия без сравнения", async () => {
    cards = [restored, quiet];
    renderScreen(reader, "/?c=kb-old");
    expect(await screen.findByText(/Манифест ещё не загружен/)).toBeInTheDocument();
  });

  it("первая версия: сравнивать не с чем", async () => {
    renderScreen(reader, "/?c=kb-it");
    expect(await screen.findByText(/первая загруженная версия манифеста/)).toBeInTheDocument();
  });

  it("несуществующая коллекция и отказ в чтении", async () => {
    renderScreen(reader, "/?c=нет");
    expect(await screen.findByText("Коллекция не найдена")).toBeInTheDocument();
  });

  it("отказ сервера в чтении списка показан текстом", async () => {
    handler = (c) => (c.url === "/api/v1/rag/collections" ? problem(403, "forbidden", "Нет права rag.read.") : undefined);
    renderScreen(reader);
    expect(await screen.findByText(/Сервер отказал в действии. Нет права rag.read./)).toBeInTheDocument();
  });
});
