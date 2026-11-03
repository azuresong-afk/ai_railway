import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Policy } from "./api";
import { RulesEditor } from "./RulesEditor";

const base: Policy = {
  id: "mine",
  name: "Моя политика",
  mode: "enforce",
  template: false,
  current_version: 2,
  updated_at: "2026-10-02T10:00:00Z",
  spec: { name: "Моя политика", mode: "enforce", rules: [{ id: "pii-ru", detector: "pii.ru", action: "redact", severity: "high" }] },
} as unknown as Policy;

const syncPolicy: Policy = {
  ...base,
  spec: {
    ...base.spec,
    judge: { provider: "local-llm", model: "qwen3", max_calls_per_minute: 60 },
    rules: [
      ...base.spec.rules,
      { id: "no-refunds", detector: "judge.llm", directions: ["output"], action: "block", severity: "high", judge: { kind: "business", criterion: "Ассистент не обещает возврат денег.", mode: "sync", timeout_ms: 3000, on_failure: "block" } },
    ],
  },
};

const provider = (o: object) => ({
  id: "p1", slug: "local-llm", name: "Локальная модель", type: "openai", base_url: "llm.internal", ca_pem: "", timeouts: {}, external: false,
  on_premise: true, credential_set: true, created_at: "2026-10-01T10:00:00Z", updated_at: "2026-10-01T10:00:00Z", ...o,
});

let calls: { method: string; url: string; body: unknown }[] = [];
let putStatus = 200;

beforeEach(() => {
  calls = [];
  putStatus = 200;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      const json = (b: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(b), { status }));
      if (url === "/api/v1/providers") return json({ items: [provider({}), provider({ id: "p2", slug: "cloud", name: "Облако", on_premise: false })] });
      if (method === "PUT" && url === "/api/v1/policies/mine") {
        return putStatus === 200
          ? json(base)
          : json({ code: "invalid_request", detail: "Нужна повторная проверка.", status: 400, errors: [{ field: "password", detail: "Введите текущий пароль." }] }, 400);
      }
      return json({ code: "not_found", detail: "нет", status: 404 }, 404);
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderEditor = (policy: Policy, canReadProviders = true) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RulesEditor policy={policy} mfa={false} canReadProviders={canReadProviders} onSaved={() => void 0} />
    </QueryClientProvider>,
  );

const type = (label: string | RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const saved = () => calls.find((c) => c.method === "PUT")?.body as { spec: { judge?: unknown; rules: { id: string; judge?: unknown; directions?: string[]; action: string }[] } };

describe("редактор judge.llm в политике", () => {
  it("предлагает только провайдеров «у заказчика» и добавляет правило с оценщиком", async () => {
    renderEditor(base);
    await waitFor(() => expect(document.querySelectorAll("datalist option")).toHaveLength(1));
    expect(document.querySelector("datalist option")?.getAttribute("value")).toBe("local-llm");
    expect(screen.getByText("Правил нет: оценщик не вызывается.")).toBeInTheDocument();

    type("Провайдер-оценщик", "local-llm");
    type("Модель оценщика", "qwen3:14b");
    type("ID правила judge", "no-refunds");
    type("Критерий нового правила", "Ассистент не обещает возврат денег и скидки.");
    fireEvent.click(screen.getByRole("button", { name: "Добавить правило judge.llm" }));
    expect(await screen.findByRole("region", { name: "Правило judge.llm no-refunds" })).toBeInTheDocument();
    // Правило видно и в общей таблице, где задаются действие, серьёзность и порог.
    expect(screen.getByLabelText("Действие правила no-refunds")).toHaveValue("log");
    expect(within(screen.getByLabelText("Действие правила no-refunds")).queryByRole("option", { name: "Заблокировать" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Сохранить новую версию" }));
    await waitFor(() => expect(saved()).toBeDefined());
    expect(saved().spec.judge).toEqual({ provider: "local-llm", model: "qwen3:14b" });
    expect(saved().spec.rules[1]).toEqual({
      id: "no-refunds", detector: "judge.llm", directions: ["output"], action: "log", severity: "medium",
      judge: { kind: "business", criterion: "Ассистент не обещает возврат денег и скидки." },
    });
  });

  it("проверяет пределы и не даёт сохранить неверные значения", async () => {
    renderEditor(base);
    type("ID правила judge", "Bad Id");
    expect(await screen.findByText(/латиница в нижнем регистре/)).toBeInTheDocument();
    type("ID правила judge", "ok-rule");
    type("Критерий нового правила", "коротко");
    expect(await screen.findByText(/от 10 до 1000 символов, сейчас 7/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Добавить правило judge.llm" })).toBeDisabled();
    type("Критерий нового правила", "Ассистент не даёт юридических заключений.");
    fireEvent.click(screen.getByRole("button", { name: "Добавить правило judge.llm" }));
    // Правило есть, оценщик не задан — сохранить нельзя.
    await screen.findByRole("region", { name: "Правило judge.llm ok-rule" });
    expect(screen.getByText(/оценщик не задан/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeDisabled();
    type("Провайдер-оценщик", "Local LLM");
    type("Модель оценщика", "m");
    expect(await screen.findByText(/латиница в нижнем регистре, цифры и «-»/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeDisabled();
    type("Провайдер-оценщик", "local-llm");
    type("Вызовов в минуту", "7000");
    expect(await screen.findByText(/от 1 до 6000/)).toBeInTheDocument();
    type("Вызовов в минуту", "100");
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeEnabled();
  });

  it("общая форма не принимает детектор judge.llm без критерия", () => {
    renderEditor(base);
    type("ID правила", "plain-judge");
    type("Детектор", "judge.llm");
    expect(screen.getByText(/добавляются ниже, в блоке «Модель-оценщик»/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Добавить правило" })).toBeDisabled();
  });

  it("режим sync открывает срок и поведение при отказе, возврат в async их убирает", async () => {
    renderEditor(syncPolicy);
    const card = await screen.findByRole("region", { name: "Правило judge.llm no-refunds" });
    expect(within(card).getByLabelText("Срок оценки правила no-refunds, мс")).toHaveValue("3000");
    expect(within(card).getByLabelText("При отказе оценщика, правило no-refunds")).toHaveValue("block");
    expect(screen.getByLabelText("Действие правила no-refunds")).toHaveValue("block");

    type("Срок оценки правила no-refunds, мс", "100");
    expect(await screen.findByText(/от 500 до 30000/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeDisabled();
    type("Срок оценки правила no-refunds, мс", "8000");
    expect(screen.getByRole("button", { name: "Сохранить новую версию" })).toBeEnabled();

    fireEvent.change(within(card).getByLabelText("Режим правила no-refunds"), { target: { value: "async" } });
    expect(within(card).queryByLabelText("Срок оценки правила no-refunds, мс")).toBeNull();
    expect(within(card).queryByLabelText("При отказе оценщика, правило no-refunds")).toBeNull();
    // Блокировать в async нельзя — действие смягчено до «Записать», изменение показано как ослабление.
    expect(screen.getByLabelText("Действие правила no-refunds")).toHaveValue("log");
    expect(await screen.findByText(/Изменение ослабляет защиту:.*ослаблена проверка моделью-оценщиком \(no-refunds\)/)).toBeInTheDocument();
  });

  it("ослабление: сервер просит пароль — поле появляется, повтор уходит с паролем", async () => {
    putStatus = 400;
    renderEditor(syncPolicy);
    await screen.findByRole("region", { name: "Правило judge.llm no-refunds" });
    type("Модель оценщика", "other-model");
    expect(await screen.findByText(/ослаблена проверка моделью-оценщиком/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Сохранить новую версию" }));
    const pw = await screen.findByLabelText("Текущий пароль");
    putStatus = 200;
    fireEvent.change(pw, { target: { value: "секрет-для-теста" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить новую версию" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PUT")[1]?.body).toMatchObject({ password: "секрет-для-теста" });
  });

  it("оценщика нельзя убрать, пока есть правила judge.llm; правило убирается кнопкой", async () => {
    renderEditor(syncPolicy);
    const card = await screen.findByRole("region", { name: "Правило judge.llm no-refunds" });
    expect(screen.getByRole("button", { name: "Убрать оценщика" })).toBeDisabled();
    fireEvent.click(within(card).getByRole("button", { name: "Убрать правило judge.llm no-refunds" }));
    expect(screen.queryByRole("region", { name: "Правило judge.llm no-refunds" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Убрать оценщика" }));
    expect(screen.getByLabelText("Провайдер-оценщик")).toHaveValue("");
  });

  it("без права на провайдеров список не запрашивается, имя вводится вручную", async () => {
    renderEditor(base, false);
    expect(screen.getByText(/Список провайдеров вам недоступен/)).toBeInTheDocument();
    await Promise.resolve();
    expect(calls.some((c) => c.url === "/api/v1/providers")).toBe(false);
  });

  it("предупреждает, если провайдер не отмечен как размещённый у заказчика", async () => {
    renderEditor(base);
    await waitFor(() => expect(document.querySelectorAll("datalist option")).toHaveLength(1));
    type("Провайдер-оценщик", "cloud");
    expect(await screen.findByText(/не найден среди размещённых у заказчика/)).toBeInTheDocument();
  });
});
