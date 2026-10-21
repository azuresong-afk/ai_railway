import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventCard, readDetails } from "./EventCard";

const ev = {
  id: "0190f3a2-0000-7000-8000-000000000001",
  time: "2026-10-21T12:00:00Z",
  received_at: "2026-10-21T12:00:01Z",
  gateway_id: "0190f3a2-0000-7000-8000-0000000000aa",
  type: "gateway_request",
  app: "crm-bot",
  storage: "masked",
  threats: ["DM-01"],
  stream: false,
  non_text_unchecked: false,
  has_content: true,
  details: {
    decision: {
      action: "mask",
      applied: ["mask"],
      rule: "pii-mask",
      severity: "high",
      trace: [{ rule: "pii-mask", detector: "pii.snils", matched: true, action: "mask" }],
    },
    findings: [{ detector: "pii.snils", category: "pii", score: 0.97, start: 0, end: 5, location: "messages[0].content", threat: "DM-01" }],
  },
};

const calls: { url: string; body: unknown }[] = [];
let contentStatus = 200;

beforeEach(() => {
  calls.length = 0;
  contentStatus = 200;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/content")) {
        if (contentStatus !== 200) {
          return Promise.resolve(new Response(JSON.stringify({ code: "forbidden", detail: "x" }), { status: contentStatus }));
        }
        return Promise.resolve(
          new Response(JSON.stringify({ event_id: ev.id, storage: "masked", request: "<img src=x onerror=alert(1)> **жирный**", response: "ответ" })),
        );
      }
      return Promise.resolve(new Response(JSON.stringify(ev)));
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());

const renderCard = (canReadContent: boolean) =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <EventCard id={ev.id} canReadContent={canReadContent} onClose={() => {}} />
    </QueryClientProvider>,
  );

describe("карточка события", () => {
  it("показывает решение, трассировку и находки, но не загружает содержимое", async () => {
    renderCard(true);
    expect(await screen.findByRole("heading", { name: "Почему принято решение" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Трассировка правил" })).toHaveTextContent("pii.snils");
    expect(screen.getByRole("table", { name: "Находки" })).toHaveTextContent("DM-01");
    expect(calls.some((c) => c.url.endsWith("/content"))).toBe(false);
  });

  it("без права на содержимое кнопки нет", async () => {
    renderCard(false);
    await screen.findByRole("heading", { name: "Почему принято решение" });
    expect(screen.queryByRole("button", { name: "Показать содержимое" })).toBeNull();
  });

  it("содержимое запрашивается с причиной и выводится только текстом", async () => {
    renderCard(true);
    fireEvent.click(await screen.findByRole("button", { name: "Показать содержимое" }));
    fireEvent.change(await screen.findByLabelText("Причина просмотра"), { target: { value: "ab" } });
    fireEvent.click(screen.getByRole("button", { name: "Показать содержимое", hidden: false }));
    expect(await screen.findByText("Опишите причину: от 3 до 500 символов.")).toBeInTheDocument();
    expect(calls.some((c) => c.url.endsWith("/content"))).toBe(false);

    fireEvent.change(screen.getByLabelText("Причина просмотра"), { target: { value: "  Bearer разбор инцидента 7  " } });
    fireEvent.click(screen.getAllByRole("button", { name: "Показать содержимое" }).at(-1)!);
    const text = await screen.findByText(/onerror=alert/);
    expect(text.tagName).toBe("PRE");
    expect(document.querySelector("img")).toBeNull();
    expect(calls.find((c) => c.url.endsWith("/content"))?.body).toEqual({ reason: "Bearer разбор инцидента 7" });
    expect(screen.getByRole("button", { name: "Скрыть содержимое" })).toBeInTheDocument();
  });

  it("отказ сервера объясняется и содержимое не показывается", async () => {
    contentStatus = 403;
    renderCard(true);
    fireEvent.click(await screen.findByRole("button", { name: "Показать содержимое" }));
    fireEvent.change(await screen.findByLabelText("Причина просмотра"), { target: { value: "проверка" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Показать содержимое" }).at(-1)!);
    await waitFor(() => expect(screen.getByRole("alert", { name: "" })).toBeInTheDocument());
    expect(screen.getByText(/Нет права смотреть содержимое/)).toBeInTheDocument();
    expect(screen.queryByText("ответ")).toBeNull();
  });
});

describe("разбор details", () => {
  it("терпит чужую форму данных", () => {
    const d = readDetails({ decision: "x", findings: [1, null, { score: "a" }], latency_ms: { total: 5, bad: "z" } });
    expect(d.trace).toEqual([]);
    expect(d.findings).toHaveLength(3);
    expect(d.latency).toEqual([["total", 5]]);
    expect(readDetails(undefined).tokens).toBeNull();
  });
});
