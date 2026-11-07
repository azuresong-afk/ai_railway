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

// Событие full с сохранённым изображением и рамкой находки (задача 6.13, ADR-0039).
const imageEv = {
  ...ev,
  storage: "full",
  details: {
    decision: { action: "block", applied: ["block"], rule: "pii-block", severity: "high", trace: [] },
    findings: [
      {
        detector: "pii.passport",
        category: "pii",
        score: 0.9,
        location: "messages[0].content[1]",
        source: "image",
        threat: "DM-01",
        box: { x: 4, y: 4, w: 20, h: 10 },
      },
    ],
    media: [{ location: "messages[0].content[1]", mode: "sync", checked: true, format: "png", width: 64, height: 32, stored: true }],
  },
};

const defaultContent = { event_id: ev.id, storage: "masked", request: "<img src=x onerror=alert(1)> **жирный**", response: "ответ" };
const imageContent = {
  event_id: ev.id,
  storage: "full",
  request: "Что на картинке?",
  images: [{ location: "messages[0].content[1]", format: "png", data: "iVBORw0KGgo=" }],
};

const calls: { url: string; body: unknown }[] = [];
let contentStatus = 200;
let eventBody: unknown = ev;
let contentBody: unknown = defaultContent;

beforeEach(() => {
  calls.length = 0;
  contentStatus = 200;
  eventBody = ev;
  contentBody = defaultContent;
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/content")) {
        if (contentStatus !== 200) {
          return Promise.resolve(new Response(JSON.stringify({ code: "forbidden", detail: "x" }), { status: contentStatus }));
        }
        return Promise.resolve(new Response(JSON.stringify(contentBody)));
      }
      return Promise.resolve(new Response(JSON.stringify(eventBody)));
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

describe("изображение запроса", () => {
  const svgImage = () => document.querySelector("svg image");

  it("после ввода причины показано сохранённое изображение с рамками", async () => {
    eventBody = imageEv;
    contentBody = imageContent;
    renderCard(true);
    expect(await screen.findByText(/Изображение сохранено/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Рамки находок на изображении messages\[0\]\.content\[1\], рамок: 1/ })).toBeInTheDocument();
    expect(svgImage()).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Показать содержимое" }));
    fireEvent.change(await screen.findByLabelText("Причина просмотра"), { target: { value: "разбор инцидента 8" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Показать содержимое" }).at(-1)!);
    expect(await screen.findByRole("img", { name: /^Изображение messages\[0\]\.content\[1\], рамок: 1/ })).toBeInTheDocument();
    expect(svgImage()?.getAttribute("href")).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(screen.getByText(/Просмотр записан в журнал аудита/)).toBeInTheDocument();
    expect(calls.find((c) => c.url.endsWith("/content"))?.body).toEqual({ reason: "разбор инцидента 8" });
  });

  it("без права на содержимое — только рамки на пустом поле", async () => {
    eventBody = imageEv;
    renderCard(false);
    expect(await screen.findByText(/просмотр изображения доступен администратору безопасности/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Рамки находок на изображении/ })).toHaveTextContent("64 × 32 пикселей");
    expect(svgImage()).toBeNull();
    expect(calls.some((c) => c.url.endsWith("/content"))).toBe(false);
  });

  it("не сохранённое изображение объяснено причиной", async () => {
    eventBody = {
      ...imageEv,
      details: { ...imageEv.details, media: [{ ...imageEv.details.media[0], stored: false, store_skipped: "too_large" }] },
    };
    renderCard(true);
    expect(await screen.findByText(/Не сохранено: больше 3 МБ/)).toBeInTheDocument();
    expect(screen.getByText(/Само изображение не сохранялось/)).toBeInTheDocument();
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
