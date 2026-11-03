import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EventCard } from "./EventCard";
import { buildFilter, parseFilter } from "./filter";
import { clampBox, ImageBoxes, maxDrawnBoxes } from "./ImageBoxes";

const png = "data:image/png;base64,iVBORw0KGgo=";

describe("рамки на изображении (5.46)", () => {
  it("рамка обрезается по холсту, пустая и нечисловая отбрасываются", () => {
    expect(clampBox({ x: 10, y: 10, w: 50, h: 20 }, 100, 100)).toEqual({ x: 10, y: 10, w: 50, h: 20 });
    expect(clampBox({ x: 90, y: 95, w: 50, h: 50 }, 100, 100)).toEqual({ x: 90, y: 95, w: 10, h: 5 });
    expect(clampBox({ x: 100, y: 0, w: 5, h: 5 }, 100, 100)).toBeNull();
    expect(clampBox({ x: 0, y: 0, w: Number.NaN, h: 5 }, 100, 100)).toBeNull();
    expect(clampBox({ x: 0, y: 0, w: 5, h: 5 }, 0, 100)).toBeNull();
  });

  it("рисует рамки SVG с подписью-подсказкой; без изображения — пустое поле, внешних ресурсов нет", () => {
    const { container } = render(
      <ImageBoxes width={800} height={600} label="Рамки" marks={[{ n: 1, title: "1. pii.ru", box: { x: 10, y: 20, w: 100, h: 30 } }, { n: 2, title: "2. secrets", box: { x: 5000, y: 0, w: 4, h: 4 } }]} />,
    );
    const svg = screen.getByRole("img", { name: "Рамки" });
    expect(svg).toHaveAttribute("viewBox", "0 0 800 600");
    expect(svg.querySelectorAll("title")).toHaveLength(1);
    expect(svg.querySelector("image")).toBeNull();
    expect(container.querySelector("[href], [src]")).toBeNull();
    expect(within(svg as unknown as HTMLElement).getByText("800 × 600 пикселей")).toBeInTheDocument();
  });

  it("изображение подставляется только data:-адресом", () => {
    const { container, rerender } = render(<ImageBoxes width={10} height={10} label="x" marks={[]} src={png} />);
    expect(container.querySelector("image")?.getAttribute("href")).toBe(png);
    for (const bad of ["blob:abc", "//cdn/x.png", "data:text/html;base64,PGI+"]) {
      rerender(<ImageBoxes width={10} height={10} label="x" marks={[]} src={bad} />);
      expect(container.querySelector("image")).toBeNull();
    }
  });

  it("рамок больше предела: рисуется предел и сказано сколько всего", () => {
    const marks = Array.from({ length: maxDrawnBoxes + 5 }, (_, i) => ({ n: i + 1, title: `m${i}`, box: { x: 1, y: 1, w: 5, h: 5 } }));
    const { container } = render(<ImageBoxes width={100} height={100} label="x" marks={marks} />);
    expect(container.querySelectorAll("title")).toHaveLength(maxDrawnBoxes);
    expect(screen.getByText(`На рисунке первые ${maxDrawnBoxes} рамок из ${maxDrawnBoxes + 5}.`)).toBeInTheDocument();
  });
});

const imageEvent = (storage: string, extra: Record<string, unknown> = {}) => ({
  id: "0190f3a2-0000-7000-8000-000000000002",
  time: "2026-11-02T12:00:00Z",
  received_at: "2026-11-02T12:00:01Z",
  gateway_id: "0190f3a2-0000-7000-8000-0000000000aa",
  type: "gateway_request",
  app: "crm-bot",
  storage,
  threats: ["DM-46"],
  stream: false,
  non_text_unchecked: false,
  has_content: storage !== "none",
  details: {
    decision: { action: "block", applied: ["block"], rule: "pii-block", severity: "high", trace: [] },
    findings: [
      { detector: "pii.ru", category: "pii.card", score: 0.9, start: 0, end: 16, location: "messages[0].content[1]", threat: "DM-46", source: "image", box: { x: 40, y: 60, w: 300, h: 40 } },
      { detector: "secrets", category: "secret.token", score: 0.8, start: 0, end: 8, location: "messages[0].content[1]", threat: "DM-46", source: "image", box: { x: 40, y: 120, w: 200, h: 30 } },
      { detector: "pii.ru", category: "pii.phone", score: 0.7, start: 0, end: 8, location: "messages[0].content[0]", threat: "DM-01", source: "user" },
    ],
    media: [
      { location: "messages[0].content[1]", mode: "sync", checked: true, format: "png", width: 640, height: 480, texts: 2 },
      { location: "messages[0].content[2]", mode: "sync", checked: false, reason: "unavailable" },
    ],
    ...extra,
  },
});

let current = imageEvent("full");
afterEach(() => vi.unstubAllGlobals());
const renderCard = (canReadContent: boolean) => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify(current)))));
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <EventCard id={current.id} canReadContent={canReadContent} onClose={() => {}} />
    </QueryClientProvider>,
  );
};

describe("карточка события с изображением", () => {
  it("рамки и находки видны без права на содержимое; само изображение не показывается", async () => {
    current = imageEvent("full");
    const { container } = renderCard(false);
    expect(await screen.findByRole("heading", { name: "Изображения и рамки находок" })).toBeInTheDocument();
    const svg = screen.getByRole("img", { name: "Рамки находок на изображении messages[0].content[1]: 2" });
    expect(svg.querySelectorAll("title")).toHaveLength(2);
    expect(container.querySelector("image")).toBeNull();
    expect(screen.getByText("Показаны рамки и находки без самого изображения.")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Находки на изображении messages[0].content[1]" });
    expect(list).toHaveTextContent("1. pii.ru, pii.card, DM-46, область 300 × 40 в точке 40, 60");
    expect(list).toHaveTextContent("2. secrets, secret.token");
    // Находка в тексте пользователя на рисунок не попадает.
    expect(list).not.toHaveTextContent("pii.phone");
    expect(screen.getByText(/Формат PNG, 640 × 480 пикселей/)).toBeInTheDocument();
  });

  it("с правом на содержимое при режиме «полностью» честно сказано, что изображение сервер не хранит", async () => {
    current = imageEvent("full");
    renderCard(true);
    expect(await screen.findByText(/Само изображение сервер не сохраняет/)).toBeInTheDocument();
  });

  it("непроверенное изображение объясняется причиной и без рисунка", async () => {
    current = imageEvent("masked");
    renderCard(true);
    expect(await screen.findByText("Не проверено: анализатор изображений недоступен.")).toBeInTheDocument();
    expect(screen.getAllByRole("img")).toHaveLength(1);
  });

  it("у события без изображений раздела нет", async () => {
    current = imageEvent("full", { media: undefined, findings: [] });
    renderCard(true);
    await screen.findByRole("heading", { name: "Почему принято решение" });
    expect(screen.queryByRole("heading", { name: "Изображения и рамки находок" })).toBeNull();
  });
});

describe("фильтр по источнику находки", () => {
  it("собирается и разбирается без потерь", () => {
    const chips = [{ field: "finding_source", negate: false, values: ["image"] }];
    expect(buildFilter(chips)).toBe('finding_source = "image"');
    expect(parseFilter('finding_source = "image"')).toEqual(chips);
  });
});
