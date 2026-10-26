import { describe, expect, it } from "vitest";
import { chartOption } from "./Chart";
import { heatmapOption } from "./charts";

// 3Н45 ревью 3.r3: подсказки ECharts — только текст внутри SVG, без HTML через innerHTML.
describe("опции графика", () => {
  it("подсказка всегда в режиме richText, настройки графика сохраняются", () => {
    const o = chartOption({ tooltip: { trigger: "axis" }, series: [] });
    expect(o.tooltip).toEqual({ trigger: "axis", renderMode: "richText" });
    expect(o.animation).toBe(false);
  });

  it("опции графика не возвращают HTML-подсказку", () => {
    const o = chartOption({ tooltip: { renderMode: "html" } });
    expect((o.tooltip as { renderMode: string }).renderMode).toBe("richText");
  });

  it("у графика без подсказки она тоже текстовая", () => {
    expect(chartOption({ series: [] }).tooltip).toEqual({ renderMode: "richText" });
  });

  it("тепловая карта: formatter возвращает текст", () => {
    const tip = chartOption(heatmapOption([{ weekday: 0, hour: 9, findings: 3 }])).tooltip as { formatter: (p: { value: number[] }) => string };
    expect(tip.formatter({ value: [9, 0, 3] })).toMatch(/^[^<>]*$/);
  });
});
