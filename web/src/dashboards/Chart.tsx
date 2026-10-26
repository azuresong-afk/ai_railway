import { BarChart, HeatmapChart, LineChart, PieChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

// Модульный импорт: только нужные типы графиков (ТЗ 6.6). Рисуем SVG-рендерером: он не требует
// canvas и eval, а стили задаёт через CSSOM и атрибуты оформления, которые строгий CSP (ТЗ 6.9) допускает.
echarts.use([BarChart, LineChart, PieChart, HeatmapChart, GridComponent, LegendComponent, TooltipComponent, VisualMapComponent, SVGRenderer]);

export type EChartsOption = echarts.EChartsCoreOption;

// Цвет из токена дизайн-системы (src/design/tokens.css): графики берут цвета оттуда же, что и экраны.
export function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Цвета серий: решения политики и серьёзность — из токенов, остальное — акцент и приглушённые тона.
export function palette(): string[] {
  return [
    token("--c-accent"),
    token("--c-dec-allowed"),
    token("--c-dec-masked"),
    token("--c-dec-blocked"),
    token("--c-sev-high"),
    token("--c-sev-medium"),
    token("--c-sev-info"),
  ];
}

// Общие настройки поверх опций графика. Подсказка — только текстом внутри SVG (renderMode: "richText"):
// по умолчанию ECharts строит её как HTML через innerHTML с атрибутами style, а это и нарушение
// строгого CSP (ТЗ 6.9), и точка внедрения для будущего formatter с данными (3Н45 ревью 3.r3).
// Режим ставится последним, чтобы опции графика не могли вернуть HTML.
export function chartOption(option: EChartsOption): EChartsOption {
  const tooltip = option.tooltip as Record<string, unknown> | undefined;
  return {
    animation: false,
    textStyle: { color: token("--c-text"), fontFamily: token("--ff-sans") },
    color: palette(),
    ...option,
    tooltip: { ...tooltip, renderMode: "richText" },
  };
}

export interface ChartProps {
  option: EChartsOption;
  // Подпись для экранных дикторов; обязательна: у картинки нет другого текста.
  label: string;
  height?: number;
  // Клик по элементу графика: переход к отфильтрованным событиям (ТЗ 6.6).
  onPick?: (params: { name?: string; seriesName?: string; value?: unknown; data?: unknown }) => void;
}

export function Chart({ option, label, height = 240, onPick }: ChartProps) {
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  const pick = useRef(onPick);

  useEffect(() => {
    pick.current = onPick;
  }, [onPick]);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const c = echarts.init(el, undefined, { renderer: "svg" });
    chart.current = c;
    c.on("click", (p) => pick.current?.(p as never));
    const ro = typeof ResizeObserver === "undefined" ? undefined : new ResizeObserver(() => c.resize());
    ro?.observe(el);
    return () => {
      ro?.disconnect();
      c.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption(chartOption(option), true);
  }, [option]);

  return <div ref={host} role="img" aria-label={label} style={{ height }} />;
}
