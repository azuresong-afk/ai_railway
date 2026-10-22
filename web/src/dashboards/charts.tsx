import { useState } from "react";
import { Button } from "../ui/Button";
import { Panel, Table, Td, Th } from "../ui/Layout";
import type { DashPoint, DashPeriodInfo } from "./api";
import { Chart, type ChartProps, token } from "./Chart";
import { bucketLabel, decisionTitle, num, weekdays } from "./format";

// Карточка графика с кнопкой «Показать данные таблицей» (ТЗ 6.6): таблица — и доступность, и проверяемость.
export function ChartCard({
  title,
  option,
  label,
  head,
  rows,
  height,
  onPick,
  empty,
}: {
  title: string;
  option: ChartProps["option"];
  label: string;
  head: string[];
  rows: (string | number)[][];
  height?: number;
  onPick?: ChartProps["onPick"];
  empty?: boolean;
}) {
  const [table, setTable] = useState(false);
  return (
    <Panel className="flex min-w-0 flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-md font-semibold">{title}</h3>
        {!empty && (
          <Button variant="ghost" aria-pressed={table} onClick={() => setTable(!table)}>
            {table ? "Показать график" : "Показать данные таблицей"}
          </Button>
        )}
      </div>
      {empty ? (
        <p className="py-8 text-center text-sm text-muted">Нет данных за выбранный период.</p>
      ) : table ? (
        <div className="max-h-72 overflow-auto">
          <Table aria-label={`Данные: ${title}`}>
            <thead>
              <tr>
                {head.map((h, i) => (
                  <Th key={h} className={i > 0 ? "text-right" : ""}>
                    {h}
                  </Th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  {r.map((c, j) => (
                    <Td key={j} className={j > 0 ? "text-right" : ""}>
                      {typeof c === "number" ? num(c) : c}
                    </Td>
                  ))}
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      ) : (
        <Chart option={option} label={label} {...(height ? { height } : {})} {...(onPick ? { onPick } : {})} />
      )}
    </Panel>
  );
}

const axisText = () => ({ color: token("--c-text-muted") });
const split = () => ({ lineStyle: { color: token("--c-border") } });

// Ряд точек (bucket, key, value) → корзины по оси X и серии по ключам.
export function pivot(points: DashPoint[], unit: string) {
  const buckets = [...new Set(points.map((p) => p.bucket))].sort();
  const keys = [...new Set(points.map((p) => p.key))];
  const at = new Map(points.map((p) => [`${p.bucket}|${p.key}`, p.value]));
  return {
    buckets,
    labels: buckets.map((b) => bucketLabel(b, unit)),
    keys,
    values: (k: string) => buckets.map((b) => at.get(`${b}|${k}`) ?? 0),
  };
}

const decisionTokens = new Map([
  ["allowed", "--c-dec-allowed"],
  ["masked", "--c-dec-masked"],
  ["blocked", "--c-dec-blocked"],
  ["would_block", "--c-dec-would-block"],
]);
const decisionColor = (k: string): string => token(decisionTokens.get(k) ?? "--c-accent");

// Запросы по решениям во времени: столбцы с накоплением, цвета решений — из токенов.
export function decisionsOption(points: DashPoint[], period: DashPeriodInfo) {
  const p = pivot(points, period.unit);
  const order = ["allowed", "masked", "would_block", "blocked"].filter((k) => p.keys.includes(k));
  return {
    tooltip: { trigger: "axis" },
    legend: { data: order.map((k) => decisionTitle.get(k)), textStyle: axisText() },
    grid: { left: 48, right: 16, top: 32, bottom: 28 },
    xAxis: { type: "category", data: p.labels, axisLabel: axisText() },
    yAxis: { type: "value", axisLabel: axisText(), splitLine: split() },
    series: order.map((k) => ({
      name: decisionTitle.get(k),
      type: "bar",
      stack: "d",
      data: p.values(k),
      itemStyle: { color: decisionColor(k) },
    })),
  };
}

export function decisionsRows(points: DashPoint[], period: DashPeriodInfo): [string[], (string | number)[][]] {
  return [["Время", "Решение", "Запросов"], points.map((x) => [bucketLabel(x.bucket, period.unit), decisionTitle.get(x.key) ?? x.key, x.value])];
}

// Ряд по ключам (детекторы, строки матрицы, категории): линии.
export function linesOption(points: DashPoint[], period: DashPeriodInfo, title?: (k: string) => string) {
  const p = pivot(points, period.unit);
  return {
    tooltip: { trigger: "axis" },
    legend: { data: p.keys.map((k) => title?.(k) ?? k), type: "scroll", textStyle: axisText() },
    grid: { left: 48, right: 16, top: 40, bottom: 28 },
    xAxis: { type: "category", data: p.labels, axisLabel: axisText() },
    yAxis: { type: "value", axisLabel: axisText(), splitLine: split() },
    series: p.keys.map((k) => ({ name: title?.(k) ?? k, type: "line", showSymbol: false, data: p.values(k) })),
  };
}

export const linesRows = (points: DashPoint[], period: DashPeriodInfo, title?: (k: string) => string): [string[], (string | number)[][]] => [
  ["Время", "Показатель", "Значение"],
  points.map((x) => [bucketLabel(x.bucket, period.unit), title?.(x.key) ?? x.key, x.value]),
];

// Горизонтальные столбцы «топ».
export function barsOption(items: { key: string; value: number }[], title?: (k: string) => string) {
  const rows = [...items].reverse();
  return {
    tooltip: { trigger: "item" },
    grid: { left: 140, right: 24, top: 8, bottom: 24 },
    xAxis: { type: "value", axisLabel: axisText(), splitLine: split() },
    yAxis: { type: "category", data: rows.map((r) => title?.(r.key) ?? (r.key || "не указано")), axisLabel: { ...axisText(), width: 120, overflow: "truncate" } },
    series: [{ type: "bar", data: rows.map((r) => ({ value: r.value, name: r.key })), itemStyle: { color: token("--c-accent") } }],
  };
}

// Тепловая карта «день недели × час»: яркость — число находок.
export function heatmapOption(cells: { weekday: number; hour: number; findings: number }[]) {
  const max = Math.max(1, ...cells.map((c) => c.findings));
  return {
    tooltip: { formatter: (p: { value: number[] }) => `${weekdays[p.value[1]!]}, ${p.value[0]}:00 — ${num(p.value[2]!)}` },
    grid: { left: 36, right: 16, top: 8, bottom: 56 },
    xAxis: { type: "category", data: Array.from({ length: 24 }, (_, h) => String(h)), axisLabel: axisText() },
    yAxis: { type: "category", data: weekdays, inverse: true, axisLabel: axisText() },
    visualMap: {
      min: 0,
      max,
      orient: "horizontal",
      left: "center",
      bottom: 0,
      textStyle: axisText(),
      inRange: { color: [token("--c-surface"), token("--c-sev-high")] },
    },
    series: [{ type: "heatmap", data: cells.map((c) => [c.hour, c.weekday - 1, c.findings]), itemStyle: { borderColor: token("--c-border"), borderWidth: 1 } }],
  };
}
