import type { Alert } from "./api";

export const statusText = { new: "Новое", in_progress: "В работе", closed: "Закрыто" } as const;

export const kindText = new Map<string, string>([
  ["threshold", "Порог"],
  ["new", "Новое"],
  ["frequency", "Частота"],
  ["anomaly", "Аномалия"],
  ["budget", "Бюджет"],
  ["system", "Системное"],
  ["security", "Безопасность"],
]);

export const severityTitle = new Map<string, string>([
  ["critical", "Критическая"],
  ["high", "Высокая"],
  ["medium", "Средняя"],
  ["low", "Низкая"],
  ["info", "Информация"],
]);

export const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

// Поля группировки, которые понимает фильтр событий (совпадают с полями языка GET /api/v1/events).
const filterFields = new Set(["type", "app", "env", "user", "provider", "model", "source", "gateway", "action", "rule", "severity", "policy_mode"]);

const quote = (v: string) => `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

// Период экрана «События», который покрывает срабатывания оповещения; предустановки — как в панели фильтров.
export function eventsPeriod(a: Alert, now: number): "1h" | "24h" | "7d" | "30d" {
  const from = Date.parse(a.first_event_at ?? a.created_at);
  const age = now - (Number.isNaN(from) ? now : from);
  if (age <= 3_600_000) return "1h";
  if (age <= 86_400_000) return "24h";
  if (age <= 7 * 86_400_000) return "7d";
  return "30d";
}

// Ссылка на экран «События» с фильтром по значениям группировки оповещения; пустая группа — только период.
export function eventsLink(a: Alert, now: number): string {
  const conds = Object.entries(a.group)
    .filter(([k, v]) => filterFields.has(k) && v !== "")
    .map(([k, v]) => `${k} = ${quote(v)}`);
  const q = new URLSearchParams({ r: eventsPeriod(a, now) });
  if (conds.length > 0) q.set("f", conds.join(" and "));
  return `/events?${q}`;
}

export const eventLink = (eventId: string, a: Alert, now: number): string => {
  const q = new URLSearchParams({ r: eventsPeriod(a, now), event: eventId });
  return `/events?${q}`;
};
