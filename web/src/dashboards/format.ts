import { displayTimezone } from "../events/format";

const int = new Intl.NumberFormat("ru-RU");
const pct = new Intl.NumberFormat("ru-RU", { style: "percent", maximumFractionDigits: 1 });

export const num = (n: number): string => int.format(n);
export const percent = (x: number): string => pct.format(x);

// Рубли из десятичной строки API: копейки, а для сумм меньше рубля — до четырёх знаков (дешёвые модели).
export function rub(s: string): string {
  const v = Number(s);
  if (!Number.isFinite(v)) return "—";
  const small = v > 0 && v < 1;
  return new Intl.NumberFormat("ru-RU", { style: "currency", currency: "RUB", minimumFractionDigits: small ? 2 : 2, maximumFractionDigits: small ? 4 : 2 }).format(v);
}

// Подпись корзины ряда в часовом поясе установки.
export function bucketLabel(iso: string, unit: string): string {
  const opts: Intl.DateTimeFormatOptions =
    unit === "day"
      ? { day: "2-digit", month: "2-digit" }
      : unit === "hour"
        ? { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }
        : { hour: "2-digit", minute: "2-digit", hour12: false };
  const tz = displayTimezone();
  try {
    return new Intl.DateTimeFormat("ru-RU", tz ? { ...opts, timeZone: tz } : opts).format(new Date(iso));
  } catch {
    return new Intl.DateTimeFormat("ru-RU", opts).format(new Date(iso));
  }
}

export const decisionTitle = new Map<string, string>([
  ["allowed", "Пропущено"],
  ["masked", "Замаскировано"],
  ["blocked", "Заблокировано"],
  ["would_block", "Заблокировало бы"],
]);

export const actionTitle = new Map<string, string>([
  ["allow", "Пропуск"],
  ["log", "Запись"],
  ["redact", "Маскирование"],
  ["pseudonymize", "Псевдонимизация"],
  ["require_approval", "Нужно подтверждение"],
  ["block", "Блокировка"],
]);

export const weekdays = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];

// Ссылка на экран «События» с фильтром: период экрана событий ближайший из доступных.
export function eventsUrl(period: string, conds: Record<string, string>, raw = ""): string {
  const r = period === "30d" || period === "7d" || period === "24h" ? period : "1h";
  const f = [
    ...Object.entries(conds).map(([k, v]) => `${k} = "${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`),
    ...(raw ? [raw] : []),
  ].join(" and ");
  const q = new URLSearchParams({ r });
  if (f) q.set("f", f);
  return `/events?${q}`;
}

// Условие фильтра событий для решения дашборда (ключи ряда decisions).
export const decisionFilter = new Map<string, string>([
  ["blocked", 'action = "block" and policy_mode = "enforce"'],
  ["would_block", 'action = "block" and policy_mode = "monitor"'],
  ["masked", 'action in ("redact", "pseudonymize")'],
  ["allowed", 'action in ("allow", "log")'],
]);
