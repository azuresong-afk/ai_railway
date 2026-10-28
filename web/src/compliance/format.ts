import type { ComplianceItem } from "./api";

export type ItemStatus = ComplianceItem["status"];

// Знак и подпись статуса: смысл не держится на цвете (ТЗ 6.7).
export const statusTitle = new Map<ItemStatus, { sign: string; title: string }>([
  ["met", { sign: "✓", title: "Выполнено" }],
  ["partial", { sign: "◐", title: "Частично" }],
  ["not_met", { sign: "✕", title: "Не выполнено" }],
  ["not_applicable", { sign: "–", title: "Не применимо" }],
  ["manual", { sign: "?", title: "Нужна отметка" }],
]);

export const appliesTitle = new Map<string, string>([
  ["gis", "ГИС"],
  ["kii", "КИИ"],
  ["ispdn", "ИСПДн"],
  ["commercial", "Коммерческие заказчики"],
]);

export const markStatuses: [string, string][] = [
  ["met", "Выполнено"],
  ["partial", "Частично"],
  ["not_met", "Не выполнено"],
  ["not_applicable", "Не применимо"],
];

export const groupTitle = new Map<string, string>([
  ["apps", "приложения и политики"],
  ["roles", "роли и вход"],
  ["audit_chain", "цепочка журнала аудита"],
  ["integrity", "контроль целостности"],
  ["alerts", "правила оповещений"],
  ["channels", "каналы уведомлений"],
]);

export const checkStatusTitle = new Map<string, string>([
  ["met", "выполнено"],
  ["partial", "частично"],
  ["not_met", "не выполнено"],
  ["not_applicable", "не применимо"],
]);

// Ссылка доказательства — только внутрь консоли.
export function evidenceTo(path: string, query?: Record<string, string>): string {
  const q = new URLSearchParams(query ?? {}).toString();
  return q ? `${path}?${q}` : path;
}

export function percentText(p: number | null | undefined): string {
  return p === null || p === undefined ? "—" : `${p} %`;
}
