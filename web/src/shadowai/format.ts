import type { LogFormat, ShadowCatalog, ShadowExclusion, ShadowUser } from "./api";

export const categoryTitle = new Map<string, string>([
  ["chat", "Чат"],
  ["api", "API"],
  ["code", "Код"],
  ["image", "Изображения"],
  ["search", "Поиск"],
  ["platform", "Платформа"],
]);

export const formatTitle = new Map<LogFormat, string>([
  ["csv", "CSV с заголовком"],
  ["squid", "Squid access.log"],
  ["cef", "CEF (UserGate, NGFW, ArcSight)"],
]);

export const userKindTitle = new Map<ShadowUser["kind"], string>([
  ["user", "логин"],
  ["address", "адрес"],
]);

export const exclusionKindTitle = new Map<ShadowExclusion["kind"], string>([
  ["user", "Пользователь"],
  ["service", "Сервис"],
]);

// Периоды экрана: шаг динамики — час для коротких, сутки для длинных.
export const periods = [
  { id: "24h", title: "Последние 24 часа", days: 1, step: "hour" },
  { id: "7d", title: "Последние 7 суток", days: 7, step: "hour" },
  { id: "30d", title: "Последние 30 суток", days: 30, step: "day" },
  { id: "90d", title: "Последние 90 суток", days: 90, step: "day" },
  { id: "365d", title: "Последние 365 суток", days: 365, step: "day" },
] as const;
export type PeriodId = (typeof periods)[number]["id"];

// Название сервиса по ID из каталога; нет в каталоге — сам ID.
export function serviceName(catalog: ShadowCatalog | undefined, id: string): string {
  return catalog?.services.find((s) => s.id === id)?.name ?? id;
}

// Строка фильтра событий по псевдониму пользователя (ADR-0015): значение в кавычках, с экранированием.
export function userFilter(alias: string): string {
  return `user = "${alias.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
