import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type ReportSchedule = S["ReportSchedule"];
export type ReportScheduleInput = S["ReportScheduleInput"];
export type ReportRun = S["ReportRun"];
export type ReportKind = "summary" | "incidents" | "pilot" | "compliance";

const id = encodeURIComponent;

export const reportKinds: [ReportKind, string][] = [
  ["summary", "Сводный отчёт"],
  ["incidents", "Отчёт по инцидентам"],
  ["pilot", "Итоги пилота"],
  ["compliance", "Соответствие требованиям"],
];

export const frequencyTitles = new Map<string, string>([
  ["daily", "Каждый день"],
  ["weekly", "Каждую неделю"],
  ["monthly", "Каждый месяц"],
]);

export const weekdayTitles = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];

// Ссылка на отчёт: файл отдаёт сервер, он же пишет выгрузку в журнал аудита до выдачи.
export function reportUrl(
  kind: ReportKind,
  format: "html" | "csv" | "xlsx",
  from: string,
  to: string,
  app: string,
  delimiter: "semicolon" | "comma" = "semicolon",
): string {
  const q = new URLSearchParams({ format });
  if (format === "csv") q.set("delimiter", delimiter);
  if (from) q.set("from", from);
  if (to) q.set("to", to);
  if (app) q.set("app", app);
  return `/api/v1/reports/${id(kind)}?${q.toString()}`;
}

// Права проверяет сервер, консоль только скрывает недоступное.
export const reportsApi = {
  schedules: (signal?: AbortSignal) => request<S["ReportScheduleList"]>("GET", "/api/v1/report-schedules", undefined, signal),
  create: (b: ReportScheduleInput) => request<ReportSchedule>("POST", "/api/v1/report-schedules", b),
  update: (sid: string, b: ReportScheduleInput) => request<ReportSchedule>("PUT", `/api/v1/report-schedules/${id(sid)}`, b),
  remove: (sid: string) => request<void>("DELETE", `/api/v1/report-schedules/${id(sid)}`),
  runs: (sid: string, signal?: AbortSignal) => request<S["ReportRunList"]>("GET", `/api/v1/report-schedules/${id(sid)}/runs`, undefined, signal),
  // Пользователи для выбора получателей: без адресов, только признак «адрес задан».
  recipients: (signal?: AbortSignal) => request<S["ReportRecipientList"]>("GET", "/api/v1/report-recipients", undefined, signal),
  // Почтовые каналы для расписания: только ID и название, без права на каналы уведомлений.
  channels: (signal?: AbortSignal) => request<S["ReportChannelList"]>("GET", "/api/v1/report-channels", undefined, signal),
};
