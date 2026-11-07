import { download, request, upload } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Target = S["RedTeamTarget"];
export type TargetList = S["RedTeamTargetList"];
export type TargetInput = S["RedTeamTargetInput"];
export type Run = S["RedTeamRun"];
export type RunCard = S["RedTeamRunCard"];
export type Result = S["RedTeamResult"];
export type StartRun = S["RedTeamStartRun"];
export type Schedule = S["RedTeamSchedule"];
export type ScheduleInput = S["RedTeamScheduleInput"];
export type Scenarios = S["RedTeamScenarios"];
export type ScenarioInfo = S["RedTeamScenarioInfo"];
export type Verdict = Result["verdict"];

export type ReportFormat = "html" | "csv" | "xlsx";
const id = encodeURIComponent;

const reportAccept = new Map<ReportFormat, string>([
  ["html", "text/html"],
  ["csv", "text/csv"],
  ["xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
]);

// Тестирование устойчивости (ТЗ 5.13, задача 5.34): права проверяет сервер, консоль скрывает недоступное.
// Промптов атак и ответов целей API не выдаёт; выдержки ответов — только в отчёте с examples=true.
export const redteamApi = {
  targets: (signal?: AbortSignal) => request<TargetList>("GET", "/api/v1/redteam/targets", undefined, signal),
  // Цель endpoint создаётся с повторной проверкой (password или code в теле), только в сессии консоли.
  createTarget: (b: TargetInput) => request<Target>("POST", "/api/v1/redteam/targets", b),
  deleteTarget: (tid: string) => request<void>("DELETE", `/api/v1/redteam/targets/${id(tid)}`),
  scenarios: (signal?: AbortSignal) => request<Scenarios>("GET", "/api/v1/redteam/scenarios", undefined, signal),
  uploadScenarios: (file: File) => upload<Scenarios>("PUT", "/api/v1/redteam/scenarios", file, "application/octet-stream"),
  rollbackScenarios: () => request<Scenarios>("POST", "/api/v1/redteam/scenarios/rollback"),
  runs: (signal?: AbortSignal) => request<{ items: Run[] }>("GET", "/api/v1/redteam/runs?limit=50", undefined, signal),
  run: (rid: string, signal?: AbortSignal) => request<RunCard>("GET", `/api/v1/redteam/runs/${id(rid)}`, undefined, signal),
  start: (b: StartRun) => request<Run>("POST", "/api/v1/redteam/runs", b),
  cancel: (rid: string) => request<void>("POST", `/api/v1/redteam/runs/${id(rid)}/cancel`),
  // Отчёт приходит файлом: консоль только сохраняет его; сервер сам пишет выгрузку в журнал аудита.
  // С выдержками нужна причина доступа (УПД.7, задача 6.12): сервер пишет её в запись data.export.
  report: (rid: string, format: ReportFormat, examples: boolean, reason = "") => {
    const q = new URLSearchParams({ format });
    if (examples) q.set("examples", "true");
    if (reason) q.set("reason", reason);
    return download(`/api/v1/redteam/runs/${id(rid)}/report?${q}`, reportAccept.get(format) ?? "application/octet-stream");
  },
  schedules: (signal?: AbortSignal) => request<{ items: Schedule[] }>("GET", "/api/v1/redteam/schedules", undefined, signal),
  createSchedule: (b: ScheduleInput) => request<Schedule>("POST", "/api/v1/redteam/schedules", b),
  updateSchedule: (sid: string, b: ScheduleInput) => request<Schedule>("PUT", `/api/v1/redteam/schedules/${id(sid)}`, b),
  deleteSchedule: (sid: string) => request<void>("DELETE", `/api/v1/redteam/schedules/${id(sid)}`),
};

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
