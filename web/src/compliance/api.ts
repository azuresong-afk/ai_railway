import { request, upload } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type ComplianceOverview = S["ComplianceOverview"];
export type ComplianceItem = S["ComplianceItem"];
export type ComplianceBaseView = S["ComplianceBaseView"];
export type ComplianceMarkInput = S["ComplianceMarkInput"];
export type ComplianceEvidence = S["ComplianceEvidence"];

export interface Filters {
  source: string;
  applies: string;
}

const id = encodeURIComponent;

export const complianceApi = {
  overview: (f: Filters, signal?: AbortSignal) => {
    const q = new URLSearchParams();
    if (f.source) q.set("source", f.source);
    if (f.applies) q.set("applies", f.applies);
    const s = q.toString();
    return request<ComplianceOverview>("GET", `/api/v1/compliance${s ? `?${s}` : ""}`, undefined, signal);
  },
  base: (signal?: AbortSignal) => request<ComplianceBaseView>("GET", "/api/v1/compliance/base", undefined, signal),
  setMark: (rid: string, b: ComplianceMarkInput) => request<ComplianceItem>("PUT", `/api/v1/compliance/requirements/${id(rid)}/mark`, b),
  clearMark: (rid: string) => request<ComplianceItem>("DELETE", `/api/v1/compliance/requirements/${id(rid)}/mark`),
  // Подписанный файл базы из выпуска, до 4 МиБ.
  uploadBase: (file: File) => upload<ComplianceBaseView>("PUT", "/api/v1/compliance/base", file, "application/octet-stream"),
};

// Ссылка на отчёт «Соответствие»: файл отдаёт сервер, он же пишет выгрузку в журнал аудита.
export const complianceReportUrl = (format: "html" | "csv" | "xlsx") => `/api/v1/reports/compliance?format=${format}`;
