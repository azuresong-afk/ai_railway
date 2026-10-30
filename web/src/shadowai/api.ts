import { request, upload } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type ShadowService = S["ShadowServiceStat"];
export type ShadowUser = S["ShadowUserStat"];
export type ShadowTimeline = S["ShadowTimeline"];
export type ShadowCatalog = S["ShadowCatalog"];
export type ShadowImport = S["ShadowImport"];
export type ShadowSettings = S["ShadowSettings"];
export type ShadowExclusion = S["ShadowExclusion"];
export type ShadowExclusionInput = S["ShadowExclusionInput"];
export type ShadowSyslog = S["ShadowSyslogStats"];
export type LogFormat = ShadowImport["format"];

// Период запроса сводок: RFC 3339.
export interface Range {
  from: string;
  to: string;
}

const qs = (r: Range, extra: Record<string, string> = {}) => new URLSearchParams({ from: r.from, to: r.to, ...extra }).toString();
const id = encodeURIComponent;

export const shadowApi = {
  services: (r: Range, signal?: AbortSignal) => request<S["ShadowServiceList"]>("GET", `/api/v1/shadow-ai/services?${qs(r)}`, undefined, signal),
  users: (r: Range, service: string, signal?: AbortSignal) =>
    request<S["ShadowUserList"]>("GET", `/api/v1/shadow-ai/users?${qs(r, service ? { service } : {})}`, undefined, signal),
  timeline: (r: Range, step: ShadowTimeline["step"], signal?: AbortSignal) =>
    request<ShadowTimeline>("GET", `/api/v1/shadow-ai/timeline?${qs(r, { step })}`, undefined, signal),
  catalog: (signal?: AbortSignal) => request<ShadowCatalog>("GET", "/api/v1/shadow-ai/catalog", undefined, signal),
  imports: (signal?: AbortSignal) => request<S["ShadowImportList"]>("GET", "/api/v1/shadow-ai/imports", undefined, signal),
  settings: (signal?: AbortSignal) => request<ShadowSettings>("GET", "/api/v1/shadow-ai/settings", undefined, signal),
  exclusions: (signal?: AbortSignal) => request<S["ShadowExclusionList"]>("GET", "/api/v1/shadow-ai/exclusions", undefined, signal),
  syslog: (signal?: AbortSignal, background?: boolean) =>
    request<ShadowSyslog>("GET", "/api/v1/shadow-ai/syslog", undefined, signal, background),
  // Журнал — файлом целиком (до 256 МиБ); сжатый gzip — с compression=gzip.
  importLog: (file: File, format: LogFormat, gzip: boolean) =>
    upload<ShadowImport>(
      "POST",
      `/api/v1/shadow-ai/imports?${new URLSearchParams({ format, ...(gzip ? { compression: "gzip" } : {}) })}`,
      file,
      gzip ? "application/gzip" : "text/plain",
    ),
  uploadCatalog: (file: File) => upload<ShadowCatalog>("PUT", "/api/v1/shadow-ai/catalog", file, "application/octet-stream"),
  addExclusion: (b: ShadowExclusionInput) => request<ShadowExclusion>("POST", "/api/v1/shadow-ai/exclusions", b),
  removeExclusion: (kind: ShadowExclusion["kind"], value: string) =>
    request<void>("DELETE", `/api/v1/shadow-ai/exclusions/${id(kind)}/${id(value)}`),
};
