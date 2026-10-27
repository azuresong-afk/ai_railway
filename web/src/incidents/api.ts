import { request, requestText } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Incident = S["Incident"];
export type IncidentCard = S["IncidentCard"];
export type IncidentStatus = Incident["status"];
export type IncidentResolution = NonNullable<Incident["resolution"]>;
export type IncidentCategoryID = S["IncidentCategoryID"];
export type IncidentCategory = S["IncidentCategoryList"]["items"][number];
export type IncidentStage = IncidentCard["stages"][number]["key"];

const id = encodeURIComponent;

export interface IncidentQuery {
  status: string;
  severity: string;
  category: string;
  assignee_id: string;
  source: string;
}

// Права проверяет сервер, консоль только скрывает недоступное. Тела запросов и ответов — из api/openapi.yaml.
export const incidentsApi = {
  list: (q: IncidentQuery, cursor: string | undefined, signal?: AbortSignal) => {
    const p = new URLSearchParams({ limit: "200" });
    for (const [k, v] of Object.entries(q)) if (v) p.set(k, v);
    if (cursor) p.set("cursor", cursor);
    return request<S["IncidentPage"]>("GET", `/api/v1/incidents?${p}`, undefined, signal);
  },
  card: (iid: string, signal?: AbortSignal) => request<IncidentCard>("GET", `/api/v1/incidents/${id(iid)}`, undefined, signal),
  create: (b: S["IncidentCreate"]) => request<Incident>("POST", "/api/v1/incidents", b),
  setStatus: (iid: string, b: S["IncidentStatusUpdate"]) => request<Incident>("POST", `/api/v1/incidents/${id(iid)}/status`, b),
  assign: (iid: string, userId: string) => request<Incident>("PUT", `/api/v1/incidents/${id(iid)}/assignee`, { user_id: userId }),
  comment: (iid: string, body: string) => request<S["IncidentComment"]>("POST", `/api/v1/incidents/${id(iid)}/comments`, { body }),
  stage: (iid: string, stage: IncidentStage, note: string) =>
    request<Incident>("POST", `/api/v1/incidents/${id(iid)}/stages/${stage}`, note ? { note } : {}),
  // Выгрузка в JSON (aisec-incident/1): файл отдаёт сервер, консоль только сохраняет его как есть.
  exportJson: (iid: string) => requestText("GET", `/api/v1/incidents/${id(iid)}/export`, { accept: "application/json" }),
  categories: (signal?: AbortSignal) => request<S["IncidentCategoryList"]>("GET", "/api/v1/incident-categories", undefined, signal),
  setInstruction: (category: IncidentCategoryID, body: string, version: number) =>
    request<S["IncidentInstruction"]>("PUT", `/api/v1/incident-categories/${id(category)}`, { body, version }),
  settings: (signal?: AbortSignal) => request<S["IncidentSettings"]>("GET", "/api/v1/incident-settings", undefined, signal),
  setSettings: (b: S["IncidentSettingsUpdate"]) => request<S["IncidentSettings"]>("PUT", "/api/v1/incident-settings", b),
};
