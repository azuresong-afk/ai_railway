import { download, request, upload } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Overview = S["InventoryOverview"];
export type Model = S["InventoryModel"];
export type ModelCard = S["InventoryModelCard"];
export type ModelFile = S["InventoryFile"];
export type ModelUsage = S["InventoryUsage"];
export type NewModel = S["NewInventoryModel"];
export type ModelPatch = S["InventoryModelPatch"];
export type ScanReport = S["ScanReport"];
export type ChatTemplates = S["ChatTemplates"];

export interface ModelFilter {
  kind: string;
  origin: string;
  provider: string;
  q: string;
}

export const modelPageSize = 50;
const id = encodeURIComponent;

const modelQuery = (f: ModelFilter, cursor: string | undefined) => {
  const p = new URLSearchParams({ limit: String(modelPageSize) });
  if (f.kind) p.set("kind", f.kind);
  if (f.origin) p.set("origin", f.origin);
  if (f.provider) p.set("provider", f.provider);
  if (f.q) p.set("q", f.q);
  if (cursor) p.set("cursor", cursor);
  return p.toString();
};

export const inventoryApi = {
  overview: (signal?: AbortSignal) => request<Overview>("GET", "/api/v1/inventory", undefined, signal),
  models: (f: ModelFilter, cursor: string | undefined, signal?: AbortSignal) =>
    request<S["InventoryModelPage"]>("GET", `/api/v1/inventory/models?${modelQuery(f, cursor)}`, undefined, signal),
  model: (mid: string, signal?: AbortSignal) => request<ModelCard>("GET", `/api/v1/inventory/models/${id(mid)}`, undefined, signal),
  create: (b: NewModel) => request<ModelCard>("POST", "/api/v1/inventory/models", b),
  update: (mid: string, b: ModelPatch) => request<ModelCard>("PATCH", `/api/v1/inventory/models/${id(mid)}`, b),
  remove: (mid: string) => request<void>("DELETE", `/api/v1/inventory/models/${id(mid)}`),
  scanReports: (mid: string, signal?: AbortSignal) =>
    request<S["ScanReportList"]>("GET", `/api/v1/inventory/models/${id(mid)}/scan-reports`, undefined, signal),
  // Снятие запрета — ослабление защиты: пароль или код второго фактора, только в сессии консоли.
  unblock: (mid: string, reauth: S["Reauth"]) => request<ModelCard>("POST", `/api/v1/inventory/models/${id(mid)}/unblock`, reauth),
  chatTemplates: (signal?: AbortSignal) => request<ChatTemplates>("GET", "/api/v1/inventory/chat-templates", undefined, signal),
  uploadChatTemplates: (file: File) => upload<ChatTemplates>("PUT", "/api/v1/inventory/chat-templates", file, "application/octet-stream"),
  rollbackChatTemplates: () => request<ChatTemplates>("POST", "/api/v1/inventory/chat-templates/rollback"),
  // AI-BOM приходит файлом: консоль только сохраняет его.
  aibom: () => download("/api/v1/inventory/aibom", "application/vnd.cyclonedx+json"),
};
