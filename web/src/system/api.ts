import { request } from "../api/client";
import type { components } from "../api/schema";

export type SystemStatus = components["schemas"]["SystemStatus"];
export type IntegrityCheck = components["schemas"]["IntegrityCheck"];

export const systemApi = {
  status: (signal?: AbortSignal) => request<SystemStatus>("GET", "/api/v1/system/status", undefined, signal),
  verifyIntegrity: () => request<IntegrityCheck>("POST", "/api/v1/system/integrity/verify"),
};
