import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Provider = S["Provider"];
export type NewProvider = S["NewProvider"];
export type ProviderFields = S["ProviderFields"];

const id = encodeURIComponent;

// Права проверяет сервер, консоль только скрывает недоступное. Учётные данные только отправляются, обратно не приходят.
export const providersApi = {
  list: (signal?: AbortSignal) => request<S["ProviderList"]>("GET", "/api/v1/providers", undefined, signal),
  create: (b: NewProvider) => request<Provider>("POST", "/api/v1/providers", b),
  update: (pid: string, b: ProviderFields) => request<Provider>("PUT", `/api/v1/providers/${id(pid)}`, b),
  remove: (pid: string) => request<void>("DELETE", `/api/v1/providers/${id(pid)}`),
  setCredential: (pid: string, credential: string) => request<Provider>("PUT", `/api/v1/providers/${id(pid)}/credentials`, { credential }),
  setExternal: (pid: string, b: S["ProviderExternal"]) => request<Provider>("PUT", `/api/v1/providers/${id(pid)}/external`, b),
};
