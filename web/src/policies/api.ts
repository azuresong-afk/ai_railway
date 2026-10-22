import { requestText } from "../api/client";
import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type PolicySummary = S["PolicySummary"];
export type Policy = S["Policy"];
export type PolicySpec = S["PolicySpec"];
export type PolicyRule = S["PolicyRule"];
export type PolicyVersion = S["PolicyVersion"];
export type PolicyDiff = S["PolicyDiff"];
export type PolicyTestRequest = S["PolicyTestRequest"];
export type PolicyTestResult = S["PolicyTestResult"];
export type NewPolicy = S["NewPolicy"];

const id = encodeURIComponent;

export const policiesApi = {
  list: (signal?: AbortSignal) => request<S["PolicyList"]>("GET", "/api/v1/policies", undefined, signal),
  get: (pid: string, signal?: AbortSignal) => request<Policy>("GET", `/api/v1/policies/${id(pid)}`, undefined, signal),
  versions: (pid: string, signal?: AbortSignal) =>
    request<S["PolicyVersionList"]>("GET", `/api/v1/policies/${id(pid)}/versions`, undefined, signal),
  diff: (pid: string, from: number, to: number, signal?: AbortSignal) =>
    request<PolicyDiff>("GET", `/api/v1/policies/${id(pid)}/diff?from=${from}&to=${to}`, undefined, signal),
  create: (b: NewPolicy) => request<Policy>("POST", "/api/v1/policies", b),
  rollback: (pid: string, version: number, baseVersion: number, comment: string) =>
    request<Policy>("POST", `/api/v1/policies/${id(pid)}/rollback`, {
      version,
      base_version: baseVersion,
      ...(comment ? { comment } : {}),
    }),
  // Экспорт и загрузка идут документом YAML, а не JSON.
  exportYaml: (pid: string, version?: number) =>
    requestText("GET", `/api/v1/policies/${id(pid)}/export${version ? `?version=${version}` : ""}`, { accept: "application/yaml" }),
  importYaml: (yaml: string, baseVersion: number | undefined, comment: string) => {
    const q = new URLSearchParams({
      ...(baseVersion ? { base_version: String(baseVersion) } : {}),
      ...(comment ? { comment } : {}),
    });
    return requestText("POST", `/api/v1/policies/import${q.size > 0 ? `?${q}` : ""}`, {
      accept: "application/json",
      body: yaml,
      contentType: "application/yaml",
    });
  },
  test: (b: PolicyTestRequest) => request<PolicyTestResult>("POST", "/api/v1/policies/test", b),
};

// Подписи причин ослабления защиты (DM-40).
export const weakeningText: Record<NonNullable<PolicyDiff["weakening_reasons"][number]["kind"]>, string> = {
  mode_monitor: "политика переведена в режим мониторинга",
  non_text_weakened: "ослаблена проверка нетекстовых данных",
  response_check_weakened: "ослаблена проверка ответа модели",
  rule_removed: "правило удалено",
  action_weakened: "действие правила смягчено",
  threshold_raised: "порог правила повышен",
  scope_narrowed: "правило применяется к меньшему числу случаев",
  detector_changed: "у правила заменён детектор",
};

export const actionText: Record<PolicyRule["action"], string> = {
  allow: "Разрешить",
  log: "Записать",
  redact: "Замаскировать",
  pseudonymize: "Заменить псевдонимом",
  block: "Заблокировать",
};
