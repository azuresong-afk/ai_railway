import type { ReauthBody } from "../admin/reauth";
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
  // Откат, ослабляющий защиту, — с паролем или кодом (В23 ревью 2.r5).
  rollback: (pid: string, version: number, baseVersion: number, comment: string, re: ReauthBody = {}) =>
    request<Policy>("POST", `/api/v1/policies/${id(pid)}/rollback`, {
      version,
      base_version: baseVersion,
      ...(comment ? { comment } : {}),
      ...re,
    }),
  // Экспорт и загрузка идут документом YAML, а не JSON.
  exportYaml: (pid: string, version?: number) =>
    requestText("GET", `/api/v1/policies/${id(pid)}/export${version ? `?version=${version}` : ""}`, { accept: "application/yaml" }),
  // Без подтверждения — документом YAML; с паролем или кодом (версия ослабляет защиту) — в обёртке JSON (В23 ревью 2.r5).
  importYaml: async (yaml: string, baseVersion: number | undefined, comment: string, re: ReauthBody = {}): Promise<Policy> => {
    if (Object.keys(re).length > 0) {
      return request<Policy>("POST", "/api/v1/policies/import", {
        document: yaml,
        ...(baseVersion ? { base_version: baseVersion } : {}),
        ...(comment ? { comment } : {}),
        ...re,
      });
    }
    const q = new URLSearchParams({
      ...(baseVersion ? { base_version: String(baseVersion) } : {}),
      ...(comment ? { comment } : {}),
    });
    const text = await requestText("POST", `/api/v1/policies/import${q.size > 0 ? `?${q}` : ""}`, {
      accept: "application/json",
      body: yaml,
      contentType: "application/yaml",
    });
    return JSON.parse(text) as Policy;
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
  exception_added: "добавлено исключение",
  exception_extended: "продлён срок исключения",
  exception_changed: "изменено условие исключения",
};

export const actionText: Record<PolicyRule["action"], string> = {
  allow: "Разрешить",
  log: "Записать",
  redact: "Замаскировать",
  pseudonymize: "Заменить псевдонимом",
  block: "Заблокировать",
};
