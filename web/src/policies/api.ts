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
export type PolicyImportPreview = S["PolicyImportPreview"];
export type PolicyTestRequest = S["PolicyTestRequest"];
export type PolicyTestResult = S["PolicyTestResult"];
export type NewPolicy = S["NewPolicy"];
export type PolicyException = S["PolicyException"];
export type PolicyExceptionItem = S["PolicyExceptionItem"];
export type NewPolicyException = S["NewPolicyException"];
export type PolicyExceptionExtend = S["PolicyExceptionExtend"];

// Наибольший срок нового или продлённого исключения, суток: у канарейки — 7 (3Н49 ревью 3.r4), у остальных — 365.
export const exceptionMaxDays = (detector: string | undefined) => (detector === "canary" ? 7 : 365);

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
  // Проверка загрузки без сохранения (задача 3.35): тот же разбор на сервере, различия и признак ослабления.
  // Документ — в обёртке JSON: так запрос отменяется вместе с запросом данных (signal).
  previewYaml: (yaml: string, baseVersion: number | undefined, signal?: AbortSignal) =>
    request<PolicyImportPreview>("POST", "/api/v1/policies/import?dry_run=true", { document: yaml, ...(baseVersion ? { base_version: baseVersion } : {}) }, signal),
  // Исключения версии (ТЗ 5.3, задача 3.22): добавление и продление — ослабление защиты, нужны пароль или код.
  exceptions: (pid: string, signal?: AbortSignal) =>
    request<S["PolicyExceptionList"]>("GET", `/api/v1/policies/${id(pid)}/exceptions`, undefined, signal),
  addException: (pid: string, b: NewPolicyException) => request<S["PolicyExceptionChange"]>("POST", `/api/v1/policies/${id(pid)}/exceptions`, b),
  extendException: (pid: string, exc: string, b: PolicyExceptionExtend) =>
    request<S["PolicyExceptionChange"]>("POST", `/api/v1/policies/${id(pid)}/exceptions/${id(exc)}/extend`, b),
  deleteException: (pid: string, exc: string, baseVersion: number, comment: string) => {
    const q = new URLSearchParams({ base_version: String(baseVersion), ...(comment ? { comment } : {}) });
    return request<S["PolicyExceptionChange"]>("DELETE", `/api/v1/policies/${id(pid)}/exceptions/${id(exc)}?${q}`);
  },
  // Сохранение новой версии из редактора правил (PUT /policies/{id}); ослабление — с паролем или кодом.
  update: (pid: string, baseVersion: number, spec: PolicySpec, comment: string, re: ReauthBody = {}) =>
    request<Policy>("PUT", `/api/v1/policies/${id(pid)}`, { base_version: baseVersion, spec, ...(comment ? { comment } : {}), ...re }),
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
  tools_unapproved_weakened: "смягчено действие для неодобренных инструментов или по умолчанию",
  tool_rule_added: "добавлено разрешающее правило вызовов",
  tool_action_weakened: "действие правила вызовов смягчено",
  tool_scope_widened: "правило вызовов применяется к большему числу случаев",
  tool_scope_narrowed: "ограничивающее правило вызовов применяется к меньшему числу случаев",
  tool_args_relaxed: "ослаблены ограничения аргументов",
  tool_rate_raised: "повышены лимиты вызовов",
  approval_timeout_raised: "увеличен срок ожидания подтверждения",
  tool_rule_removed: "правило вызовов удалено",
};

export const actionText: Record<PolicyRule["action"], string> = {
  allow: "Разрешить",
  log: "Записать",
  redact: "Замаскировать",
  pseudonymize: "Заменить псевдонимом",
  block: "Заблокировать",
};
