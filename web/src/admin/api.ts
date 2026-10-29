import { request } from "../api/client";
import type { components } from "../api/schema";
import type { ReauthBody } from "./reauth";

type S = components["schemas"];
export type User = S["User"];
export type UserWithPassword = S["UserWithPassword"];
export type RoleDetails = S["RoleDetails"];
export type Permission = S["Permission"];
export type AuthPolicy = S["AuthPolicy"];
export type IdPSettings = S["IdPSettings"];
export type IdPSettingsUpdate = S["IdPSettingsUpdate"];
export type LDAPSettings = S["LDAPSettings"];
export type LDAPSettingsUpdate = S["LDAPSettingsUpdate"];
export type APIToken = S["APIToken"];
export type CreatedAPIToken = S["CreatedAPIToken"];
export type NewAPIToken = S["NewAPIToken"];
export type RoleInput = Pick<S["RoleInput"], "display_name" | "description" | "mfa_required"> & {
  permissions: { permission: string; scope: "all" | "own" }[];
};
export type NewRole = RoleInput & { id: string };
export type EventRetention = S["EventRetention"];
export type InstallSettings = S["InstallSettings"];
export type SessionList = S["SessionList"];
export type AuditRecord = S["AuditRecord"];
export type AuditPage = S["AuditPage"];
export type AuditVerification = S["AuditVerification"];
export type LicenseInfo = S["LicenseInfo"];
// Фильтр журнала аудита: коды или группы «auth.*», субъект и итог (задача 2.4a).
export type AuditFilter = { from: string; to: string; actions: string[]; actor: string; result: string };

const id = encodeURIComponent;

// Все пути — относительные; права проверяет сервер, консоль только скрывает недоступное.
export const adminApi = {
  users: async (signal?: AbortSignal): Promise<User[]> => {
    const all: User[] = [];
    let cursor: string | undefined;
    // Страницы по 200 до конца списка; учётных записей в организации немного.
    for (let i = 0; i < 50; i++) {
      const q = new URLSearchParams({ limit: "200", ...(cursor ? { cursor } : {}) });
      const p = await request<S["UserPage"]>("GET", `/api/v1/users?${q}`, undefined, signal);
      all.push(...p.items);
      if (!p.next_cursor) break;
      cursor = p.next_cursor;
    }
    return all;
  },
  createUser: (b: S["NewUser"]) => request<UserWithPassword>("POST", "/api/v1/users", b),
  deactivate: (uid: string) => request<User>("POST", `/api/v1/users/${id(uid)}/deactivate`),
  activate: (uid: string) => request<User>("POST", `/api/v1/users/${id(uid)}/activate`),
  resetPassword: (uid: string) => request<UserWithPassword>("POST", `/api/v1/users/${id(uid)}/password-reset`),
  resetMfa: (uid: string) => request<unknown>("POST", `/api/v1/users/${id(uid)}/mfa/reset`),
  sessions: (uid: string, signal?: AbortSignal) =>
    request<SessionList>("GET", `/api/v1/users/${id(uid)}/sessions`, undefined, signal),
  revokeSessions: (uid: string, revokeTokens: boolean) =>
    request<unknown>("DELETE", `/api/v1/users/${id(uid)}/sessions?revoke_api_tokens=${revokeTokens}`),
  // Смена адреса — с повторной проверкой администратора (ревью 4.r1, 4В12).
  setEmail: (uid: string, email: string, reauth: ReauthBody) => request<User>("PUT", `/api/v1/users/${id(uid)}/email`, { email, ...reauth }),
  setRole: (uid: string, role: string) => request<S["RoleAssigned"]>("PUT", `/api/v1/users/${id(uid)}/role`, { role }),

  permissions: (signal?: AbortSignal) => request<S["PermissionList"]>("GET", "/api/v1/permissions", undefined, signal),
  roles: (signal?: AbortSignal) => request<S["RoleList"]>("GET", "/api/v1/roles", undefined, signal),
  createRole: (b: NewRole) => request<RoleDetails>("POST", "/api/v1/roles", b),
  updateRole: (rid: string, b: RoleInput) => request<RoleDetails>("PUT", `/api/v1/roles/${id(rid)}`, b),
  deleteRole: (rid: string) => request<void>("DELETE", `/api/v1/roles/${id(rid)}`),

  policy: (signal?: AbortSignal) => request<AuthPolicy>("GET", "/api/v1/auth/policy", undefined, signal),
  // Ослабление настроек входа — с паролем или кодом (В24 ревью 2.r5).
  savePolicy: (b: AuthPolicy, re: ReauthBody = {}) => request<AuthPolicy>("PUT", "/api/v1/auth/policy", { ...b, ...re }),
  // Вход через внешний IdP (ADR-0025): изменение и удаление — всегда с повторной проверкой.
  idp: (signal?: AbortSignal) => request<IdPSettings>("GET", "/api/v1/auth/idp", undefined, signal),
  saveIdP: (b: IdPSettingsUpdate) => request<IdPSettings>("PUT", "/api/v1/auth/idp", b),
  deleteIdP: (re: ReauthBody) => request<void>("DELETE", "/api/v1/auth/idp", re),
  // Вход через каталог LDAP (ADR-0025, раздел 2): так же, с повторной проверкой.
  ldap: (signal?: AbortSignal) => request<LDAPSettings>("GET", "/api/v1/auth/ldap", undefined, signal),
  saveLDAP: (b: LDAPSettingsUpdate) => request<LDAPSettings>("PUT", "/api/v1/auth/ldap", b),
  deleteLDAP: (re: ReauthBody) => request<void>("DELETE", "/api/v1/auth/ldap", re),

  tokens: async (signal?: AbortSignal): Promise<APIToken[]> => {
    const p = await request<S["APITokenPage"]>("GET", "/api/v1/api-tokens?limit=200", undefined, signal);
    return p.items;
  },
  createToken: (b: NewAPIToken) => request<CreatedAPIToken>("POST", "/api/v1/api-tokens", b),
  revokeToken: (tid: string) => request<unknown>("DELETE", `/api/v1/api-tokens/${id(tid)}`),

  // Часовой пояс показа и режим хранения по умолчанию (В26 ревью 2.r5): none или full — с паролем или кодом.
  // Лицензия (ADR-0026): загрузка — только с паролем или кодом в теле.
  license: (signal?: AbortSignal) => request<LicenseInfo>("GET", "/api/v1/license", undefined, signal),
  uploadLicense: (license: string, re: { password: string } | { code: string }) =>
    request<LicenseInfo>("PUT", "/api/v1/license", { license, ...re }),

  installSettings: (signal?: AbortSignal) => request<InstallSettings>("GET", "/api/v1/system/settings", undefined, signal),
  saveInstallSettings: (b: InstallSettings, re: ReauthBody = {}) =>
    request<InstallSettings>("PUT", "/api/v1/system/settings", { ...b, ...re }),

  retention: (signal?: AbortSignal) => request<EventRetention>("GET", "/api/v1/events/settings", undefined, signal),
  saveRetention: (b: S["EventRetentionInput"]) =>
    request<EventRetention>("PUT", "/api/v1/events/settings", b),

  audit: (f: AuditFilter, cursor: string | undefined, signal?: AbortSignal) => {
    const q = new URLSearchParams({ from: f.from, to: f.to, limit: "100" });
    for (const a of f.actions) q.append("action", a);
    if (f.actor) q.set("actor", f.actor);
    if (f.result) q.set("result", f.result);
    if (cursor) q.set("cursor", cursor);
    return request<AuditPage>("GET", `/api/v1/audit?${q}`, undefined, signal);
  },
  verifyAudit: () => request<AuditVerification>("POST", "/api/v1/audit/verify"),
};
