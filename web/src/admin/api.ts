import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type User = S["User"];
export type UserWithPassword = S["UserWithPassword"];
export type RoleDetails = S["RoleDetails"];
export type Permission = S["Permission"];
export type AuthPolicy = S["AuthPolicy"];
export type APIToken = S["APIToken"];
export type CreatedAPIToken = S["CreatedAPIToken"];
export type NewAPIToken = S["NewAPIToken"];
export type RoleInput = Pick<S["RoleInput"], "display_name" | "description" | "mfa_required"> & {
  permissions: { permission: string; scope: "all" | "own" }[];
};
export type NewRole = RoleInput & { id: string };
export type EventRetention = S["EventRetention"];
export type SessionList = S["SessionList"];
export type AuditRecord = S["AuditRecord"];
export type AuditPage = S["AuditPage"];
export type AuditVerification = S["AuditVerification"];
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
  setRole: (uid: string, role: string) => request<S["RoleAssigned"]>("PUT", `/api/v1/users/${id(uid)}/role`, { role }),

  permissions: (signal?: AbortSignal) => request<S["PermissionList"]>("GET", "/api/v1/permissions", undefined, signal),
  roles: (signal?: AbortSignal) => request<S["RoleList"]>("GET", "/api/v1/roles", undefined, signal),
  createRole: (b: NewRole) => request<RoleDetails>("POST", "/api/v1/roles", b),
  updateRole: (rid: string, b: RoleInput) => request<RoleDetails>("PUT", `/api/v1/roles/${id(rid)}`, b),
  deleteRole: (rid: string) => request<void>("DELETE", `/api/v1/roles/${id(rid)}`),

  policy: (signal?: AbortSignal) => request<AuthPolicy>("GET", "/api/v1/auth/policy", undefined, signal),
  savePolicy: (b: AuthPolicy) => request<AuthPolicy>("PUT", "/api/v1/auth/policy", b),

  tokens: async (signal?: AbortSignal): Promise<APIToken[]> => {
    const p = await request<S["APITokenPage"]>("GET", "/api/v1/api-tokens?limit=200", undefined, signal);
    return p.items;
  },
  createToken: (b: NewAPIToken) => request<CreatedAPIToken>("POST", "/api/v1/api-tokens", b),
  revokeToken: (tid: string) => request<unknown>("DELETE", `/api/v1/api-tokens/${id(tid)}`),

  retention: (signal?: AbortSignal) => request<EventRetention>("GET", "/api/v1/events/settings", undefined, signal),
  saveRetention: (b: { metadata_days: number; content_days: number }) =>
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
