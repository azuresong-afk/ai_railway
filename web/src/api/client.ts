import type { components } from "./schema";

export type Me = components["schemas"]["Me"];
export type SessionState = components["schemas"]["SessionState"];
export type MFASetup = components["schemas"]["MFASetup"];
export type RecoveryCodes = components["schemas"]["RecoveryCodes"];
export type SetupStatus = components["schemas"]["SetupStatus"];
export type SetupRequest = components["schemas"]["SetupRequest"];
export type Problem = components["schemas"]["Problem"];

const csrfCookie = "__Host-aisec_csrf";

// Ошибка API: статус, код и русский текст из Problem Details.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    readonly fields: { field: string; detail: string }[] = [],
  ) {
    super(detail);
  }
}

// CSRF-токен читается из cookie (двойная отправка, Р6); других хранилищ нет.
export function csrfToken(): string {
  for (const part of document.cookie.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === csrfCookie) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}

let onUnauthorized: (() => void) | undefined;

// Обработчик 401 вне входа: консоль сбрасывает сессию и показывает вход, причину не раскрывает.
export function setUnauthorizedHandler(fn: (() => void) | undefined) {
  onUnauthorized = fn;
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) init.body = JSON.stringify(body);
  if (signal) init.signal = signal;
  const resp = await fetch(path, init);
  if (resp.ok) {
    return (resp.status === 204 ? undefined : await resp.json()) as T;
  }
  let p: Partial<Problem> = {};
  try {
    p = (await resp.json()) as Partial<Problem>;
  } catch {
    // тело не Problem Details — остаётся общий текст
  }
  if (resp.status === 401 && !path.startsWith("/api/v1/auth/login")) onUnauthorized?.();
  throw new ApiError(resp.status, p.code ?? "internal_error", p.detail ?? "Запрос не выполнен.", p.errors ?? []);
}

export const api = {
  // null — сессии нет (401).
  async me(signal?: AbortSignal): Promise<Me | null> {
    try {
      return await request<Me>("GET", "/api/v1/me", undefined, signal);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return null;
      throw e;
    }
  },
  setupStatus: (signal?: AbortSignal) => request<SetupStatus>("GET", "/api/v1/auth/setup", undefined, signal),
  setup: (b: SetupRequest) => request<unknown>("POST", "/api/v1/auth/setup", b),
  login: (login: string, password: string) => request<Me>("POST", "/api/v1/auth/login", { login, password }),
  logout: () => request<void>("POST", "/api/v1/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("POST", "/api/v1/auth/password", { current_password, new_password }),
  mfaSetup: () => request<MFASetup>("POST", "/api/v1/auth/mfa/setup", {}),
  mfaConfirm: (code: string) => request<RecoveryCodes>("POST", "/api/v1/auth/mfa/setup/confirm", { code }),
  mfaVerify: (v: { code: string } | { recovery_code: string }) => request<Me>("POST", "/api/v1/auth/mfa/verify", v),
};
