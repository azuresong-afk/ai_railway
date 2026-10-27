import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Application = S["Application"];
export type NewApplication = S["NewApplication"];
export type AppKey = S["AppKey"];
export type CreatedAppKey = S["CreatedAppKey"];
export type NewAppKey = S["NewAppKey"];
export type AppKeyRotation = S["AppKeyRotation"];
export type Provider = S["Provider"];
export type PolicySummary = S["PolicySummary"];
export type ProtectionUpdate = S["ProtectionUpdate"];
export type GatewayCertificate = S["GatewayCertificate"];
export type GatewayCertificateUpload = S["GatewayCertificateUpload"];
export type PromptBaseline = S["PromptBaseline"];
export type PromptBaselineUpdate = S["PromptBaselineUpdate"];
export type Reauth = S["Reauth"];
export type UserAccess = S["UserAccess"];
export type UserAccessUpdate = S["UserAccessUpdate"];

const id = encodeURIComponent;

// Права проверяет сервер, консоль только скрывает недоступное. Владелец приложения получает свои приложения (УПД.8).
export const appsApi = {
  applications: async (signal?: AbortSignal): Promise<Application[]> => {
    const all: Application[] = [];
    let cursor: string | undefined;
    // Страницы по 200 до конца списка; приложений в организации немного.
    for (let i = 0; i < 50; i++) {
      const q = new URLSearchParams({ limit: "200", ...(cursor ? { cursor } : {}) });
      const p = await request<S["ApplicationPage"]>("GET", `/api/v1/applications?${q}`, undefined, signal);
      all.push(...p.items);
      if (!p.next_cursor) break;
      cursor = p.next_cursor;
    }
    return all;
  },
  providers: (signal?: AbortSignal) => request<S["ProviderList"]>("GET", "/api/v1/providers", undefined, signal),
  policies: (signal?: AbortSignal) => request<S["PolicyList"]>("GET", "/api/v1/policies", undefined, signal),
  create: (b: NewApplication) => request<Application>("POST", "/api/v1/applications", b),
  // Поля защиты — только через /protection (право applications.policy, В15 ревью 2.r3b).
  setProtection: (appId: string, b: ProtectionUpdate) => request<Application>("PUT", `/api/v1/applications/${id(appId)}/protection`, b),
  archive: (appId: string) => request<Application>("DELETE", `/api/v1/applications/${id(appId)}`),
  keys: (appId: string, signal?: AbortSignal) =>
    request<S["AppKeyList"]>("GET", `/api/v1/applications/${id(appId)}/keys`, undefined, signal),
  issueKey: (appId: string, b: NewAppKey) => request<CreatedAppKey>("POST", `/api/v1/applications/${id(appId)}/keys`, b),
  rotateKey: (keyId: string, b: AppKeyRotation) => request<CreatedAppKey>("POST", `/api/v1/app-keys/${id(keyId)}/rotate`, b),
  revokeKey: (keyId: string) => request<AppKey>("POST", `/api/v1/app-keys/${id(keyId)}/revoke`),
  // Сертификат заказчика для адреса шлюза (задача 3.27): один на установку; ключ сервер не возвращает.
  gatewayCert: (signal?: AbortSignal) => request<GatewayCertificate>("GET", "/api/v1/gateway-certificate", undefined, signal),
  setGatewayCert: (b: GatewayCertificateUpload) => request<GatewayCertificate>("PUT", "/api/v1/gateway-certificate", b),
  // Эталон системного промпта (задача 4.14, DM-26): текст видит и меняет только обладатель applications.policy.
  promptBaseline: (appId: string, signal?: AbortSignal) =>
    request<PromptBaseline>("GET", `/api/v1/applications/${id(appId)}/prompt-baseline`, undefined, signal),
  setPromptBaseline: (appId: string, b: PromptBaselineUpdate) =>
    request<PromptBaseline>("PUT", `/api/v1/applications/${id(appId)}/prompt-baseline`, b),
  deletePromptBaseline: (appId: string, b: Reauth) => request<void>("DELETE", `/api/v1/applications/${id(appId)}/prompt-baseline`, b),
  // Пользователь по JWT и доступ к моделям по группам (задача 4.21, DM-33): меняет только обладатель applications.policy.
  userAccess: (appId: string, signal?: AbortSignal) =>
    request<UserAccess>("GET", `/api/v1/applications/${id(appId)}/user-access`, undefined, signal),
  setUserAccess: (appId: string, b: UserAccessUpdate) => request<UserAccess>("PUT", `/api/v1/applications/${id(appId)}/user-access`, b),
};

// Список из текстового поля: разделители — перевод строки, запятая, пробел; повторы убираются.
export function splitList(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).filter((x) => x !== ""))];
}

// Пример обращения к шлюзу (ТЗ 6.4). Ключ в пример не подставляется: его берут из переменной окружения,
// чтобы он не попал в историю командной оболочки и в буфер обмена вместе с командой.
export function gatewayExample(model: string, host = "<адрес-шлюза>"): string {
  const body = JSON.stringify({ model, messages: [{ role: "user", content: "Привет" }] });
  return [
    `curl https://${host}/v1/chat/completions \\`,
    '  -H "Authorization: Bearer $AISEC_KEY" \\',
    '  -H "Content-Type: application/json" \\',
    `  -d '${body}'`,
  ].join("\n");
}

const translit = new Map(
  Object.entries({
    а: "a", б: "b", в: "v", г: "g", д: "d", е: "e", ё: "e", ж: "zh", з: "z", и: "i", й: "y", к: "k", л: "l", м: "m",
    н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u", ф: "f", х: "kh", ц: "ts", ч: "ch", ш: "sh", щ: "shch",
    ъ: "", ы: "y", ь: "", э: "e", ю: "yu", я: "ya",
  }),
);

// Предложение ID приложения по названию; пользователь его правит.
export function suggestSlug(name: string): string {
  const s = [...name.toLowerCase()].map((c) => translit.get(c) ?? c).join("");
  return s.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);
}

export const slugPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
