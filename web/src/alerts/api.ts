import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Alert = S["Alert"];
export type AlertCard = S["AlertCard"];
export type AlertRule = S["AlertRule"];
export type AlertRuleInput = S["AlertRuleInput"];
export type AlertRuleUpdate = S["AlertRuleUpdate"];
export type AlertRuleState = S["AlertRuleState"];
export type AlertCondition = S["AlertCondition"];
export type AlertRecipients = S["AlertRecipients"];
export type AlertSettings = S["AlertSettings"];
export type NotifyChannel = S["NotifyChannel"];
export type NotifyChannelInput = S["NotifyChannelInput"];
export type NotifyChannelUpdate = S["NotifyChannelUpdate"];
export type NotifyDelivery = S["NotifyDelivery"];

const id = encodeURIComponent;

export interface AlertQuery {
  status: string;
  severity: string;
  rule_id: string;
}

// Права проверяет сервер, консоль только скрывает недоступное. Тела запросов и ответов — из api/openapi.yaml.
export const alertsApi = {
  list: (q: AlertQuery, cursor: string | undefined, signal?: AbortSignal) => {
    const p = new URLSearchParams({ limit: "200" });
    for (const [k, v] of Object.entries(q)) if (v) p.set(k, v);
    if (cursor) p.set("cursor", cursor);
    return request<S["AlertPage"]>("GET", `/api/v1/alerts?${p}`, undefined, signal);
  },
  card: (alertId: string, signal?: AbortSignal) => request<AlertCard>("GET", `/api/v1/alerts/${id(alertId)}`, undefined, signal),
  setStatus: (alertId: string, status: "in_progress" | "closed", comment: string) =>
    request<Alert>("POST", `/api/v1/alerts/${id(alertId)}/status`, comment ? { status, comment } : { status }),

  // Инцидент из оповещения: название, серьёзность и категория берутся из оповещения; повтор вернёт тот же инцидент.
  createIncident: (alertId: string) => request<S["Incident"]>("POST", "/api/v1/incidents", { alert_id: alertId }),

  rules: (signal?: AbortSignal) => request<S["AlertRuleList"]>("GET", "/api/v1/alert-rules", undefined, signal),
  ruleState: (ruleId: string, signal?: AbortSignal) =>
    request<AlertRuleState>("GET", `/api/v1/alert-rules/${id(ruleId)}/state`, undefined, signal),
  createRule: (b: AlertRuleInput) => request<AlertRule>("POST", "/api/v1/alert-rules", b),
  updateRule: (ruleId: string, b: AlertRuleUpdate) => request<AlertRule>("PUT", `/api/v1/alert-rules/${id(ruleId)}`, b),

  settings: (signal?: AbortSignal) => request<AlertSettings>("GET", "/api/v1/alert-settings", undefined, signal),
  setSettings: (b: S["AlertSettingsUpdate"]) => request<AlertSettings>("PUT", "/api/v1/alert-settings", b),

  channels: (signal?: AbortSignal) => request<S["NotifyChannelList"]>("GET", "/api/v1/notify-channels", undefined, signal),
  createChannel: (b: NotifyChannelInput) => request<NotifyChannel>("POST", "/api/v1/notify-channels", b),
  updateChannel: (chId: string, b: NotifyChannelUpdate) => request<NotifyChannel>("PUT", `/api/v1/notify-channels/${id(chId)}`, b),
  testChannel: (chId: string) => request<NotifyDelivery>("POST", `/api/v1/notify-channels/${id(chId)}/test`),
  deliveries: (chId: string, signal?: AbortSignal) =>
    request<S["NotifyDeliveryList"]>("GET", `/api/v1/notify-channels/${id(chId)}/deliveries?limit=50`, undefined, signal),
};
