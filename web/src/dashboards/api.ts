import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Overview = S["DashboardOverview"];
export type Threats = S["DashboardThreats"];
export type Pii = S["DashboardPII"];
export type AppDashboard = S["DashboardApp"];
export type Consumption = S["DashboardConsumption"];
export type DashPoint = S["DashPoint"];
export type DashTop = S["DashTop"];
export type DashFeedItem = S["DashFeedItem"];
export type DashRequestRow = S["DashRequestRow"];
export type DashPeriodInfo = S["DashPeriodInfo"];

// Период дашборда: именованный (ТЗ 5.8) или произвольный (from/to в RFC 3339).
export interface Period {
  name: "15m" | "1h" | "24h" | "7d" | "30d" | "custom";
  from?: string;
  to?: string;
}

export const periodTitles: [Period["name"], string][] = [
  ["15m", "15 минут"],
  ["1h", "1 час"],
  ["24h", "24 часа"],
  ["7d", "7 суток"],
  ["30d", "30 суток"],
  ["custom", "Произвольный"],
];

export function periodParams(p: Period, feedAll = false): URLSearchParams {
  const q = new URLSearchParams();
  if (p.name === "custom") {
    if (p.from) q.set("from", p.from);
    if (p.to) q.set("to", p.to);
  } else {
    q.set("period", p.name);
  }
  if (feedAll) q.set("feed", "all");
  return q;
}

export type DashName = "overview" | "threats" | "pii" | "consumption" | "app";

function path(name: DashName, appId: string | undefined, q: URLSearchParams): string {
  const base = name === "app" ? `/api/v1/dashboards/app/${encodeURIComponent(appId ?? "")}` : `/api/v1/dashboards/${name}`;
  return `${base}?${q}`;
}

export type LiveState = "off" | "connecting" | "on" | "lost";

// Дашборд: обычный запрос и, в режиме реального времени, поток SSE (ТЗ 5.8), который подменяет данные запроса.
// Поток закрывается при выходе с экрана; при обрыве консоль показывает «связь потеряна» и обновляется по запросу.
export function useDashboard<T>(name: DashName, appId: string | undefined, period: Period, opts: { live: boolean; feedAll?: boolean }) {
  const qc = useQueryClient();
  const q = periodParams(period, opts.feedAll);
  const key = ["dash", name, appId ?? "", q.toString()];
  const enabled = name !== "app" || Boolean(appId);
  const query = useQuery({ queryKey: key, queryFn: ({ signal }) => request<T>("GET", path(name, appId, q), undefined, signal), enabled, staleTime: 5_000 });
  const [live, setLive] = useState<LiveState>("connecting");
  const qs = q.toString();
  const keyStr = JSON.stringify(key);
  useEffect(() => {
    if (!opts.live || !enabled) return;
    const sq = new URLSearchParams(qs);
    sq.set("dashboard", name);
    if (appId) sq.set("app_id", appId);
    const es = new EventSource(`/api/v1/dashboards/stream?${sq}`);
    es.onopen = () => setLive("on");
    es.addEventListener("snapshot", (e) => {
      try {
        qc.setQueryData(JSON.parse(keyStr) as unknown[], JSON.parse((e as MessageEvent<string>).data) as T);
        setLive("on");
      } catch {
        setLive("lost");
      }
    });
    es.onerror = () => {
      // CLOSED — сервер отказал (выход, лимит потоков, права): автоповтор браузера не сработает.
      setLive(es.readyState === EventSource.CLOSED ? "lost" : "connecting");
    };
    return () => es.close();
  }, [opts.live, enabled, name, appId, qs, keyStr, qc]);
  // Без режима реального времени поток не нужен: состояние «выключено» выводится, а не хранится.
  return { ...query, live: opts.live && enabled ? live : ("off" as LiveState) };
}

// Что требует внимания на «Обзоре»: критические оповещения, незакрытые инциденты и шлюзы не в сети.
// Каждый источник читается только при наличии права; сервер проверяет его заново.
export function useAttention(perms: string[]) {
  const has = (p: string) => perms.includes(p);
  const alerts = useQuery({
    queryKey: ["dash", "attention", "alerts"],
    queryFn: ({ signal }) => request<components["schemas"]["AlertPage"]>("GET", "/api/v1/alerts?status=new&severity=critical&limit=5", undefined, signal),
    enabled: has("alerts.read"),
    staleTime: 15_000,
  });
  const incidents = useQuery({
    queryKey: ["dash", "attention", "incidents"],
    queryFn: ({ signal }) => request<components["schemas"]["IncidentPage"]>("GET", "/api/v1/incidents?status=open&severity=critical&limit=5", undefined, signal),
    enabled: has("incidents.read"),
    staleTime: 15_000,
  });
  const gateways = useQuery({
    queryKey: ["dash", "attention", "gateways"],
    queryFn: ({ signal }) => request<components["schemas"]["SystemStatus"]>("GET", "/api/v1/system/status", undefined, signal),
    enabled: has("system.read"),
    staleTime: 15_000,
  });
  return { alerts, incidents, gateways };
}
