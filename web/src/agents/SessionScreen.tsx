import { useInfiniteQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link, useParams } from "react-router";
import type { Me } from "../api/client";
import { type Event, eventsApi, describeError } from "../events/api";
import { buildFilter, valueTitle } from "../events/filter";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Banner, EmptyState, Panel } from "../ui/Layout";

// Допустимый вид псевдонима сессии (ADR-0023): другое значение в запрос не уходит.
export const sessionIdRe = /^[A-Za-z0-9._:-]{1,128}$/;
const types = ["gateway_request", "check", "agent_tool_call", "agent_mcp"];
const day = 86_400_000;

const rec = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown): string => (typeof v === "string" ? v : "");

// Что произошло в событии — одной строкой, из служебных полей без содержимого.
export function summarize(e: Event): string {
  const a = rec(rec(e.details).agent);
  const parts: string[] = [];
  const tool = str(a.tool);
  const server = str(a.server);
  if (tool) parts.push(server ? `${tool} · ${server}` : tool);
  else if (str(a.method)) parts.push(`${str(a.method)}${server ? ` · ${server}` : ""}`);
  else if (e.model) parts.push(e.model);
  const ap = rec(a.approval);
  if (str(ap.state)) parts.push(`подтверждение: ${str(ap.state)}`);
  if (e.action) parts.push(`действие: ${e.action}`);
  if (e.rule) parts.push(`правило: ${e.rule}`);
  return parts.join("; ") || "—";
}

// Хронология сессии агента: события четырёх типов по порядку времени (ТЗ 5.10).
export function SessionScreen({ me }: { me: Me }) {
  const { id = "" } = useParams();
  const valid = sessionIdRe.test(id);
  const allowed = me.permissions.includes("events.read");
  const filter = buildFilter([
    { field: "session", negate: false, values: [id] },
    { field: "type", negate: false, values: types },
  ]);
  const q = useInfiniteQuery({
    queryKey: ["events", "session", id],
    enabled: valid && allowed,
    queryFn: ({ pageParam, signal }) => {
      const to = Date.now();
      return eventsApi.list({ from: new Date(to - 31 * day + 60_000).toISOString(), to: new Date(to).toISOString(), filter }, pageParam, signal);
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor || undefined,
  });
  // Сервер отдаёт новые первыми; хронология читается от старых к новым.
  const rows = useMemo(() => (q.data?.pages.flatMap((p) => p.items) ?? []).slice().sort((a, b) => Date.parse(a.time) - Date.parse(b.time)), [q.data]);

  if (!allowed) return <EmptyState title="Нет доступа к событиям" action={<p className="text-sm text-muted">Хронология строится по событиям. Обратитесь к администратору.</p>} />;
  return (
    <section aria-label="Хронология сессии" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Хронология сессии</h1>
        <Link className="underline" to="/approvals">
          К подтверждениям
        </Link>
      </div>
      {!valid ? (
        <Banner kind="error">Некорректный идентификатор сессии. Откройте хронологию из карточки события или подтверждения.</Banner>
      ) : (
        <>
          <p className="font-mono text-sm break-all">{id}</p>
          {q.isError && <Banner kind="error">{describeError(q.error, "list")}</Banner>}
          {q.isPending && !q.isError && <p className="text-sm text-muted">Загрузка событий…</p>}
          {q.data && rows.length === 0 && <EmptyState title="Событий этой сессии за последние 31 день нет" action={<p className="text-sm text-muted">Возможно, срок хранения событий истёк.</p>} />}
          {rows.length > 0 && (
            <Panel className="p-0">
              <ol aria-label="События сессии" className="divide-y divide-line">
                {rows.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-3 py-2">
                    <time dateTime={e.time} className="font-mono text-sm">
                      {formatAbsolute(e.time)}
                    </time>
                    <span className="text-sm font-medium">{valueTitle("type", e.type)}</span>
                    <span className="min-w-0 flex-1 break-words">{summarize(e)}</span>
                    <Link className="underline" to={`/events?event=${encodeURIComponent(e.id)}`} aria-label={`Открыть событие ${e.id}`}>
                      Открыть событие
                    </Link>
                  </li>
                ))}
              </ol>
            </Panel>
          )}
          {q.hasNextPage && (
            <div>
              <Button disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
                Показать ещё
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
