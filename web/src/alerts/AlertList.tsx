import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { EmptyState } from "../ui/Layout";
import { alertsApi } from "./api";
import { AlertCardPanel } from "./AlertCardPanel";
import { kindText, severityOrder, severityTitle, statusText } from "./format";

const periods = [
  { id: "all", title: "За всё время", ms: 0 },
  { id: "24h", title: "Последние 24 часа", ms: 86_400_000 },
  { id: "7d", title: "Последние 7 суток", ms: 7 * 86_400_000 },
  { id: "30d", title: "Последние 30 суток", ms: 30 * 86_400_000 },
];
const cols = "grid grid-cols-[9rem_8rem_minmax(12rem,1fr)_12rem_5rem_9rem]";

// Список оповещений (ТЗ 6.4): фильтры по статусу, серьёзности, правилу и периоду; таблица виртуализирована.
// Период в API оповещений не предусмотрен, он применяется к уже загруженным страницам (вопрос записан в stage-3.md).
export function AlertList({ me }: { me: Me }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [period, setPeriod] = useState("all");
  const [selected, setSelected] = useState<string>();
  const canRules = me.permissions.includes("alert_rules.read");
  const query = { status, severity, rule_id: ruleId };

  const rules = useQuery({ queryKey: ["alerts", "rules"], queryFn: ({ signal }) => alertsApi.rules(signal), enabled: canRules });
  const list = useInfiniteQuery({
    queryKey: ["alerts", "list", query],
    queryFn: ({ pageParam, signal }) => alertsApi.list(query, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor || undefined,
  });
  const [now] = useState(() => Date.now());
  const ms = periods.find((p) => p.id === period)?.ms ?? 0;
  const all = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const rows = useMemo(() => (ms === 0 ? all : all.filter((a) => now - Date.parse(a.last_triggered_at) <= ms)), [all, ms, now]);

  const scroller = useRef<HTMLDivElement>(null);
  // Известное ограничение TanStack Virtual: результат хука нельзя мемоизировать; таблица рисует только видимые строки.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virt = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => 40, overscan: 10 });
  const items = virt.getVirtualItems();
  const last = items[items.length - 1];
  const { fetchNextPage, hasNextPage, isFetchingNextPage } = list;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);
  useEffect(() => {
    if (last && last.index >= rows.length - 20 && hasNextPage && !isFetchingNextPage) loadMore();
  }, [last, rows.length, hasNextPage, isFetchingNextPage, loadMore]);
  // Фильтр по загруженному мог скрыть всё, а страницы ещё есть: догружаем, чтобы не показать пустоту зря.
  useEffect(() => {
    if (rows.length === 0 && ms > 0 && hasNextPage && !isFetchingNextPage) loadMore();
  }, [rows.length, ms, hasNextPage, isFetchingNextPage, loadMore]);

  const empty = list.isSuccess && rows.length === 0 && !hasNextPage;
  const filtered = status !== "" || severity !== "" || ruleId !== "" || ms > 0;

  return (
    <div className="flex min-h-0 gap-4">
      <div className="flex min-w-0 flex-1 flex-col gap-3">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Статус">
            {({ id }) => (
              <Select id={id} value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">Любой</option>
                <option value="new">{statusText.new}</option>
                <option value="in_progress">{statusText.in_progress}</option>
                <option value="closed">{statusText.closed}</option>
              </Select>
            )}
          </Field>
          <Field label="Серьёзность">
            {({ id }) => (
              <Select id={id} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">Любая</option>
                {severityOrder.map((s) => (
                  <option key={s} value={s}>
                    {severityTitle.get(s)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {canRules && (
            <Field label="Правило">
              {({ id }) => (
                <Select id={id} value={ruleId} onChange={(e) => setRuleId(e.target.value)}>
                  <option value="">Любое</option>
                  {(rules.data?.items ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          <Field label="Период">
            {({ id }) => (
              <Select id={id} value={period} onChange={(e) => setPeriod(e.target.value)}>
                {periods.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.title}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {filtered && (
            <Button
              onClick={() => {
                setStatus("");
                setSeverity("");
                setRuleId("");
                setPeriod("all");
              }}
            >
              Сбросить фильтры
            </Button>
          )}
        </div>
        <ErrorBanner error={list.error} />
        {list.isPending && <p className="text-sm text-muted">Загрузка оповещений…</p>}
        {empty && (
          <EmptyState
            title={filtered ? "По этим условиям оповещений нет" : "Оповещений пока нет"}
            action={<p className="text-sm text-muted">{filtered ? "Измените или сбросьте фильтры." : "Они появятся, когда сработает правило."}</p>}
          />
        )}
        {rows.length > 0 && (
          <div className="rounded-panel border border-line">
            <div role="row" className={`${cols} border-b border-line-strong px-3 py-1.5 text-sm font-medium text-muted`}>
              <span>Время</span>
              <span>Серьёзность</span>
              <span>Оповещение</span>
              <span>Правило</span>
              <span>Раз</span>
              <span>Статус</span>
            </div>
            <div ref={scroller} className="max-h-[60vh] overflow-auto" data-testid="alerts-scroll">
              <div role="table" aria-label="Оповещения" aria-rowcount={rows.length} style={{ height: virt.getTotalSize(), position: "relative" }}>
                {items.map((vi) => {
                  const a = rows[vi.index]!;
                  return (
                    <div
                      key={a.id}
                      role="row"
                      aria-selected={a.id === selected}
                      style={{ position: "absolute", top: 0, left: 0, width: "100%", height: vi.size, transform: `translateY(${vi.start}px)` }}
                      className={`${cols} items-center border-b border-line px-3 hover:bg-surface-hover ${a.id === selected ? "bg-surface-hover" : ""}`}
                    >
                      <time dateTime={a.last_triggered_at} className="text-sm whitespace-nowrap">
                        {formatAbsolute(a.last_triggered_at)}
                      </time>
                      <span>
                        <SeverityBadge level={a.severity} />
                      </span>
                      <button
                        type="button"
                        onClick={() => setSelected(a.id)}
                        aria-label={`Открыть оповещение: ${a.title}`}
                        className="truncate text-left underline-offset-2 hover:underline"
                      >
                        {a.title}
                      </button>
                      <span className="truncate text-sm text-muted" title={a.rule_name}>
                        {kindText.get(a.kind) ?? a.kind}: {a.rule_name}
                      </span>
                      <span className="text-right tabular-nums">{a.count}</span>
                      <span className="pl-3 text-sm">{statusText[a.status]}</span>
                    </div>
                  );
                })}
              </div>
            </div>
            {isFetchingNextPage && <p className="p-2 text-sm text-muted">Загрузка следующих оповещений…</p>}
          </div>
        )}
      </div>
      {selected && <AlertCardPanel key={selected} id={selected} me={me} onClose={() => setSelected(undefined)} />}
    </div>
  );
}
