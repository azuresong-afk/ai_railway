import { columnVisibilityFeature, tableFeatures, useTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";
import { SeverityBadge } from "../ui/Badge";
import { Check } from "../ui/Field";
import type { Severity } from "../ui/icons";
import type { Event } from "./api";
import { formatAbsolute, formatRelative } from "./format";
import { valueTitle } from "./filter";

const features = tableFeatures({ columnVisibilityFeature });

const severities = new Set<string>(["critical", "high", "medium", "low", "info"]);
const dash = "—";

const spec: { id: string; header: string; accessorFn: (e: Event) => string }[] = [
  { id: "type", header: "Тип", accessorFn: (e) => valueTitle("type", e.type) },
  { id: "app", header: "Приложение", accessorFn: (e) => e.app || dash },
  { id: "action", header: "Действие", accessorFn: (e) => e.action || dash },
  { id: "severity", header: "Серьёзность", accessorFn: (e) => e.severity ?? "" },
  { id: "threats", header: "Угрозы", accessorFn: (e) => (e.threats.length > 0 ? e.threats.join(", ") : dash) },
  { id: "model", header: "Модель", accessorFn: (e) => e.model || dash },
  { id: "provider", header: "Провайдер", accessorFn: (e) => e.provider || dash },
  { id: "policy_mode", header: "Режим", accessorFn: (e) => (e.policy_mode ? valueTitle("policy_mode", e.policy_mode) : dash) },
  { id: "storage", header: "Хранение", accessorFn: (e) => valueTitle("storage", e.storage) },
  { id: "user", header: "Пользователь", accessorFn: (e) => e.user || dash },
  { id: "gateway", header: "Шлюз", accessorFn: (e) => e.gateway_id },
];

// Значения ячеек берутся напрямую из события: модель строк таблицы для сотен тысяч записей не строится.
const cellOf = new Map(spec.map((c) => [c.id, c.accessorFn]));

// Колонки, скрытые по умолчанию; время закреплено слева и не скрывается.
const hiddenByDefault = { provider: false, storage: false, user: false, gateway: false };

function useNow(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function EventTable({
  rows,
  selected,
  onSelect,
  hasMore,
  loadingMore,
  onLoadMore,
}: {
  rows: Event[];
  selected: string | null;
  onSelect: (id: string) => void;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
}) {
  const now = useNow();
  const scroller = useRef<HTMLDivElement>(null);
  const [visibility, setVisibility] = useState<Record<string, boolean>>(hiddenByDefault);
  const data = useMemo(() => rows, [rows]);
  const table = useTable({
    features,
    columns: spec,
    data,
    state: { columnVisibility: visibility },
    onColumnVisibilityChange: (u) => setVisibility((v) => (typeof u === "function" ? u(v) : u)),
  });
  const cols = table.getVisibleLeafColumns();

  // Известное ограничение TanStack Virtual: правило React Compiler не знает, что мемоизировать результат хука нельзя;
  // компонент от этого просто не оптимизируется, а таблица отображает только видимые строки.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 36,
    overscan: 12,
  });
  const items = virt.getVirtualItems();
  const last = items[items.length - 1];
  // Подгрузка следующей страницы, когда прокрутка подошла к концу загруженного.
  useEffect(() => {
    if (last && last.index >= rows.length - 20 && hasMore && !loadingMore) onLoadMore();
  }, [last, rows.length, hasMore, loadingMore, onLoadMore]);

  const top = items[0]?.start ?? 0;
  const bottom = items.length > 0 ? virt.getTotalSize() - (last?.end ?? 0) : 0;
  const th = "sticky top-0 z-10 border-b border-line-strong bg-surface px-3 py-1.5 text-left text-sm font-medium whitespace-nowrap text-muted";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <details className="text-sm">
        <summary className="cursor-pointer text-muted">Колонки таблицы</summary>
        <div className="mt-2 flex flex-wrap gap-x-5 gap-y-2">
          {table.getAllLeafColumns().map((c) => (
            <Check
              key={c.id}
              label={String(c.columnDef.header)}
              checked={c.getIsVisible()}
              onCheckedChange={(v) => c.toggleVisibility(v)}
            />
          ))}
        </div>
      </details>
      <div ref={scroller} className="min-h-0 flex-1 overflow-auto rounded-panel border border-line" data-testid="events-scroll">
        <table className="w-full border-collapse text-base" aria-rowcount={rows.length}>
          <thead>
            <tr>
              <th scope="col" className={`${th} left-0 z-20`}>
                Время
              </th>
              {cols.map((c) => (
                <th key={c.id} scope="col" className={th}>
                  {String(c.columnDef.header)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {top > 0 && (
              <tr aria-hidden="true">
                <td colSpan={cols.length + 1} style={{ height: top, padding: 0 }} />
              </tr>
            )}
            {items.map((vi) => {
              const ev = rows[vi.index]!;
              const on = ev.id === selected;
              return (
                <tr
                  key={ev.id}
                  ref={virt.measureElement}
                  data-index={vi.index}
                  aria-rowindex={vi.index + 2}
                  aria-selected={on}
                  className={`border-b border-line hover:bg-surface-hover ${on ? "bg-surface-hover" : ""}`}
                >
                  <td className="sticky left-0 z-10 h-[var(--row-h)] bg-inherit px-3 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => onSelect(ev.id)}
                      title={formatAbsolute(ev.time)}
                      aria-label={`Открыть событие от ${formatAbsolute(ev.time)}`}
                      className="h-full w-full text-left underline-offset-2 hover:underline"
                    >
                      <time dateTime={ev.time}>{formatRelative(ev.time, now)}</time>
                    </button>
                  </td>
                  {cols.map((c) => {
                    const v = cellOf.get(c.id)?.(ev) ?? "";
                    return (
                      <td key={c.id} className="h-[var(--row-h)] px-3 whitespace-nowrap">
                        {c.id === "severity" && severities.has(v) ? <SeverityBadge level={v as Severity} /> : v || dash}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
            {bottom > 0 && (
              <tr aria-hidden="true">
                <td colSpan={cols.length + 1} style={{ height: bottom, padding: 0 }} />
              </tr>
            )}
          </tbody>
        </table>
        {loadingMore && <p className="p-2 text-sm text-muted">Загрузка следующих событий…</p>}
      </div>
    </div>
  );
}
