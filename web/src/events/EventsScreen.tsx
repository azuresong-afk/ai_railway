import { useInfiniteQuery } from "@tanstack/react-query";
import { Download, RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import type { Me } from "../api/client";
import { Button } from "../ui/Button";
import { Select } from "../ui/Field";
import { Banner, EmptyState } from "../ui/Layout";
import { Toaster } from "../ui/Toaster";
import { type CsvDelimiter, delimiterTitles, describeError, eventsApi, type Query } from "./api";
import { EventCard } from "./EventCard";
import { EventTable } from "./EventTable";
import { buildFilter, parseFilter } from "./filter";
import { chipLabel, FilterBar, periods } from "./FilterBar";
import { formatNumber } from "./format";

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Экран «События» (ТЗ 6.4, п. 4). Состояние — в адресе: период, фильтр и открытая карточка.
export function EventsScreen({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams();
  const period = periods.find((p) => p.id === params.get("r")) ?? periods[1]!;
  const filter = params.get("f") ?? "";
  const selected = params.get("event");
  const [anchor, setAnchor] = useState(() => Date.now());
  const [toast, setToast] = useState<{ title: string; text: string } | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [delimiter, setDelimiter] = useState<CsvDelimiter>("semicolon");

  const canExport = me.permissions.includes("events.export");
  const canReadContent = me.permissions.includes("events.content.read");

  const set = useCallback(
    (key: string, value: string | null) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value) next.set(key, value);
          else next.delete(key);
          return next;
        },
        { replace: key !== "event" },
      );
    },
    [setParams],
  );

  const query: Query = useMemo(
    () => ({
      from: new Date(anchor - period.ms).toISOString(),
      to: new Date(anchor).toISOString(),
      filter,
    }),
    [anchor, period.ms, filter],
  );

  const list = useInfiniteQuery({
    queryKey: ["events", query],
    queryFn: ({ pageParam, signal }) => eventsApi.list(query, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor || undefined,
  });
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const { fetchNextPage, hasNextPage, isFetchingNextPage } = list;
  const loadMore = useCallback(() => void fetchNextPage(), [fetchNextPage]);
  const chips = parseFilter(filter);

  const doExport = async (format: "csv" | "json") => {
    setExporting(true);
    setExportError(null);
    try {
      const r = await eventsApi.export(query, format, delimiter);
      save(r.blob, r.name);
      setToast({
        title: "Выгружено",
        text: r.rows === null ? `Файл ${r.name} сохранён.` : `Файл ${r.name}: ${formatNumber(r.rows)} строк, без содержимого запросов.`,
      });
    } catch (e) {
      setExportError(describeError(e, "export"));
    } finally {
      setExporting(false);
    }
  };

  const empty = list.isSuccess && rows.length === 0;

  return (
    <div className="-m-6 flex h-[calc(100%+3rem)] min-h-0">
      <section aria-label="События" className="flex min-w-0 flex-1 flex-col gap-3 p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h1 className="text-xl font-semibold">События</h1>
          <div className="flex gap-2">
            <Button onClick={() => setAnchor(Date.now())}>
              <RefreshCw size={16} aria-hidden="true" />
              Обновить
            </Button>
            {canExport && (
              <>
                <Select
                  aria-label="Разделитель CSV"
                  value={delimiter}
                  onChange={(e) => setDelimiter(e.target.value as CsvDelimiter)}
                >
                  {delimiterTitles.map(([v, t]) => (
                    <option key={v} value={v}>
                      {t}
                    </option>
                  ))}
                </Select>
                <Button disabled={exporting} onClick={() => void doExport("csv")}>
                  <Download size={16} aria-hidden="true" />
                  Выгрузить CSV
                </Button>
                <Button disabled={exporting} onClick={() => void doExport("json")}>
                  <Download size={16} aria-hidden="true" />
                  Выгрузить JSON
                </Button>
              </>
            )}
          </div>
        </div>
        <FilterBar filter={filter} onFilter={(f) => set("f", f || null)} period={period.id} onPeriod={(p) => set("r", p)} />
        {exportError && <Banner kind="error">{exportError}</Banner>}
        {list.isError && <Banner kind="error">{describeError(list.error, "list")}</Banner>}
        {list.isPending && <p className="text-sm text-muted">Загрузка событий…</p>}
        {empty && (
          <EmptyState
            title={chips && chips.length > 0 ? "По этим условиям событий за период нет" : "За выбранный период событий нет"}
            action={
              chips && chips.length > 0 ? (
                <div className="flex flex-col items-center gap-2">
                  <p className="text-sm text-muted">Попробуйте снять условие — возможно, оно отсекло всё:</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {chips.map((c) => (
                      <Button key={chipLabel(c)} onClick={() => set("f", buildFilter(chips.filter((x) => x !== c)) || null)}>
                        Снять: {chipLabel(c)}
                      </Button>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-sm text-muted">Расширьте период или подключите приложение, которое отправляет запросы через шлюз.</p>
              )
            }
          />
        )}
        {rows.length > 0 && (
          <>
            <p className="text-sm text-muted" aria-live="polite">
              Загружено {formatNumber(rows.length)} {hasNextPage ? "событий, остальные подгрузятся при прокрутке" : "событий"}.
            </p>
            <EventTable
              rows={rows}
              selected={selected}
              onSelect={(id) => set("event", id)}
              hasMore={Boolean(hasNextPage)}
              loadingMore={isFetchingNextPage}
              onLoadMore={loadMore}
            />
          </>
        )}
      </section>
      {selected && <EventCard
          key={selected}
          id={selected}
          canReadContent={canReadContent}
          rights={{ canMark: me.permissions.includes("events.mark"), canException: me.permissions.includes("policies.manage"), mfa: me.mfa?.enabled === true }}
          onClose={() => set("event", null)}
        />}
      <Toaster open={toast !== null} onOpenChange={(v) => !v && setToast(null)} title={toast?.title ?? ""}>
        {toast?.text}
      </Toaster>
    </div>
  );
}
