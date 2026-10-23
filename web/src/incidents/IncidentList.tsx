import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { ErrorBanner } from "../admin/common";
import { severityOrder, severityTitle } from "../alerts/format";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Check, Field, Select } from "../ui/Field";
import { EmptyState, Table, Td, Th } from "../ui/Layout";
import { type Incident, type IncidentQuery, incidentsApi } from "./api";
import { CreateIncidentDialog, IncidentCardPanel } from "./IncidentCardPanel";
import { reactionText, sourceText, statusText } from "./format";

// Список и доска инцидентов (ТЗ 5.7). Выбранный инцидент и вид хранятся в адресе: ссылка открывает карточку.
export function IncidentList({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams();
  const selected = params.get("id") ?? undefined;
  const view = params.get("view") === "board" ? "board" : "list";
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [source, setSource] = useState("");
  const [mine, setMine] = useState(false);
  const [overdue, setOverdue] = useState(false);
  const [creating, setCreating] = useState(false);
  const canManage = me.permissions.includes("incidents.manage");

  // Доска показывает все четыре статуса сразу, поэтому фильтр по статусу к ней не применяется.
  const query: IncidentQuery = {
    status: view === "board" ? "" : status,
    severity,
    category,
    assignee_id: mine ? me.user.id : "",
    source,
  };
  const cats = useQuery({ queryKey: ["incidents", "categories"], queryFn: ({ signal }) => incidentsApi.categories(signal) });
  const list = useInfiniteQuery({
    queryKey: ["incidents", "list", query],
    queryFn: ({ pageParam, signal }) => incidentsApi.list(query, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor || undefined,
  });
  const [now] = useState(() => Date.now());
  const all = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const rows = useMemo(() => (overdue ? all.filter((i) => i.overdue) : all), [all, overdue]);
  const catTitle = (id: string) => cats.data?.items.find((c) => c.id === id)?.title ?? id;

  const setParam = (k: string, v: string | null) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (v) next.set(k, v);
        else next.delete(k);
        return next;
      },
      { replace: k !== "id" },
    );
  const open = (i: Incident) => setParam("id", i.id);

  const filtered = (view === "list" && status !== "open") || severity !== "" || category !== "" || source !== "" || mine || overdue;
  const empty = list.isSuccess && rows.length === 0 && !list.hasNextPage;

  return (
    <div className="flex min-h-0 gap-4">
      <div className="flex min-w-0 flex-1 flex-col gap-3">
        <div className="flex flex-wrap items-end gap-3">
          <div role="group" aria-label="Вид" className="flex gap-1">
            <Button variant={view === "list" ? "primary" : "secondary"} aria-pressed={view === "list"} onClick={() => setParam("view", null)}>
              Список
            </Button>
            <Button variant={view === "board" ? "primary" : "secondary"} aria-pressed={view === "board"} onClick={() => setParam("view", "board")}>
              Доска
            </Button>
          </div>
          {view === "list" && (
            <Field label="Статус">
              {({ id }) => (
                <Select id={id} value={status} onChange={(e) => setStatus(e.target.value)}>
                  <option value="open">Незакрытые</option>
                  <option value="">Любой</option>
                  {Object.entries(statusText).map(([s, t]) => (
                    <option key={s} value={s}>
                      {t}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
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
          <Field label="Категория">
            {({ id }) => (
              <Select id={id} value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="">Любая</option>
                {(cats.data?.items ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.title}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Источник">
            {({ id }) => (
              <Select id={id} value={source} onChange={(e) => setSource(e.target.value)}>
                <option value="">Любой</option>
                {[...sourceText].map(([v, t]) => (
                  <option key={v} value={v}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Check label="Назначены мне" checked={mine} onCheckedChange={setMine} />
          <Check label="Срок реакции истёк" checked={overdue} onCheckedChange={setOverdue} />
          {filtered && (
            <Button
              onClick={() => {
                setStatus("open");
                setSeverity("");
                setCategory("");
                setSource("");
                setMine(false);
                setOverdue(false);
              }}
            >
              Сбросить фильтры
            </Button>
          )}
          {canManage && (
            <Button variant="primary" className="ml-auto" onClick={() => setCreating(true)}>
              Создать инцидент
            </Button>
          )}
        </div>
        <ErrorBanner error={list.error} />
        {list.isPending && <p className="text-sm text-muted">Загрузка инцидентов…</p>}
        {empty && (
          <EmptyState
            title={filtered ? "По этим условиям инцидентов нет" : "Инцидентов пока нет"}
            action={<p className="text-sm text-muted">{filtered ? "Измените или сбросьте фильтры." : "Инцидент создаётся из оповещения или вручную."}</p>}
          />
        )}
        {rows.length > 0 && view === "list" && (
          <Table aria-label="Инциденты">
            <thead>
              <tr>
                <Th>№</Th>
                <Th>Серьёзность</Th>
                <Th>Название</Th>
                <Th>Категория</Th>
                <Th>Статус</Th>
                <Th>Срок реакции</Th>
                <Th>Создан</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} aria-selected={i.id === selected}>
                  <Td className="tabular-nums">{i.number}</Td>
                  <Td>
                    <SeverityBadge level={i.severity} />
                  </Td>
                  <Td>
                    <button type="button" className="text-left underline-offset-2 hover:underline" aria-label={`Открыть инцидент ${i.number}: ${i.title}`} onClick={() => open(i)}>
                      {i.title}
                    </button>
                  </Td>
                  <Td>{catTitle(i.category)}</Td>
                  <Td>{statusText[i.status]}</Td>
                  <Td className="text-sm">{reactionText(i, now)}</Td>
                  <Td className="text-sm whitespace-nowrap">{formatAbsolute(i.created_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {rows.length > 0 && view === "board" && (
          <div className="grid grid-cols-4 gap-3" role="group" aria-label="Доска инцидентов">
            {Object.entries(statusText).map(([s, title]) => {
              const col = rows.filter((i) => i.status === s);
              return (
                <section key={s} aria-label={`Статус: ${title}`} className="flex flex-col gap-2 rounded-panel border border-line bg-bg p-2">
                  <h2 className="text-sm font-semibold">
                    {title} <span className="font-normal text-muted">({col.length})</span>
                  </h2>
                  {col.map((i) => (
                    <button
                      key={i.id}
                      type="button"
                      aria-label={`Открыть инцидент ${i.number}: ${i.title}`}
                      onClick={() => open(i)}
                      className={`flex flex-col items-start gap-1 rounded-control border bg-surface p-2 text-left hover:bg-surface-hover ${i.id === selected ? "border-accent" : "border-line"}`}
                    >
                      <span className="text-xs text-muted">№ {i.number}</span>
                      <span className="text-sm">{i.title}</span>
                      <SeverityBadge level={i.severity} />
                      {i.overdue && <span className="text-xs font-medium">Срок реакции истёк</span>}
                    </button>
                  ))}
                </section>
              );
            })}
          </div>
        )}
        {list.hasNextPage && (
          <div>
            <Button onClick={() => void list.fetchNextPage()} disabled={list.isFetchingNextPage}>
              {list.isFetchingNextPage ? "Загрузка…" : "Показать ещё"}
            </Button>
          </div>
        )}
      </div>
      {selected && <IncidentCardPanel key={selected} id={selected} me={me} onClose={() => setParam("id", null)} onOpen={(id) => setParam("id", id)} />}
      {creating && (
        <CreateIncidentDialog
          cats={cats.data?.items ?? []}
          onClose={() => setCreating(false)}
          onCreated={(i) => {
            setCreating(false);
            open(i);
          }}
        />
      )}
    </div>
  );
}
