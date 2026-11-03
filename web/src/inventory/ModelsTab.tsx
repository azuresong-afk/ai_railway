import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { inventoryApi, type ModelFilter } from "./api";
import { kindTitle, originTitle } from "./format";
import { ModelStatus } from "./Marks";
import { ModelCardView } from "./ModelCard";
import { ModelDialog } from "./ModelDialog";

const emptyFilter: ModelFilter = { kind: "", origin: "", provider: "", q: "" };

// Вкладка «Модели»: список с отбором и карточка выбранной модели (адрес ?model=ID — карточку можно отправить коллеге).
export function ModelsTab({ canManage, canUnblock, mfa }: { canManage: boolean; canUnblock: boolean; mfa: boolean }) {
  const [params, setParams] = useSearchParams();
  const selected = params.get("model");
  if (selected) {
    return (
      <ModelCardView
        id={selected}
        canManage={canManage}
        canUnblock={canUnblock}
        mfa={mfa}
        onBack={() => {
          const next = new URLSearchParams(params);
          next.delete("model");
          setParams(next);
        }}
      />
    );
  }
  return (
    <ModelList
      canManage={canManage}
      onOpen={(id) => {
        const next = new URLSearchParams(params);
        next.set("model", id);
        setParams(next);
      }}
    />
  );
}

function ModelList({ canManage, onOpen }: { canManage: boolean; onOpen: (id: string) => void }) {
  const [draft, setDraft] = useState<ModelFilter>(emptyFilter);
  const [filter, setFilter] = useState<ModelFilter>(emptyFilter);
  const [adding, setAdding] = useState(false);
  // Провайдеры для отбора и для формы добавления — из сводки реестра (тот же запрос, что на первой вкладке).
  const overview = useQuery({ queryKey: ["inventory", "overview"], queryFn: ({ signal }) => inventoryApi.overview(signal) });
  const q = useInfiniteQuery({
    queryKey: ["inventory", "models", filter],
    queryFn: ({ pageParam, signal }) => inventoryApi.models(filter, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  const providers = overview.data?.providers ?? [];
  const filtered = filter.kind !== "" || filter.origin !== "" || filter.provider !== "" || filter.q !== "";

  return (
    <div className="flex flex-col gap-4">
      <Panel role="region" aria-label="Отбор моделей" className="flex flex-wrap items-end gap-3">
        <Field label="Вид">
          {({ id }) => (
            <Select id={id} value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })}>
              <option value="">Все</option>
              <option value="provider">{kindTitle.get("provider")}</option>
              <option value="customer">{kindTitle.get("customer")}</option>
            </Select>
          )}
        </Field>
        <Field label="Происхождение">
          {({ id }) => (
            <Select id={id} value={draft.origin} onChange={(e) => setDraft({ ...draft, origin: e.target.value })}>
              <option value="">Любое</option>
              <option value="traffic">{originTitle.get("traffic")}</option>
              <option value="manual">{originTitle.get("manual")}</option>
            </Select>
          )}
        </Field>
        <Field label="Провайдер">
          {({ id }) => (
            <Select id={id} value={draft.provider} onChange={(e) => setDraft({ ...draft, provider: e.target.value })}>
              <option value="">Все</option>
              {providers.map((p) => (
                <option key={p.id} value={p.slug}>
                  {p.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Имя или название">
          {({ id }) => <Input id={id} maxLength={256} value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />}
        </Field>
        <Button onClick={() => setFilter({ ...draft, q: draft.q.trim() })}>Применить отбор</Button>
        {filtered && (
          <Button
            variant="ghost"
            onClick={() => {
              setDraft(emptyFilter);
              setFilter(emptyFilter);
            }}
          >
            Сбросить отбор
          </Button>
        )}
        {canManage && (
          <Button variant="primary" className="ml-auto" onClick={() => setAdding(true)}>
            Добавить модель
          </Button>
        )}
      </Panel>

      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка моделей…</p>}
      {q.data && items.length === 0 && (
        <EmptyState
          title={filtered ? "По отбору моделей нет" : "Моделей в реестре пока нет"}
          action={
            <p className="text-sm text-muted">
              {filtered
                ? "Измените отбор или сбросьте его."
                : "Модели появляются сами, когда приложения начинают их вызывать через шлюз. Модель заказчика, которой нет в трафике, добавьте вручную."}
            </p>
          }
        />
      )}
      {items.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Модели реестра">
            <thead>
              <tr>
                <Th>Модель</Th>
                <Th>Вид</Th>
                <Th>Провайдер</Th>
                <Th>Происхождение</Th>
                <Th>Состояние</Th>
                <Th className="text-right">Файлов</Th>
                <Th>Последний раз в трафике</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => (
                <tr key={m.id}>
                  <Td className="break-words">
                    {m.title || m.name}
                    {m.title && <div className="text-xs text-muted">{m.name}</div>}
                    {m.version && <div className="text-xs text-muted">версия {m.version}</div>}
                  </Td>
                  <Td>{kindTitle.get(m.kind)}</Td>
                  <Td>{providers.find((p) => p.slug === m.provider)?.name ?? (m.provider || "—")}</Td>
                  <Td>{originTitle.get(m.origin)}</Td>
                  <Td>
                    <ModelStatus status={m.status} />
                  </Td>
                  <Td className="text-right">{formatNumber(m.file_count)}</Td>
                  <Td>{m.last_seen ? formatAbsolute(m.last_seen) : "—"}</Td>
                  <Td>
                    <Button variant="ghost" aria-label={`Открыть карточку модели ${m.name}`} onClick={() => onOpen(m.id)}>
                      Открыть карточку
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {q.hasNextPage && (
        <div>
          <Button disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
            Показать ещё
          </Button>
        </div>
      )}
      {adding && <ModelDialog mode="create" providers={providers} onClose={() => setAdding(false)} onDone={onOpen} />}
    </div>
  );
}
