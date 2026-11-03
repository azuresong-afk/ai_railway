import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { ApiError, type Me } from "../api/client";
import { ConfirmDialog, ErrorBanner, fieldError, FormDialog } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { formatBytes } from "../system/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { type Collection, type CollectionCard, type Exclusion, ragApi } from "./api";

const mono = "break-all font-mono text-sm";

// Исключение документа администратором (задача 5.26): индексатор получит ID в ответе на загрузку манифеста и не станет индексировать документ.
function ExcludeDialog({ slug, documentId, onClose }: { slug: string; documentId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [id, setId] = useState(documentId);
  const [reason, setReason] = useState("");
  const add = useMutation({
    mutationFn: () => ragApi.exclude(slug, { document_id: id.trim(), ...(reason.trim() ? { reason: reason.trim() } : {}) }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["rag"] });
      onClose();
    },
  });
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title="Исключение документа из индекса"
      description="Индексатор получит ID документа в ответе на загрузку манифеста и перестанет его индексировать. Документа может ещё не быть в манифесте."
    >
      <Field label="ID документа" hint="Как у индексатора, до 512 байт." {...(fieldError(add.error, "document_id") ? { error: fieldError(add.error, "document_id")! } : {})}>
        {({ id: fid, describedBy }) => <Input id={fid} aria-describedby={describedBy} className="font-mono" maxLength={512} autoComplete="off" value={id} onChange={(e) => setId(e.target.value)} />}
      </Field>
      <Field label="Причина" hint="До 500 знаков: почему документ нельзя индексировать.">
        {({ id: fid, describedBy }) => <Input id={fid} aria-describedby={describedBy} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}
      </Field>
      <ErrorBanner error={add.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={add.isPending || id.trim() === ""} onClick={() => add.mutate()}>
          Исключить документ
        </Button>
      </div>
    </FormDialog>
  );
}

function IdList({ title, total, ids, canExclude, onExclude }: { title: string; total: number; ids: string[]; canExclude: boolean; onExclude: (id: string) => void }) {
  return (
    <section aria-label={title} className="flex flex-col gap-1">
      <h3 className="text-base font-medium">
        {title}: {formatNumber(total)}
      </h3>
      {total === 0 ? (
        <p className="text-sm text-muted">Нет.</p>
      ) : (
        <>
          <ul className="flex flex-col gap-1">
            {ids.map((id) => (
              <li key={id} className="flex flex-wrap items-center gap-2">
                <span className={mono}>{id}</span>
                {canExclude && (
                  <Button variant="ghost" aria-label={`Исключить документ ${id}`} onClick={() => onExclude(id)}>
                    Исключить
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {total > ids.length && <p className="text-sm text-muted">Показаны первые {formatNumber(ids.length)} по возрастанию ID.</p>}
        </>
      )}
    </section>
  );
}

function ChangesTab({ c, canExclude, onExclude }: { c: CollectionCard; canExclude: boolean; onExclude: (id: string) => void }) {
  const d = c.diff;
  const none = d.added + d.changed + d.removed === 0;
  return (
    <Panel role="region" aria-label="Изменения документов" className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Что изменилось с предыдущей версии</h2>
      {c.version <= 1 ? (
        <p className="text-sm text-muted">Это первая загруженная версия манифеста: сравнивать пока не с чем.</p>
      ) : (
        <p className="text-sm text-muted">
          Версия {c.version} сравнивается с предыдущей{c.prev_loaded_at ? ` от ${formatAbsolute(c.prev_loaded_at)}` : ""}. Документ считается изменённым, если у него
          другой хеш или размер.
        </p>
      )}
      {c.version > 1 && none && <Banner kind="info">Документы коллекции не менялись.</Banner>}
      {c.version > 1 && !none && (
        <>
          <Banner kind="warning">
            Изменено документов: добавлено {formatNumber(d.added)}, изменено {formatNumber(d.changed)}, удалено {formatNumber(d.removed)}. Если обновления не ждали,
            проверьте источник базы знаний: подмена документов — путь к косвенной инъекции.
          </Banner>
          <IdList title="Изменённые документы" total={d.changed} ids={d.changed_ids} canExclude={canExclude} onExclude={onExclude} />
          <IdList title="Новые документы" total={d.added} ids={d.added_ids} canExclude={canExclude} onExclude={onExclude} />
          <IdList title="Пропавшие документы" total={d.removed} ids={d.removed_ids} canExclude={false} onExclude={onExclude} />
        </>
      )}
    </Panel>
  );
}

function DocumentsTab({ slug, version, canExclude, onExclude }: { slug: string; version: number; canExclude: boolean; onExclude: (id: string) => void }) {
  const q = useInfiniteQuery({
    queryKey: ["rag", "documents", slug, version],
    queryFn: ({ pageParam, signal }) => ragApi.documents(slug, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_after || undefined,
  });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Panel role="region" aria-label="Документы коллекции" className="flex flex-col gap-2">
      <h2 className="text-lg font-semibold">Документы текущей версии</h2>
      <p className="text-sm text-muted">
        Содержимого документов у сервера нет: только ID, SHA-256 и размер, которые прислал индексатор. Отметку «исключён индексатором» индексатор ставит сам, когда
        проверка до индексации вернула «исключить».
      </p>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка документов…</p>}
      {q.data && items.length === 0 && <p className="text-sm text-muted">В текущей версии манифеста документов нет.</p>}
      {items.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Документы манифеста">
            <thead>
              <tr>
                <Th>ID документа</Th>
                <Th className="text-right">Размер</Th>
                <Th>SHA-256</Th>
                <Th>Состояние</Th>
                {canExclude && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {items.map((d) => (
                <tr key={d.id}>
                  <Td className={mono}>{d.id}</Td>
                  <Td className="text-right">{formatBytes(d.size)}</Td>
                  <Td className="break-all font-mono text-xs">{d.sha256}</Td>
                  <Td>{[d.blocked ? "исключён администратором" : "", d.excluded ? "исключён индексатором" : ""].filter(Boolean).join(", ") || "индексируется"}</Td>
                  {canExclude && (
                    <Td>
                      {!d.blocked && (
                        <Button variant="ghost" aria-label={`Исключить документ ${d.id}`} onClick={() => onExclude(d.id)}>
                          Исключить
                        </Button>
                      )}
                    </Td>
                  )}
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
    </Panel>
  );
}

function ExclusionsTab({ slug, list, canManage, canUnexclude, onAdd }: { slug: string; list: Exclusion[]; canManage: boolean; canUnexclude: boolean; onAdd: () => void }) {
  const qc = useQueryClient();
  const [removing, setRemoving] = useState<Exclusion | null>(null);
  const remove = useMutation({
    mutationFn: (x: Exclusion) => ragApi.unexclude(slug, x.id),
    onSuccess: async () => {
      setRemoving(null);
      await qc.invalidateQueries({ queryKey: ["rag"] });
    },
  });
  return (
    <Panel role="region" aria-label="Исключения документов" className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">Исключённые документы</h2>
        {canManage && (
          <Button variant="primary" onClick={onAdd}>
            Исключить документ
          </Button>
        )}
      </div>
      <p className="text-sm text-muted">Документы, которые администратор запретил индексировать. Индексатор получает их список при каждой загрузке манифеста.</p>
      {list.length === 0 ? (
        <EmptyState title="Исключений нет" action={<p className="text-sm text-muted">Индексируются все документы, которые не отметил сам индексатор.</p>} />
      ) : (
        <div className="overflow-auto">
          <Table aria-label="Исключения">
            <thead>
              <tr>
                <Th>ID документа</Th>
                <Th>Причина</Th>
                <Th>Исключён</Th>
                {canUnexclude && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {list.map((x) => (
                <tr key={x.id}>
                  <Td className={mono}>{x.document_id}</Td>
                  <Td className="break-words">{x.reason || "—"}</Td>
                  <Td>
                    {formatAbsolute(x.created_at)}
                    <div className="text-xs text-muted">{x.created_by}</div>
                  </Td>
                  {canUnexclude && (
                    <Td>
                      <Button variant="ghost" aria-label={`Снять исключение ${x.document_id}`} onClick={() => setRemoving(x)}>
                        Снять исключение
                      </Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {!canUnexclude && list.length > 0 && <p className="text-sm text-muted">Снять исключение может только администратор безопасности.</p>}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => {
          if (!v) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Снять исключение документа?"
        description="Это ослабление защиты: при следующей загрузке манифеста индексатор снова сможет проиндексировать документ. Действие записывается в журнал аудита как ослабление."
        actionLabel="Снять исключение"
        busy={remove.isPending}
        error={remove.error}
        onConfirm={() => removing && remove.mutate(removing)}
      />
    </Panel>
  );
}

function CollectionView({ slug, canManage, canUnexclude, onBack }: { slug: string; canManage: boolean; canUnexclude: boolean; onBack: () => void }) {
  const q = useQuery({ queryKey: ["rag", "collection", slug], queryFn: ({ signal }) => ragApi.collection(slug, signal) });
  const [excluding, setExcluding] = useState<string | null>(null);
  const c = q.data;
  const back = (
    <div>
      <Button variant="ghost" onClick={onBack}>
        ← Все коллекции
      </Button>
    </div>
  );
  if (q.error instanceof ApiError && q.error.status === 404) {
    return (
      <div className="flex flex-col gap-3">
        {back}
        <EmptyState title="Коллекция не найдена" action={<p className="text-sm text-muted">Вернитесь к списку коллекций.</p>} />
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {back}
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка коллекции…</p>}
      {c && (
        <>
          <Panel role="region" aria-label="Карточка коллекции" className="flex flex-col gap-2">
            <h2 className="text-xl font-semibold break-all">{c.slug}</h2>
            {c.version === 0 && (
              <Banner kind="info">
                Манифест ещё не загружен: коллекция восстановлена из резервной копии вместе с исключениями администратора. Индексатор пришлёт манифест при следующем
                запуске.
              </Banner>
            )}
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
              <dt className="text-muted">Версия манифеста</dt>
              <dd>{c.version}</dd>
              <dt className="text-muted">Документов</dt>
              <dd>{formatNumber(c.documents)}</dd>
              <dt className="text-muted">Общий размер</dt>
              <dd>{formatBytes(c.size)}</dd>
              <dt className="text-muted">Исключено проверкой до индексации</dt>
              <dd>{formatNumber(c.excluded)}</dd>
              <dt className="text-muted">Исключено администратором</dt>
              <dd>{formatNumber(c.exclusions)}</dd>
              <dt className="text-muted">Загружена</dt>
              <dd>{c.version === 0 ? "—" : `${formatAbsolute(c.loaded_at)}, ${c.loaded_by}`}</dd>
            </dl>
          </Panel>
          <TabBar
            label="Разделы коллекции"
            defaultValue="changes"
            tabs={[
              { value: "changes", title: "Изменения", content: <ChangesTab c={c} canExclude={canManage} onExclude={setExcluding} /> },
              { value: "documents", title: "Документы", content: <DocumentsTab slug={slug} version={c.version} canExclude={canManage} onExclude={setExcluding} /> },
              {
                value: "exclusions",
                title: "Исключения",
                content: <ExclusionsTab slug={slug} list={c.exclusion_list} canManage={canManage} canUnexclude={canUnexclude} onAdd={() => setExcluding("")} />,
              },
            ]}
          />
          {excluding !== null && <ExcludeDialog key={excluding} slug={slug} documentId={excluding} onClose={() => setExcluding(null)} />}
        </>
      )}
    </div>
  );
}

const changes = (c: Collection) => (c.version > 1 ? c.diff.added + c.diff.changed + c.diff.removed : 0);

function CollectionList({ onOpen }: { onOpen: (slug: string) => void }) {
  const q = useQuery({ queryKey: ["rag", "collections"], queryFn: ({ signal }) => ragApi.collections(signal) });
  const items = q.data?.items ?? [];
  return (
    <div className="flex flex-col gap-4">
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка коллекций…</p>}
      {q.data && items.length === 0 && (
        <EmptyState
          title="Коллекций RAG пока нет"
          action={<p className="text-sm text-muted">Коллекция появляется, когда индексатор впервые отправляет манифест документов. Как подключить индексатор — в руководстве администратора.</p>}
        />
      )}
      {items.length > 0 && (
        <Panel role="region" aria-label="Коллекции" className="flex flex-col gap-2">
          <div className="overflow-auto">
            <Table aria-label="Коллекции RAG">
              <thead>
                <tr>
                  <Th>Коллекция</Th>
                  <Th className="text-right">Версия</Th>
                  <Th className="text-right">Документов</Th>
                  <Th className="text-right">Размер</Th>
                  <Th className="text-right">Исключено</Th>
                  <Th>Изменения в последней версии</Th>
                  <Th>Загружена</Th>
                  <Th>Действия</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((c) => (
                  <tr key={c.slug}>
                    <Td className="break-all">{c.slug}</Td>
                    <Td className="text-right">{c.version === 0 ? "нет манифеста" : c.version}</Td>
                    <Td className="text-right">{formatNumber(c.documents)}</Td>
                    <Td className="text-right">{formatBytes(c.size)}</Td>
                    <Td className="text-right" title="Исключено администратором и отмечено индексатором">
                      {formatNumber(c.exclusions)} / {formatNumber(c.excluded)}
                    </Td>
                    <Td>
                      {c.version <= 1
                        ? "—"
                        : changes(c) === 0
                          ? "не менялись"
                          : `добавлено ${formatNumber(c.diff.added)}, изменено ${formatNumber(c.diff.changed)}, удалено ${formatNumber(c.diff.removed)}`}
                    </Td>
                    <Td>{c.version === 0 ? "—" : formatAbsolute(c.loaded_at)}</Td>
                    <Td>
                      <Button variant="ghost" aria-label={`Открыть коллекцию ${c.slug}`} onClick={() => onOpen(c.slug)}>
                        Открыть
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
          <p className="text-sm text-muted">
            В колонке «Исключено»: исключения администратора / отметки индексатора. Предел — {formatNumber(q.data!.limits.collections)} коллекций и{" "}
            {formatNumber(q.data!.limits.documents)} документов в манифесте.
          </p>
        </Panel>
      )}
    </div>
  );
}

// Экран «Коллекции RAG» (ТЗ 5.12, DM-30; задача 5.26): манифесты хешей документов, изменения между версиями, исключения.
// Консоль скрывает кнопки без rag.manage и снятие исключения без права безопасности rag.unexclude; права проверяет сервер.
export function RagScreen({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams();
  const slug = params.get("c");
  const canManage = me.permissions.includes("rag.manage");
  const canUnexclude = me.permissions.includes("rag.unexclude");
  const open = (s: string | null) => {
    const next = new URLSearchParams(params);
    if (s) next.set("c", s);
    else next.delete("c");
    setParams(next);
  };
  return (
    <section aria-label="Коллекции RAG" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Коллекции RAG</h1>
        <p className="text-sm text-muted">
          Целостность баз знаний: сервер хранит ID, хеш и размер каждого документа, замечает подмену между загрузками и не даёт индексировать исключённые документы.
        </p>
      </div>
      {slug ? <CollectionView slug={slug} canManage={canManage} canUnexclude={canUnexclude} onBack={() => open(null)} /> : <CollectionList onOpen={open} />}
    </section>
  );
}
