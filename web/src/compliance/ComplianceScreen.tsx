import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link } from "react-router";
import { area, ConfirmDialog, ErrorBanner, fieldError, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { type ComplianceItem, type ComplianceOverview, complianceApi, complianceReportUrl, type Filters } from "./api";
import { appliesTitle, checkStatusTitle, evidenceTo, groupTitle, markStatuses, percentText, statusTitle } from "./format";

function StatusMark({ status }: { status: ComplianceItem["status"] }) {
  const s = statusTitle.get(status)!;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-control border border-line bg-surface px-2 py-0.5 text-xs font-medium text-fg">
      <span aria-hidden="true">{s.sign}</span>
      {s.title}
    </span>
  );
}

// Ручная отметка (организационные меры): комментарий обязателен, срок пересмотра необязателен.
function MarkDialog({ item, onClose }: { item: ComplianceItem | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState(item?.mark?.status ?? "met");
  const [comment, setComment] = useState(item?.mark?.comment ?? "");
  const [document, setDocument] = useState(item?.mark?.document ?? "");
  const [reviewBy, setReviewBy] = useState(item?.mark?.review_by ?? "");
  const save = useMutation({
    mutationFn: () =>
      complianceApi.setMark(item!.id, {
        status: status as "met",
        comment: comment.trim(),
        ...(document.trim() ? { document: document.trim() } : {}),
        ...(reviewBy ? { review_by: reviewBy } : {}),
      }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["compliance"] });
      onClose();
    },
  });
  // Пункт, который вычисляют проверки, можно только объявить неприменимым.
  const onlyNA = Boolean(item) && !item!.manual;
  return (
    <FormDialog
      open={item !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Ручная отметка"
      description={item ? `${item.clause}. ${item.title}` : undefined}
    >
      <Field label="Состояние" hint={onlyNA ? "Статус этого пункта вычисляют проверки; вручную его можно только объявить неприменимым." : undefined}>
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
            {markStatuses
              .filter(([k]) => !onlyNA || k === "not_applicable")
              .map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
          </Select>
        )}
      </Field>
      <Field
        label="Комментарий"
        hint="Обязателен, до 1000 знаков: что сделано и где подтверждается. Не указывайте пароли, ключи и персональные данные."
        error={fieldError(save.error, "comment")}
      >
        {({ id, describedBy, invalid }) => (
          <textarea
            id={id}
            aria-describedby={describedBy}
            aria-invalid={invalid}
            rows={4}
            maxLength={1000}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            className={area}
          />
        )}
      </Field>
      <Field label="Документ-основание" hint="Например, «Приказ № 12 от 01.09.2026». До 300 знаков." error={fieldError(save.error, "document")}>
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} maxLength={300} value={document} onChange={(e) => setDocument(e.target.value)} />
        )}
      </Field>
      <Field label="Пересмотреть до" hint="После этой даты отметка не засчитывается. Не дальше трёх лет." error={fieldError(save.error, "review_by")}>
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} type="date" value={reviewBy} onChange={(e) => setReviewBy(e.target.value)} />
        )}
      </Field>
      <ErrorBanner error={save.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={save.isPending || comment.trim() === ""} onClick={() => save.mutate()}>
          Сохранить отметку
        </Button>
      </div>
    </FormDialog>
  );
}

// Карточка пункта: пересказ, результаты проверок словами, доказательства и отметка.
function ItemPanel({ item, canMark, onMark, onClear }: { item: ComplianceItem; canMark: boolean; onMark: () => void; onClear: () => void }) {
  return (
    <Panel role="region" aria-label={`Пункт ${item.clause}`} className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="text-lg font-semibold">{item.title}</h3>
          <p className="text-sm text-muted">
            {item.source_title}, {item.clause}
            {item.draft ? " · из проекта документа, в процент не входит" : ""}
          </p>
        </div>
        <StatusMark status={item.status} />
      </div>
      <p className="text-base">{item.summary}</p>
      <p className="text-xs text-muted">Применимо: {item.applies.map((a) => appliesTitle.get(a) ?? a).join(", ")}</p>
      {(item.checks ?? []).length > 0 && (
        <ul aria-label="Результаты проверок" className="flex flex-col gap-1 text-sm">
          {(item.checks ?? []).map((c) => (
            <li key={c.name}>
              <span className="font-medium">{c.title}</span> — {checkStatusTitle.get(c.status)}. {c.detail}
            </li>
          ))}
        </ul>
      )}
      {item.mark && (
        <div className="rounded-control border border-line p-2 text-sm">
          <div className="font-medium">
            Ручная отметка: {statusTitle.get(item.mark.status)?.title.toLowerCase()}
            {item.mark_overdue && " — срок пересмотра истёк, не засчитывается"}
          </div>
          <div className="break-words">{item.mark.comment}</div>
          {item.mark.document && <div className="break-words text-muted">Основание: {item.mark.document}</div>}
          <div className="text-xs text-muted">
            {formatAbsolute(item.mark.set_at)}, {item.mark.set_by}
            {item.mark.review_by ? ` · пересмотреть до ${item.mark.review_by}` : ""}
          </div>
        </div>
      )}
      {(item.evidence ?? []).length > 0 && (
        <ul aria-label="Где проверить" className="flex flex-col gap-1 text-sm">
          {(item.evidence ?? []).map((e) => (
            <li key={`${e.path}${e.title}`}>
              <Link className="underline" to={evidenceTo(e.path, e.query)}>
                {e.title}
              </Link>
              {e.hint && <span className="text-muted"> — {e.hint}</span>}
            </li>
          ))}
        </ul>
      )}
      {canMark && (
        <div className="flex flex-wrap gap-2">
          <Button onClick={onMark}>{item.mark ? "Изменить отметку" : "Поставить отметку"}</Button>
          {item.mark && (
            <Button variant="ghost" onClick={onClear}>
              Снять отметку
            </Button>
          )}
        </div>
      )}
    </Panel>
  );
}

function Requirements({ me }: { me: Me }) {
  const qc = useQueryClient();
  const [f, setF] = useState<Filters>({ source: "", applies: "" });
  const [open, setOpen] = useState<string | null>(null);
  const [marking, setMarking] = useState<ComplianceItem | null>(null);
  const [clearing, setClearing] = useState<ComplianceItem | null>(null);
  const q = useQuery({ queryKey: ["compliance", "overview", f], queryFn: ({ signal }) => complianceApi.overview(f, signal) });
  const clear = useMutation({
    mutationFn: (i: ComplianceItem) => complianceApi.clearMark(i.id),
    onSuccess: async () => {
      setClearing(null);
      await qc.invalidateQueries({ queryKey: ["compliance"] });
    },
  });
  const canMark = me.permissions.includes("compliance.mark");
  const canReport = me.permissions.includes("reports.read");
  const o: ComplianceOverview | undefined = q.data;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Источник требований">
          {({ id }) => (
            <Select id={id} value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })}>
              <option value="">Все источники</option>
              {(o?.sources ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Применимость">
          {({ id }) => (
            <Select id={id} value={f.applies} onChange={(e) => setF({ ...f, applies: e.target.value })}>
              <option value="">Для любых</option>
              {[...appliesTitle].map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {canReport && (
          <>
            <a
              href={complianceReportUrl("html")}
              target="_blank"
              rel="noreferrer"
              className="inline-flex h-[var(--control-h)] items-center rounded-control border border-line-strong bg-surface px-3 text-base font-medium text-fg hover:bg-surface-hover"
            >
              Открыть отчёт
            </a>
            <a
              href={complianceReportUrl("xlsx")}
              className="inline-flex h-[var(--control-h)] items-center rounded-control border border-line-strong bg-surface px-3 text-base font-medium text-fg hover:bg-surface-hover"
            >
              Скачать XLSX
            </a>
          </>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка требований…</p>}
      {o && (
        <>
          <Panel role="region" aria-label="Итог" className="flex flex-wrap items-baseline gap-x-6 gap-y-1">
            <div>
              <div className="text-3xl font-semibold">{percentText(o.summary.percent)}</div>
              <div className="text-xs text-muted">выполнено из {o.summary.counted} учтённых пунктов</div>
            </div>
            <ul className="flex flex-wrap gap-x-4 text-sm" aria-label="Пункты по статусам">
              {(
                [
                  ["met", o.summary.counts.met],
                  ["partial", o.summary.counts.partial],
                  ["not_met", o.summary.counts.not_met],
                  ["manual", o.summary.counts.manual],
                  ["not_applicable", o.summary.counts.not_applicable],
                ] as const
              ).map(([k, n]) => (
                <li key={k}>
                  {statusTitle.get(k)!.title}: {n}
                </li>
              ))}
            </ul>
            <div className="text-xs text-muted">
              База требований: версия {o.base.version} от {o.base.date}, {o.base.origin === "uploaded" ? "загруженная" : "встроенная"}
              {o.summary.drafts > 0 ? ` · пунктов из проектов документов: ${o.summary.drafts} (в процент не входят)` : ""}
            </div>
          </Panel>
          {o.unavailable.length > 0 && (
            <Banner kind="warning">
              Не удалось прочитать: {o.unavailable.map((g) => groupTitle.get(g) ?? g).join(", ")}. Зависящие от этого проверки не засчитаны.
            </Banner>
          )}
          {o.items.length === 0 ? (
            <EmptyState title="По выбранным условиям пунктов нет" action={<Button onClick={() => setF({ source: "", applies: "" })}>Сбросить фильтры</Button>} />
          ) : (
            <div className="overflow-auto">
              <Table aria-label="Требования">
                <thead>
                  <tr>
                    <Th>Источник и пункт</Th>
                    <Th>Требование</Th>
                    <Th>Статус</Th>
                    <Th>Действия</Th>
                  </tr>
                </thead>
                <tbody>
                  {o.items.map((i) => (
                    <tr key={i.id}>
                      <Td>
                        {i.source_title}
                        <div className="text-xs text-muted">{i.clause}</div>
                      </Td>
                      <Td>
                        {i.title}
                        {i.draft && <div className="text-xs text-muted">из проекта документа</div>}
                      </Td>
                      <Td>
                        <StatusMark status={i.status} />
                      </Td>
                      <Td>
                        <Button variant="ghost" aria-expanded={open === i.id} aria-label={`${open === i.id ? "Скрыть" : "Показать"} подробности: ${i.title}`} onClick={() => setOpen(open === i.id ? null : i.id)}>
                          {open === i.id ? "Скрыть" : "Подробнее"}
                        </Button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
          {o.items
            .filter((i) => i.id === open)
            .map((i) => (
              <ItemPanel key={i.id} item={i} canMark={canMark} onMark={() => setMarking(i)} onClear={() => setClearing(i)} />
            ))}
        </>
      )}
      {marking && <MarkDialog key={marking.id} item={marking} onClose={() => setMarking(null)} />}
      <ConfirmDialog
        open={clearing !== null}
        onOpenChange={(v) => !v && setClearing(null)}
        title="Снять ручную отметку?"
        description={clearing ? `Пункт «${clearing.title}» снова будет оцениваться только проверками или станет «Нужна отметка».` : ""}
        actionLabel="Снять отметку"
        busy={clear.isPending}
        error={clear.error}
        onConfirm={() => clearing && clear.mutate(clearing)}
      />
    </div>
  );
}

// База требований: версия, происхождение и загрузка обновления (право compliance.base.load).
function BaseTab({ canLoad }: { canLoad: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["compliance", "base"], queryFn: ({ signal }) => complianceApi.base(signal) });
  const file = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState(false);
  const load = useMutation({
    mutationFn: () => complianceApi.uploadBase(file.current!.files![0]!),
    onSuccess: async () => {
      if (file.current) file.current.value = "";
      setPicked(false);
      await qc.invalidateQueries({ queryKey: ["compliance"] });
    },
  });
  const b = q.data;
  return (
    <Panel className="flex flex-col gap-3">
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка сведений о базе…</p>}
      {b && (
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted">Действует</dt>
          <dd>
            версия {b.active.version} от {b.active.date}, {b.active.origin === "uploaded" ? "загруженная" : "встроенная в сборку"}, пунктов: {b.active.requirements}
          </dd>
          <dt className="text-muted">Встроенная</dt>
          <dd>
            версия {b.builtin.version} от {b.builtin.date}
          </dd>
          <dt className="text-muted">Загруженная</dt>
          <dd>
            {b.uploaded
              ? `версия ${b.uploaded.version} от ${b.uploaded.date}, загружена ${formatAbsolute(b.uploaded.uploaded_at)}, заверение № ${b.uploaded.subkey_serial}${
                  b.uploaded.valid ? ", подпись проверена" : ", подпись не прошла проверку — не используется"
                }`
              : "нет"}
          </dd>
        </dl>
      )}
      {b?.uploaded && !b.uploaded.valid && <Banner kind="warning">Сохранённая база не прошла проверку подписи при запуске сервера, действует встроенная.</Banner>}
      {canLoad && (
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Файл базы требований" hint="Подписанный файл из выпуска, до 4 МиБ. Версия должна быть новее действующей.">
            {({ id, describedBy }) => (
              <input id={id} aria-describedby={describedBy} ref={file} type="file" accept=".aisecdb" className="text-sm" onChange={(e) => setPicked(Boolean(e.target.files?.length))} />
            )}
          </Field>
          <Button disabled={!picked || load.isPending} onClick={() => load.mutate()}>
            Загрузить базу
          </Button>
        </div>
      )}
      <ErrorBanner error={load.error} />
      {load.data && <Banner kind="info">База версии {load.data.active.version} загружена.</Banner>}
    </Panel>
  );
}

// Экран «Соответствие» (ТЗ 5.18, задача 4.24): статусы требований ФСТЭК и 152-ФЗ по настройкам и состоянию системы.
// Права проверяет сервер; консоль только скрывает кнопки без compliance.mark и compliance.base.load.
export function ComplianceScreen({ me }: { me: Me }) {
  return (
    <section aria-label="Соответствие" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Соответствие требованиям</h1>
        <p className="text-sm text-muted">
          Состояние настроек и работы системы относительно требований ФСТЭК России и 152-ФЗ. Статусы вычисляются по настройкам; организационные меры отмечаются вручную.
        </p>
      </div>
      <TabBar
        label="Разделы соответствия"
        defaultValue="requirements"
        tabs={[
          { value: "requirements", title: "Требования", content: <Requirements me={me} /> },
          { value: "base", title: "База требований", content: <BaseTab canLoad={me.permissions.includes("compliance.base.load")} /> },
        ]}
      />
    </section>
  );
}
