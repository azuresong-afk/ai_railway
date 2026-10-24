import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { adminApi } from "../admin/api";
import { ErrorBanner, FormDialog } from "../admin/common";
import { severityOrder, severityTitle } from "../alerts/format";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Panel } from "../ui/Layout";
import { type Incident, type IncidentCard, type IncidentCategory, type IncidentResolution, type IncidentStage, incidentsApi } from "./api";
import {
  alertStatusText,
  reactionText,
  resolutionText,
  sourceText,
  stageText,
  statusText,
  timelineLine,
  transitionButton,
  transitions,
} from "./format";

type Target = Exclude<IncidentCard["status"], "new">;
const noteClass = "w-full rounded-control border border-line-strong bg-surface px-2 py-1 text-base";

function save(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Карточка инцидента (ТЗ 5.7): поля, этапы реагирования, хронология, комментарии (только добавление), связанные
// оповещения и события, инструкция категории. Кнопки изменения видны при incidents.manage; закрытый инцидент — только чтение.
export function IncidentCardPanel({ id, me, onClose, onOpen }: { id: string; me: Me; onClose: () => void; onOpen: (id: string) => void }) {
  const qc = useQueryClient();
  const has = (p: string) => me.permissions.includes(p);
  const canManage = has("incidents.manage");
  const q = useQuery({ queryKey: ["incidents", "card", id], queryFn: ({ signal }) => incidentsApi.card(id, signal) });
  const users = useQuery({ queryKey: ["incidents", "users"], queryFn: ({ signal }) => adminApi.users(signal), enabled: has("users.read") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["incidents"] });

  const [target, setTarget] = useState<Target>();
  const [resolution, setResolution] = useState<IncidentResolution | "">("");
  const [comment, setComment] = useState("");
  const [stage, setStage] = useState<IncidentStage>();
  const [note, setNote] = useState("");
  const [text, setText] = useState("");
  const [now] = useState(() => Date.now());

  const closeDialogs = () => {
    setTarget(undefined);
    setStage(undefined);
    setResolution("");
    setComment("");
    setNote("");
    statusM.reset();
    stageM.reset();
  };
  const statusM = useMutation({
    mutationFn: (to: Target) =>
      incidentsApi.setStatus(id, { status: to, ...(to === "closed" && resolution ? { resolution } : {}), ...(comment.trim() ? { comment: comment.trim() } : {}) }),
    onSuccess: async () => {
      closeDialogs();
      await refresh();
    },
  });
  const stageM = useMutation({
    mutationFn: (s: IncidentStage) => incidentsApi.stage(id, s, note.trim()),
    onSuccess: async () => {
      closeDialogs();
      await refresh();
    },
  });
  const assignM = useMutation({ mutationFn: (uid: string) => incidentsApi.assign(id, uid), onSuccess: refresh });
  const commentM = useMutation({
    mutationFn: () => incidentsApi.comment(id, text.trim()),
    onSuccess: async () => {
      setText("");
      await refresh();
    },
  });
  const reopenM = useMutation({
    mutationFn: () => incidentsApi.create({ reopen_of: id }),
    onSuccess: async (i) => {
      await refresh();
      onOpen(i.id);
    },
  });
  const exportM = useMutation({
    mutationFn: () => incidentsApi.exportJson(id),
    onSuccess: (t) => save(t, `incident-${q.data?.number ?? id}.json`),
  });

  const c = q.data;
  const open = c !== undefined && c.status !== "closed";
  const userName = (uid: string | undefined) => {
    if (!uid) return "не назначен";
    if (uid === me.user.id) return `${me.user.display_name} (вы)`;
    return users.data?.find((u) => u.id === uid)?.display_name ?? uid;
  };
  const closing = target === "closed";

  return (
    <aside aria-label="Карточка инцидента" className="w-[30rem] shrink-0">
      <Panel className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-2">
          <h2 className="text-lg font-semibold">{c ? `Инцидент № ${c.number}: ${c.title}` : "Инцидент"}</h2>
          <Button variant="ghost" onClick={onClose} aria-label="Закрыть карточку">
            Закрыть
          </Button>
        </div>
        <ErrorBanner error={q.error} />
        {!c && !q.isError && <p className="text-sm text-muted">Загрузка…</p>}
        {c && (
          <>
            <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-muted">Серьёзность</dt>
              <dd>
                <SeverityBadge level={c.severity} />
              </dd>
              <dt className="text-muted">Статус</dt>
              <dd>
                {statusText[c.status]}
                {c.resolution ? `: ${resolutionText[c.resolution]}` : ""}
              </dd>
              {c.resolution_comment && (
                <>
                  <dt className="text-muted">Комментарий к закрытию</dt>
                  <dd className="break-words whitespace-pre-wrap">{c.resolution_comment}</dd>
                </>
              )}
              <dt className="text-muted">Категория</dt>
              <dd>{c.category_title}</dd>
              <dt className="text-muted">Источник</dt>
              <dd>{sourceText.get(c.source) ?? c.source}</dd>
              <dt className="text-muted">Ответственный</dt>
              <dd>{userName(c.assignee_id)}</dd>
              <dt className="text-muted">Срок реакции</dt>
              <dd>
                {formatAbsolute(c.reaction_due_at)} ({reactionText(c, now)})
              </dd>
              <dt className="text-muted">Создан</dt>
              <dd>
                {formatAbsolute(c.created_at)}, {c.created_by}
              </dd>
              {c.contained_at && (
                <>
                  <dt className="text-muted">Локализован</dt>
                  <dd>{formatAbsolute(c.contained_at)}</dd>
                </>
              )}
              {c.closed_at && (
                <>
                  <dt className="text-muted">Закрыт</dt>
                  <dd>
                    {formatAbsolute(c.closed_at)}
                    {c.closed_by ? `, ${c.closed_by}` : ""}
                  </dd>
                </>
              )}
              {c.reopened_from && (
                <>
                  <dt className="text-muted">Открыт повторно после</dt>
                  <dd>
                    <button type="button" className="underline" onClick={() => onOpen(c.reopened_from!)}>
                      прежнего инцидента
                    </button>
                  </dd>
                </>
              )}
            </dl>

            <div className="flex flex-wrap gap-2">
              {canManage && transitions[c.status].map((to) => (
                <Button key={to} variant={to === "closed" ? "primary" : "secondary"} onClick={() => setTarget(to)}>
                  {transitionButton.get(to)}
                </Button>
              ))}
              {canManage && c.status === "closed" && (
                <Button onClick={() => reopenM.mutate()} disabled={reopenM.isPending}>
                  Открыть заново
                </Button>
              )}
              {has("incidents.export") && (
                <Button onClick={() => exportM.mutate()} disabled={exportM.isPending}>
                  Выгрузить JSON
                </Button>
              )}
            </div>
            <ErrorBanner error={reopenM.error ?? exportM.error ?? assignM.error} />

            {canManage && open && (
              <div className="flex flex-wrap items-end gap-2">
                {users.data ? (
                  <Field label="Ответственный">
                    {({ id: fid }) => (
                      <Select id={fid} value={c.assignee_id ?? ""} onChange={(e) => assignM.mutate(e.target.value)} disabled={assignM.isPending}>
                        <option value="">Не назначен</option>
                        {users.data
                          .filter((u) => u.status === "active")
                          .map((u) => (
                            <option key={u.id} value={u.id}>
                              {u.display_name}
                            </option>
                          ))}
                      </Select>
                    )}
                  </Field>
                ) : (
                  <>
                    {c.assignee_id !== me.user.id && <Button onClick={() => assignM.mutate(me.user.id)}>Назначить себя</Button>}
                    {c.assignee_id && <Button onClick={() => assignM.mutate("")}>Снять назначение</Button>}
                  </>
                )}
              </div>
            )}

            <section aria-label="Этапы реагирования" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">Этапы реагирования</h3>
              <ol className="flex flex-col gap-1 text-sm">
                {c.stages.map((s) => (
                  <li key={s.key} className="flex flex-wrap items-center gap-2">
                    <span>{stageText.get(s.key) ?? s.title}:</span>
                    {s.done_at ? (
                      <span>
                        выполнен {formatAbsolute(s.done_at)}
                        {s.done_by ? `, ${s.done_by}` : ""}
                        {s.note ? ` — ${s.note}` : ""}
                      </span>
                    ) : canManage && open ? (
                      <Button onClick={() => setStage(s.key)} aria-label={`Отметить этап: ${stageText.get(s.key) ?? s.title}`}>
                        Отметить
                      </Button>
                    ) : (
                      <span className="text-muted">не выполнен</span>
                    )}
                  </li>
                ))}
              </ol>
            </section>

            <section aria-label="Инструкция реагирования" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">Инструкция реагирования</h3>
              <div className="rounded-control border border-line bg-bg p-2 text-sm break-words whitespace-pre-wrap">{c.instruction.body}</div>
            </section>

            <section aria-label="Оповещения инцидента" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">Оповещения</h3>
              {c.alerts.length === 0 ? (
                <p className="text-sm text-muted">Оповещений нет.</p>
              ) : (
                <ul className="flex flex-col gap-1 text-sm">
                  {c.alerts.map((a) => (
                    <li key={a.id}>
                      <SeverityBadge level={a.severity} /> {a.title} — {alertStatusText[a.status]}, срабатываний: {a.count}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section aria-label="События инцидента" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">События</h3>
              {!has("events.read") ? (
                <p className="text-sm text-muted">Для просмотра событий нужно право «events.read».</p>
              ) : c.events.length === 0 ? (
                <p className="text-sm text-muted">Ссылок на события нет.</p>
              ) : (
                <ul className="max-h-40 overflow-auto text-sm">
                  {c.events.map((e) => (
                    <li key={e.id}>
                      <Link className="underline" to={`/events?${new URLSearchParams({ r: "30d", event: e.id })}`}>
                        Событие от {formatAbsolute(e.ts)}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
              {c.events_truncated && <p className="text-xs text-muted">Показаны первые {c.events.length} событий: ссылок больше.</p>}
            </section>

            <section aria-label="Хронология" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">Хронология</h3>
              <ol className="flex flex-col gap-1 text-sm">
                {c.timeline.map((e, i) => (
                  <li key={`${e.at}-${i}`}>
                    {formatAbsolute(e.at)}: {timelineLine(e)}, {e.actor}
                  </li>
                ))}
              </ol>
            </section>

            <section aria-label="Комментарии" className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Комментарии</h3>
              {c.comments.length === 0 && <p className="text-sm text-muted">Комментариев нет.</p>}
              <ul className="flex flex-col gap-2">
                {c.comments.map((m) => (
                  <li key={m.id} className="rounded-control border border-line p-2 text-sm">
                    <div className="text-xs text-muted">
                      {m.author_name}, {formatAbsolute(m.at)}
                      {m.replaces ? " (исправленная версия)" : ""}
                      {m.superseded ? " (заменён исправленным)" : ""}
                    </div>
                    <div className="break-words whitespace-pre-wrap">{m.body}</div>
                  </li>
                ))}
              </ul>
              {canManage && open && (
                <form
                  className="flex flex-col gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (text.trim()) commentM.mutate();
                  }}
                >
                  <Field label="Новый комментарий" hint="До 4000 знаков. Комментарии только добавляются.">
                    {({ id: fid, describedBy }) => (
                      <textarea id={fid} aria-describedby={describedBy} rows={3} maxLength={4000} value={text} onChange={(e) => setText(e.target.value)} className={noteClass} />
                    )}
                  </Field>
                  <ErrorBanner error={commentM.error} />
                  <div>
                    <Button type="submit" disabled={!text.trim() || commentM.isPending}>
                      Добавить комментарий
                    </Button>
                  </div>
                </form>
              )}
            </section>
          </>
        )}
      </Panel>

      <FormDialog
        open={target !== undefined}
        onOpenChange={(v) => !v && closeDialogs()}
        title={target ? (transitionButton.get(target) ?? "") : ""}
        description={closing ? "Закрытый инцидент не меняется. Его незакрытые оповещения закроются вместе с ним." : "Переход запишется в хронологию инцидента."}
      >
        {closing && (
          <Field label="Резолюция" hint="Обязательна при закрытии.">
            {({ id: fid, describedBy }) => (
              <Select id={fid} aria-describedby={describedBy} value={resolution} onChange={(e) => setResolution(e.target.value as IncidentResolution | "")}>
                <option value="">Выберите резолюцию</option>
                {Object.entries(resolutionText).map(([r, t]) => (
                  <option key={r} value={r}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        <Field label="Комментарий" hint="Необязательно.">
          {({ id: fid, describedBy }) => (
            <textarea id={fid} aria-describedby={describedBy} rows={3} maxLength={2000} value={comment} onChange={(e) => setComment(e.target.value)} className={noteClass} />
          )}
        </Field>
        <ErrorBanner error={statusM.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={closeDialogs}>Отменить</Button>
          <Button variant="primary" disabled={statusM.isPending || (closing && resolution === "")} onClick={() => target && statusM.mutate(target)}>
            {target ? transitionButton.get(target) : ""}
          </Button>
        </div>
      </FormDialog>

      <FormDialog open={stage !== undefined} onOpenChange={(v) => !v && closeDialogs()} title="Отметить этап реагирования" {...(stage ? { description: stageText.get(stage) ?? stage } : {})}>
        <Field label="Заметка" hint="Необязательно. Отмеченный этап не снимается.">
          {({ id: fid, describedBy }) => (
            <textarea id={fid} aria-describedby={describedBy} rows={3} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} className={noteClass} />
          )}
        </Field>
        <ErrorBanner error={stageM.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={closeDialogs}>Отменить</Button>
          <Button variant="primary" disabled={stageM.isPending} onClick={() => stage && stageM.mutate(stage)}>
            Отметить этап
          </Button>
        </div>
      </FormDialog>
    </aside>
  );
}

// Ручное создание: название, серьёзность и категория обязательны (API C2).
export function CreateIncidentDialog({ cats, onClose, onCreated }: { cats: IncidentCategory[]; onClose: () => void; onCreated: (i: Incident) => void }) {
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<(typeof severityOrder)[number]>("medium");
  const [category, setCategory] = useState<string>("");
  const m = useMutation({
    mutationFn: () => incidentsApi.create({ title: title.trim(), severity, category: category as IncidentCategory["id"] }),
    onSuccess: async (i) => {
      await qc.invalidateQueries({ queryKey: ["incidents"] });
      onCreated(i);
    },
  });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title="Создать инцидент" description="Срок реакции назначается по серьёзности.">
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (title.trim() && category) m.mutate();
        }}
      >
        <Field label="Название">{({ id }) => <Input id={id} autoFocus maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />}</Field>
        <Field label="Серьёзность">
          {({ id }) => (
            <Select id={id} value={severity} onChange={(e) => setSeverity(e.target.value as typeof severity)}>
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
              <option value="">Выберите категорию</option>
              {cats.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || !title.trim() || !category}>
            Создать инцидент
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
