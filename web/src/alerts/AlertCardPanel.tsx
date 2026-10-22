import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { ErrorBanner, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Panel } from "../ui/Layout";
import { alertsApi } from "./api";
import { eventLink, eventsLink, kindText, statusText } from "./format";

const groupTitle = new Map<string, string>(Object.entries({
  type: "Тип", app: "Приложение", env: "Окружение", user: "Пользователь (псевдоним)", provider: "Провайдер", model: "Модель",
  source: "Источник", gateway: "Шлюз", action: "Действие", rule: "Правило обнаружения", severity: "Серьёзность", policy_mode: "Режим политики",
}));

// Карточка оповещения: жизненный цикл новое → в работе → закрыто, история, переход к событиям. Кнопка «Создать инцидент»
// скрыта, пока в API нет /incidents (задача 3.16, поток C2); в оповещении с инцидентом показывается его ID.
export function AlertCardPanel({ id, me, onClose }: { id: string; me: Me; onClose: () => void }) {
  const qc = useQueryClient();
  const canManage = me.permissions.includes("alerts.manage");
  const canEvents = me.permissions.includes("events.read");
  const q = useQuery({ queryKey: ["alerts", "card", id], queryFn: ({ signal }) => alertsApi.card(id, signal) });
  const [target, setTarget] = useState<"in_progress" | "closed">();
  const [comment, setComment] = useState("");
  const m = useMutation({
    mutationFn: (to: "in_progress" | "closed") => alertsApi.setStatus(id, to, comment.trim()),
    onSuccess: async () => {
      setTarget(undefined);
      setComment("");
      await qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
  const a = q.data;
  const [now] = useState(() => Date.now());
  const close = () => {
    m.reset();
    setComment("");
    setTarget(undefined);
  };

  return (
    <aside aria-label="Карточка оповещения" className="w-[26rem] shrink-0">
      <Panel className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-2">
          <h2 className="text-lg font-semibold">{a?.title ?? "Оповещение"}</h2>
          <Button variant="ghost" onClick={onClose} aria-label="Закрыть карточку">
            Закрыть
          </Button>
        </div>
        <ErrorBanner error={q.error} />
        {!a && !q.isError && <p className="text-sm text-muted">Загрузка…</p>}
        {a && (
          <>
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm">
              <dt className="text-muted">Серьёзность</dt>
              <dd>
                <SeverityBadge level={a.severity} />
              </dd>
              <dt className="text-muted">Статус</dt>
              <dd>{statusText[a.status]}</dd>
              <dt className="text-muted">Правило</dt>
              <dd>
                {kindText.get(a.kind) ?? a.kind}: {a.rule_name}
              </dd>
              <dt className="text-muted">Срабатываний</dt>
              <dd>
                {a.count}
                {a.suppressed > 0 && ` (ещё ${a.suppressed} подавлено после закрытия)`}
              </dd>
              <dt className="text-muted">Создано</dt>
              <dd>{formatAbsolute(a.created_at)}</dd>
              <dt className="text-muted">Последнее</dt>
              <dd>{formatAbsolute(a.last_triggered_at)}</dd>
              {a.closed_at && (
                <>
                  <dt className="text-muted">Закрыто</dt>
                  <dd>
                    {formatAbsolute(a.closed_at)}
                    {a.closed_by ? `, ${a.closed_by}` : ""}
                  </dd>
                </>
              )}
              {a.incident_id && (
                <>
                  <dt className="text-muted">Инцидент</dt>
                  <dd className="font-mono">{a.incident_id}</dd>
                </>
              )}
              {Object.entries(a.group).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted">{groupTitle.get(k) ?? k}</dt>
                  <dd className="break-all">{v}</dd>
                </div>
              ))}
            </dl>

            {canManage && a.status !== "closed" && (
              <div className="flex gap-2">
                {a.status === "new" && <Button onClick={() => setTarget("in_progress")}>Принять в работу</Button>}
                <Button variant="primary" onClick={() => setTarget("closed")}>
                  Закрыть оповещение
                </Button>
              </div>
            )}

            <section aria-label="События оповещения" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">События</h3>
              {canEvents ? (
                <>
                  <Link className="text-sm text-accent underline" to={eventsLink(a, now)}>
                    Открыть события с этими значениями
                  </Link>
                  {a.events.length === 0 ? (
                    <p className="text-sm text-muted">Ссылок на события нет.</p>
                  ) : (
                    <ul className="max-h-40 overflow-auto text-sm">
                      {a.events.map((e) => (
                        <li key={e.id}>
                          <Link className="underline" to={eventLink(e.id, a, now)}>
                            Событие от {formatAbsolute(e.ts)}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                  {a.events_truncated && <p className="text-xs text-muted">Показаны первые {a.events.length} событий: срабатываний больше.</p>}
                </>
              ) : (
                <p className="text-sm text-muted">Для просмотра событий нужно право «events.read».</p>
              )}
            </section>

            <section aria-label="История оповещения" className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">История</h3>
              {a.history.length === 0 ? (
                <p className="text-sm text-muted">Статус не менялся.</p>
              ) : (
                <ol className="flex flex-col gap-1 text-sm">
                  {a.history.map((h, i) => (
                    <li key={`${h.at}-${i}`}>
                      {formatAbsolute(h.at)}: {statusText[h.from]} → {statusText[h.to]}, {h.actor}
                      {h.comment ? ` — ${h.comment}` : ""}
                    </li>
                  ))}
                </ol>
              )}
            </section>
          </>
        )}
      </Panel>
      <FormDialog
        open={target !== undefined}
        onOpenChange={(v) => !v && close()}
        title={target === "closed" ? "Закрыть оповещение" : "Принять оповещение в работу"}
        description={
          target === "closed"
            ? "Закрытое оповещение не открывается снова: повтор после окна подавления создаст новое."
            : "Вы станете исполнителем оповещения."
        }
      >
        <ErrorBanner error={m.error} />
        <Field label="Комментарий" hint="Необязательно, до 2000 знаков.">
          {({ id: fid, describedBy }) => (
            <textarea
              id={fid}
              aria-describedby={describedBy}
              rows={3}
              maxLength={2000}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 text-base"
            />
          )}
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button variant="primary" disabled={m.isPending} onClick={() => target && m.mutate(target)}>
            {target === "closed" ? "Закрыть" : "Принять в работу"}
          </Button>
        </div>
      </FormDialog>
    </aside>
  );
}
