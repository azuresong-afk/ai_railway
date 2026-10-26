import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { type Event, eventsApi } from "./api";
import { ExceptionDialog } from "./ExceptionDialog";
import { formatAbsolute } from "./format";

type Mark = "false_positive" | "confirmed";
const markText = new Map<Mark, string>([
  ["false_positive", "Ложное срабатывание"],
  ["confirmed", "Подтверждено"],
]);

// Отметка события и путь «ложное срабатывание → исключение» (ТЗ 5.5, задача 3.22). Кнопки отметки видны при events.mark,
// кнопка исключения — при policies.manage (исключение создаёт только администратор безопасности); отказ сервера (403) выводится текстом.
export function MarkPanel({ ev, canMark, canException, mfa }: { ev: Event; canMark: boolean; canException: boolean; mfa: boolean }) {
  const qc = useQueryClient();
  const [target, setTarget] = useState<Mark>();
  const [comment, setComment] = useState("");
  const [exc, setExc] = useState(false);
  const m = useMutation({
    mutationFn: (mark: Mark | "none") => eventsApi.mark(ev.id, mark, mark === "none" ? "" : comment.trim()),
    onSuccess: async () => {
      setTarget(undefined);
      setComment("");
      await qc.invalidateQueries({ queryKey: ["event", ev.id] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
  });
  const cur = ev.mark;
  if (!canMark && !canException && !cur) return null;
  const close = () => {
    setTarget(undefined);
    setComment("");
    m.reset();
  };
  return (
    <section aria-labelledby="mark" className="flex flex-col gap-2">
      <h3 id="mark" className="text-md font-semibold">
        Отметка аналитика
      </h3>
      {cur ? (
        <p className="text-sm">
          {markText.get(cur.mark)}: {formatAbsolute(cur.marked_at)}, {cur.marked_by_name ?? cur.marked_by}
          {cur.comment && <span className="block break-words whitespace-pre-wrap text-muted">{cur.comment}</span>}
        </p>
      ) : (
        <p className="text-sm text-muted">Отметки нет.</p>
      )}
      <div className="flex flex-wrap gap-2">
        {canMark && (
          <>
            <Button onClick={() => setTarget("false_positive")}>Ложное срабатывание</Button>
            <Button onClick={() => setTarget("confirmed")}>Подтверждено</Button>
            {cur && (
              <Button onClick={() => m.mutate("none")} disabled={m.isPending}>
                Снять отметку
              </Button>
            )}
          </>
        )}
        {canException && (
          <Button variant="primary" onClick={() => setExc(true)}>
            Создать исключение
          </Button>
        )}
      </div>
      {target === undefined && <ErrorBanner error={m.error} />}
      <FormDialog
        open={target !== undefined}
        onOpenChange={(v) => !v && close()}
        title={target ? `Отметить: ${(markText.get(target) ?? "").toLowerCase()}` : ""}
        description="Отметка хранится отдельно от события, событие не меняется. Смена отметки пишется в журнал аудита."
      >
        <Field label="Комментарий" hint="Необязательно, до 1000 знаков. Не вставляйте содержимое запроса: комментарий видят все, кто читает события.">
          {({ id, describedBy }) => (
            <textarea
              id={id}
              aria-describedby={describedBy}
              rows={3}
              maxLength={1000}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 text-base"
            />
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button variant="primary" disabled={m.isPending} onClick={() => target && m.mutate(target)}>
            Поставить отметку
          </Button>
        </div>
      </FormDialog>
      {/* Комментарий отметки в причину не подставляется: причина уходит в политику и на шлюзы мимо режима хранения содержимого (3В29). */}
      {exc && <ExceptionDialog eventId={ev.id} mfa={mfa} defaultReason={`Ложное срабатывание (событие ${ev.id})`} onClose={() => setExc(false)} />}
    </section>
  );
}
