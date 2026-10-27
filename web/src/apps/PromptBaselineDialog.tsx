import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ConfirmDialog, ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { type Application, type PromptBaseline, appsApi } from "./api";

// Предел текста эталона, байт (как на сервере).
const maxPromptBytes = 128 << 10;

type Mode = NonNullable<PromptBaseline["mode"]>;

function modeHint(mode: Mode): string {
  switch (mode) {
    case "off":
      return "Эталон хранится, но запросы с ним не сверяются.";
    case "alert":
      return "Запрос с другим системным промптом проходит, событие получает находку DM-26 и оповещение.";
    case "block":
      return "Запрос с другим системным промптом блокируется (в режиме политики «Мониторинг» — только фиксируется).";
  }
}

// Эталон системного промпта (задача 4.14, DM-26; право applications.policy). Сравнение — по хешу после нормализации
// пробелов: края обрезаются, переводы строк и повторы пробелов не важны. Понижение режима и снятие эталона — ослабление:
// сервер просит пароль или код, поле появляется по его ответу.
export function PromptBaselineDialog({ app, mfa, onClose }: { app: Application; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const key = ["apps", "prompt-baseline", app.id];
  const q = useQuery({ queryKey: key, queryFn: ({ signal }) => appsApi.promptBaseline(app.id, signal) });
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`Эталон системного промпта «${app.name}»`}
      description="Шлюз сверяет системный промпт каждого запроса приложения с эталоном. Изменение записывается в журнал аудита."
    >
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка эталона…</p>}
      {q.data && (
        <BaselineForm
          app={app}
          current={q.data}
          mfa={mfa}
          onDone={async () => {
            await qc.invalidateQueries({ queryKey: key });
            onClose();
          }}
          onCancel={onClose}
        />
      )}
    </FormDialog>
  );
}

function BaselineForm({
  app,
  current,
  mfa,
  onDone,
  onCancel,
}: {
  app: Application;
  current: PromptBaseline;
  mfa: boolean;
  onDone: () => Promise<void>;
  onCancel: () => void;
}) {
  const [text, setText] = useState(current.text ?? "");
  const [mode, setMode] = useState<Mode>(current.mode ?? "alert");
  const re = useReauth(mfa);
  const bytes = new TextEncoder().encode(text).length;
  const textErr =
    text.trim() === "" ? "Введите текст системного промпта." : bytes > maxPromptBytes ? `Не больше ${maxPromptBytes} байт.` : undefined;
  const changed = text !== (current.text ?? "");
  const save = useMutation({
    mutationFn: () => appsApi.setPromptBaseline(app.id, { mode, ...(changed || !current.configured ? { text } : {}), ...re.body() }),
    onSuccess: async () => {
      re.reset();
      await onDone();
    },
    onError: re.onError,
  });
  // Снятие — только после подтверждения; при запросе пароля подтверждение
  // закрывается, чтобы было видно поле повторной проверки.
  const [confirmRemove, setConfirmRemove] = useState(false);
  const remove = useMutation({
    mutationFn: () => appsApi.deletePromptBaseline(app.id, re.body()),
    onSuccess: async () => {
      setConfirmRemove(false);
      re.reset();
      await onDone();
    },
    onError: (e) => {
      setConfirmRemove(false);
      re.onError(e);
    },
  });
  const busy = save.isPending || remove.isPending;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!textErr && re.ready) save.mutate();
  };
  const cancel = () => {
    re.reset();
    onCancel();
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      {current.configured && (
        <p className="text-xs text-muted">
          Хеш эталона <span className="font-mono">{current.hash?.slice(0, 16)}…</span>, {current.bytes} байт
          {current.updated_at && <>, изменён {formatAbsolute(current.updated_at)}</>}.
        </p>
      )}
      <Field label="Системный промпт" hint="Как его отправляет приложение: первые сообщения с ролью system или developer." error={textErr}>
        {({ id, describedBy, invalid }) => (
          <textarea
            id={id}
            aria-describedby={describedBy}
            aria-invalid={invalid}
            rows={8}
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-base aria-[invalid=true]:border-sev-critical"
          />
        )}
      </Field>
      <Field label="Режим контроля" hint={modeHint(mode)}>
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
            <option value="block">Блокировать запрос</option>
            <option value="alert">Оповещать</option>
            <option value="off">Не сверять</option>
          </Select>
        )}
      </Field>
      <ReauthPrompt r={re} />
      <ErrorBanner error={visibleError(save.error) ?? visibleError(remove.error)} />
      <div className="flex justify-end gap-2">
        {current.configured && (
          <Button variant="danger" disabled={busy || !re.ready} onClick={() => setConfirmRemove(true)}>
            Снять эталон
          </Button>
        )}
        <Button onClick={cancel}>Отменить</Button>
        <Button type="submit" variant="primary" disabled={busy || Boolean(textErr) || !re.ready}>
          Сохранить эталон
        </Button>
      </div>
      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title="Снять эталон системного промпта"
        description={`Шлюзы перестанут сверять системный промпт приложения «${app.name}». Снятие действующего эталона — ослабление защиты, оно записывается в журнал аудита.`}
        actionLabel="Снять эталон"
        busy={remove.isPending}
        error={undefined}
        onConfirm={() => remove.mutate()}
      />
    </form>
  );
}
