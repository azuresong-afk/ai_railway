import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { adminApi, type EventRetention } from "./api";
import { ConfirmDialog, ErrorBanner } from "./common";

// Сроки и режим хранения событий (ТЗ 5.5). Часовой пояс показа сервер берёт из флага -timezone:
// записи через API нет, поэтому здесь только пояснение (открытый вопрос 2.24 в docs/plans/stage-2.md).
export function RetentionTab({ me }: { me: Me }) {
  const q = useQuery({ queryKey: ["admin", "retention"], queryFn: ({ signal }) => adminApi.retention(signal) });
  const canManage = me.permissions.includes("events.retention.manage");
  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <Banner kind="info">
        Часовой пояс показа (ВРМ.2) задаёт администратор при запуске сервера флагом <code>-timezone</code>; текущее значение видно в разделе «Состояние
        системы». Режим хранения содержимого (<code>full</code>, <code>masked</code>, <code>off</code>) выбирается в настройках шлюза.
      </Banner>
      {q.isError && <ErrorBanner error={q.error} />}
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка настроек…</p>}
      {q.data && <RetentionForm initial={q.data} canManage={canManage} />}
    </div>
  );
}

function RetentionForm({ initial, canManage }: { initial: EventRetention; canManage: boolean }) {
  const qc = useQueryClient();
  const [meta, setMeta] = useState(String(initial.metadata_days));
  const [content, setContent] = useState(String(initial.content_days));
  const [confirm, setConfirm] = useState(false);
  const [saved, setSaved] = useState(false);
  const mn = Number(meta);
  const cn = Number(content);
  const metaErr = !Number.isInteger(mn) || mn < 30 || mn > 3650 ? "Введите целое число суток от 30 до 3650." : undefined;
  const contentErr =
    !Number.isInteger(cn) || cn < 7 || cn > 3650
      ? "Введите целое число суток от 7 до 3650."
      : cn > mn
        ? "Содержимое не может храниться дольше метаданных."
        : undefined;
  const reduced = mn < initial.metadata_days || cn < initial.content_days;

  const m = useMutation({
    mutationFn: () => adminApi.saveRetention({ metadata_days: mn, content_days: cn }),
    onSuccess: (r) => {
      qc.setQueryData(["admin", "retention"], r);
      setConfirm(false);
      setSaved(true);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    if (reduced) setConfirm(true);
    else m.mutate();
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <Field label="Срок хранения метаданных событий, суток" hint="От 30 до 3650." error={metaErr}>
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" disabled={!canManage} value={meta} onChange={(e) => { setSaved(false); setMeta(e.target.value); }} />
        )}
      </Field>
      <Field label="Срок хранения содержимого запросов и ответов, суток" hint="От 7 до 3650 и не дольше метаданных." error={contentErr}>
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" disabled={!canManage} value={content} onChange={(e) => { setSaved(false); setContent(e.target.value); }} />
        )}
      </Field>
      <p className="text-xs text-muted">Последнее изменение: {formatAbsolute(initial.updated_at)}.</p>
      <ErrorBanner error={confirm ? null : m.error} />
      {saved && <Banner kind="info">Сроки сохранены. Данные старше нового срока удаляются фоновым заданием целыми сутками.</Banner>}
      {canManage ? (
        <div>
          <Button type="submit" variant="primary" disabled={m.isPending || Boolean(metaErr) || Boolean(contentErr)}>
            Сохранить сроки
          </Button>
        </div>
      ) : (
        <p className="text-sm text-muted">Менять сроки может администратор безопасности.</p>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={(v) => {
          if (!v) {
            setConfirm(false);
            m.reset();
          }
        }}
        title="Сократить срок хранения"
        description="Данные старше нового срока будут удалены без возможности восстановления. Изменение записывается в журнал аудита."
        actionLabel="Сократить срок и удалить старые данные"
        busy={m.isPending}
        error={m.error}
        onConfirm={() => m.mutate()}
      />
    </form>
  );
}
