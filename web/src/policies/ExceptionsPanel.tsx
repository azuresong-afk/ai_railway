import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { ErrorBanner, FormDialog } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, Table, Td, Th } from "../ui/Layout";
import { type PolicyExceptionItem, policiesApi } from "./api";

const sourceText = { user: "запрос", rag: "RAG", tool: "инструмент", output: "ответ" } as const;

// Условия исключения одной строкой (хеш фрагмента — только хвост: полностью он пользователю не нужен).
export function conditionText(e: PolicyExceptionItem): string {
  return [
    `детектор ${e.detector}`,
    e.category && `категория ${e.category}`,
    e.pattern && `правило ${e.pattern}`,
    e.fragment && `фрагмент …${e.fragment.slice(-8)}`,
    e.app && `приложение ${e.app}`,
    e.user && `пользователь ${e.user}`,
    e.source && `источник: ${sourceText[e.source]}`,
  ]
    .filter(Boolean)
    .join("; ");
}

// Экран исключений политики: действующие и истёкшие отдельно, продление (ослабление, нужен пароль или код) и удаление.
export function ExceptionsPanel({ policyId, canManage, canEvents, mfa }: { policyId: string; canManage: boolean; canEvents: boolean; mfa: boolean }) {
  const q = useQuery({ queryKey: ["policies", policyId, "exceptions"], queryFn: ({ signal }) => policiesApi.exceptions(policyId, signal) });
  const [extend, setExtend] = useState<PolicyExceptionItem>();
  const [del, setDel] = useState<PolicyExceptionItem>();
  const items = q.data?.items ?? [];
  const active = items.filter((e) => e.status === "active");
  const expired = items.filter((e) => e.status === "expired");

  const table = (rows: PolicyExceptionItem[], label: string) => (
    <Table aria-label={label}>
      <thead>
        <tr>
          <Th>ID</Th>
          <Th>Условия</Th>
          <Th>Причина</Th>
          <Th>Автор</Th>
          <Th>Истекает</Th>
          <Th>Событие</Th>
          {canManage && <Th>Действия</Th>}
        </tr>
      </thead>
      <tbody>
        {rows.map((e) => (
          <tr key={e.id}>
            <Td className="font-mono text-sm">{e.id}</Td>
            <Td className="text-sm">{conditionText(e)}</Td>
            <Td className="text-sm break-words">{e.reason}</Td>
            <Td className="text-sm">{e.author ?? "—"}</Td>
            <Td className="text-sm whitespace-nowrap">{e.expires_at ? formatAbsolute(e.expires_at) : "—"}</Td>
            <Td className="text-sm">
              {e.event_id && canEvents ? (
                <Link className="underline" to={`/events?${new URLSearchParams({ r: "30d", event: e.event_id })}`}>
                  Открыть
                </Link>
              ) : (
                "—"
              )}
            </Td>
            {canManage && (
              <Td>
                <span className="flex gap-2">
                  <Button onClick={() => setExtend(e)} aria-label={`Продлить исключение ${e.id}`}>
                    Продлить
                  </Button>
                  <Button variant="danger" onClick={() => setDel(e)} aria-label={`Удалить исключение ${e.id}`}>
                    Удалить
                  </Button>
                </span>
              </Td>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  );

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">
        Исключение — часть версии политики: оно подписывается вместе с ней, а любое изменение создаёт новую версию. Исключение с истёкшим сроком шлюз не применяет.
      </p>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка исключений…</p>}
      {q.data && items.length === 0 && <p className="text-sm text-muted">Исключений нет. Они создаются из карточки события.</p>}
      {active.length > 0 && (
        <section aria-label="Действующие исключения" className="flex flex-col gap-1">
          <h3 className="text-sm font-medium">Действующие</h3>
          {table(active, "Действующие исключения")}
        </section>
      )}
      {expired.length > 0 && (
        <section aria-label="Истёкшие исключения" className="flex flex-col gap-1">
          <h3 className="text-sm font-medium">Истёкшие (не применяются)</h3>
          {table(expired, "Истёкшие исключения")}
        </section>
      )}
      {extend && q.data && <ExtendDialog policyId={policyId} version={q.data.version} item={extend} mfa={mfa} onClose={() => setExtend(undefined)} />}
      {del && q.data && <DeleteDialog policyId={policyId} version={q.data.version} item={del} onClose={() => setDel(undefined)} />}
    </div>
  );
}

function ExtendDialog({ policyId, version, item, mfa, onClose }: { policyId: string; version: number; item: PolicyExceptionItem; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [days, setDays] = useState("30");
  const [secret, setSecret] = useState("");
  const n = Number(days);
  const ok = Number.isInteger(n) && n >= 1 && n <= 365;
  const m = useMutation({
    mutationFn: () => policiesApi.extendException(policyId, item.id, { base_version: version, expires_in_days: n, ...(mfa ? { code: secret } : { password: secret }) }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["policies"] });
      onClose();
    },
    onError: () => setSecret(""),
  });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Продлить исключение ${item.id}`} description="Новый срок отсчитывается от сохранения. Появится новая версия политики.">
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok && secret) m.mutate();
        }}
      >
        <Field label="Срок, суток" hint="От 1 до 365." {...(!ok ? { error: "Введите целое число от 1 до 365." } : {})}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} autoFocus inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />}
        </Field>
        <Banner kind="warning">
          Продление ослабляет защиту. Подтвердите, что это вы: введите {mfa ? "код из приложения-аутентификатора" : "текущий пароль"}. Действие запишется в журнал аудита как ослабление.
        </Banner>
        <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
          {({ id }) => <Input id={id} type={mfa ? "text" : "password"} autoComplete={mfa ? "one-time-code" : "current-password"} value={secret} onChange={(e) => setSecret(e.target.value)} />}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={!ok || !secret || m.isPending}>
            Продлить исключение
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function DeleteDialog({ policyId, version, item, onClose }: { policyId: string; version: number; item: PolicyExceptionItem; onClose: () => void }) {
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  const m = useMutation({
    mutationFn: () => policiesApi.deleteException(policyId, item.id, version, comment.trim()),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["policies"] });
      onClose();
    },
  });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Удалить исключение ${item.id}`} description="Удаление усиливает защиту и повторного подтверждения не требует. Появится новая версия политики.">
      <p className="text-sm">{conditionText(item)}</p>
      <Field label="Комментарий (необязательно)">{({ id }) => <Input id={id} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} />}</Field>
      <ErrorBanner error={m.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="danger" disabled={m.isPending} onClick={() => m.mutate()}>
          Удалить исключение
        </Button>
      </div>
    </FormDialog>
  );
}
