import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import type { Me } from "../api/client";
import { Button } from "../ui/Button";
import { Check, Field, Input } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { type AuthPolicy, adminApi } from "./api";
import { ErrorBanner } from "./common";

type NumKey = Exclude<keyof AuthPolicy, "mfa_required_all">;

// Границы и подписи повторяют api/openapi.yaml; окончательную проверку делает сервер.
const fields: { key: NumKey; label: string; hint: string; min: number; max: number }[] = [
  { key: "password_min_length", label: "Минимальная длина пароля", hint: "Символов, от 8 до 64.", min: 8, max: 64 },
  { key: "password_min_classes", label: "Классов символов в пароле", hint: "Строчные, прописные, цифры, прочие: от 1 до 4.", min: 1, max: 4 },
  { key: "password_history", label: "Запомненных паролей", hint: "Новый пароль не совпадает с последними. 0 — не проверять.", min: 0, max: 24 },
  { key: "password_max_age_days", label: "Срок действия пароля, суток", hint: "0 — бессрочно.", min: 0, max: 365 },
  { key: "password_warn_days", label: "Предупреждать за, суток", hint: "О скорой смене пароля.", min: 0, max: 60 },
  { key: "lockout_threshold", label: "Неудачных попыток до блокировки", hint: "От 3 до 20.", min: 3, max: 20 },
  { key: "lockout_minutes", label: "Длительность блокировки, минут", hint: "0 — до разблокировки администратором.", min: 0, max: 1440 },
  { key: "session_idle_minutes", label: "Завершать сессию при бездействии, минут", hint: "От 1 до 240.", min: 1, max: 240 },
  { key: "session_max_per_user", label: "Сессий на пользователя", hint: "Сверх лимита старейшая завершается. От 1 до 20.", min: 1, max: 20 },
  { key: "temp_password_hours", label: "Срок временного пароля, часов", hint: "От 1 до 168.", min: 1, max: 168 },
];

export function PolicyTab({ me }: { me: Me }) {
  const canManage = me.permissions.includes("auth_policy.manage");
  const q = useQuery({ queryKey: ["admin", "policy"], queryFn: ({ signal }) => adminApi.policy(signal) });
  if (q.isError) return <ErrorBanner error={q.error} />;
  if (!q.data) return <p className="text-sm text-muted">Загрузка настроек…</p>;
  return <PolicyForm initial={q.data} canManage={canManage} />;
}

function PolicyForm({ initial, canManage }: { initial: AuthPolicy; canManage: boolean }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<NumKey, string>>(
    () => Object.fromEntries(fields.map((f) => [f.key, String(initial[f.key])])) as Record<NumKey, string>,
  );
  const [mfaAll, setMfaAll] = useState(initial.mfa_required_all);
  const [saved, setSaved] = useState(false);
  const bad = (f: (typeof fields)[number]) => {
    const n = Number(draft[f.key]);
    return draft[f.key] === "" || !Number.isInteger(n) || n < f.min || n > f.max ? `Введите целое число от ${f.min} до ${f.max}.` : undefined;
  };
  const invalid = fields.some((f) => bad(f));
  const m = useMutation({
    mutationFn: () => {
      const body = { mfa_required_all: mfaAll } as AuthPolicy;
      for (const f of fields) body[f.key] = Number(draft[f.key]);
      return adminApi.savePolicy(body);
    },
    onSuccess: (p) => {
      qc.setQueryData(["admin", "policy"], p);
      setSaved(true);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    m.mutate();
  };
  return (
    <form onSubmit={submit} className="flex max-w-2xl flex-col gap-3">
      <p className="text-sm text-muted">Парольная политика, блокировка и сессии (ИАФ.2, ИАФ.4, УПД.4). Изменение записывается в журнал аудита.</p>
      {fields.map((f) => (
        <Field key={f.key} label={f.label} hint={f.hint} error={bad(f)}>
          {({ id, describedBy, invalid: inv }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={inv}
              inputMode="numeric"
              disabled={!canManage}
              value={draft[f.key]}
              onChange={(e) => {
                setSaved(false);
                setDraft({ ...draft, [f.key]: e.target.value });
              }}
            />
          )}
        </Field>
      ))}
      <Check label="Второй фактор обязателен для всех" checked={mfaAll} disabled={!canManage} onCheckedChange={(v) => { setSaved(false); setMfaAll(v); }} />
      <ErrorBanner error={m.error} />
      {saved && <Banner kind="info">Настройки сохранены.</Banner>}
      {canManage ? (
        <div>
          <Button type="submit" variant="primary" disabled={m.isPending || invalid}>
            Сохранить настройки
          </Button>
        </div>
      ) : (
        <p className="text-sm text-muted">Менять настройки может пользователь с правом «Управление политикой входа».</p>
      )}
    </form>
  );
}
