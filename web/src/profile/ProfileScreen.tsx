import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, type Me, request } from "../api/client";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, Panel } from "../ui/Layout";

function errorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 400) return e.detail;
  if (e instanceof ApiError && e.status === 429) return "Слишком много запросов. Подождите и повторите.";
  return "Адрес не сохранён. Повторите попытку позже.";
}

// Профиль пользователя: свои данные и e-mail для рассылки отчётов (задача 4.6). Меняется только своя запись.
export function ProfileScreen({ me }: { me: Me }) {
  const qc = useQueryClient();
  const [email, setEmail] = useState(me.user.email);
  const [saved, setSaved] = useState(false);
  const m = useMutation({
    mutationFn: () => request<unknown>("PUT", "/api/v1/me/email", { email: email.trim() }),
    onSuccess: () => {
      setSaved(true);
      void qc.invalidateQueries({ queryKey: ["me"] });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    m.mutate();
  };
  return (
    <div className="flex max-w-xl flex-col gap-4">
      <h1 className="text-xl font-semibold">Профиль</h1>
      <Panel>
        <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-base">
          <dt className="text-muted">Логин</dt>
          <dd>{me.user.login}</dd>
          <dt className="text-muted">Имя</dt>
          <dd>{me.user.display_name}</dd>
          <dt className="text-muted">Роль</dt>
          <dd>{me.user.role}</dd>
        </dl>
      </Panel>
      <form noValidate onSubmit={submit} className="flex flex-col gap-3">
        <Field label="E-mail для рассылки отчётов" hint="Вида user@example.ru. Проверочное письмо не отправляется. Пустое поле убирает адрес.">
          {({ id, describedBy }) => (
            <Input id={id} type="email" autoComplete="email" aria-describedby={describedBy} value={email} onChange={(e) => setEmail(e.target.value)} />
          )}
        </Field>
        {m.isError && <Banner kind="error">{errorText(m.error)}</Banner>}
        {saved && <Banner kind="info">Сохранено.</Banner>}
        <div>
          <Button type="submit" variant="primary" disabled={m.isPending || email.trim() === me.user.email}>
            Сохранить
          </Button>
        </div>
      </form>
    </div>
  );
}
