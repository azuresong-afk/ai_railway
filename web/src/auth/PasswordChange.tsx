import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { AuthCard } from "./AuthCard";

function changeErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 400) return e.detail;
  if (e instanceof ApiError && e.status === 409) return "Учётная запись заблокирована. Попробуйте позже или обратитесь к администратору.";
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток. Подождите и повторите.";
  return "Пароль не изменён. Повторите попытку позже.";
}

// Смена временного или истёкшего пароля (ИАФ.3): до неё доступны только этот экран и выход.
export function PasswordChange({ onCancel }: { onCancel: () => void }) {
  const qc = useQueryClient();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [local, setLocal] = useState<string>();
  const m = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["me"] }),
  });
  const submit = () => {
    if (next !== repeat) {
      setLocal("Новый пароль и повтор не совпадают. Введите их ещё раз.");
      return;
    }
    setLocal(undefined);
    m.mutate();
  };
  return (
    <AuthCard
      title="Смена пароля"
      intro="Пароль временный или истёк. Задайте новый, чтобы продолжить."
      submit="Сменить пароль"
      busy={m.isPending}
      error={local ?? (m.isError ? changeErrorText(m.error) : undefined)}
      onSubmit={submit}
      footer={
        <Button variant="ghost" onClick={onCancel}>
          Выйти
        </Button>
      }
    >
      <Field label="Текущий пароль">
        {({ id }) => <Input id={id} type="password" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} required />}
      </Field>
      <Field label="Новый пароль">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />}
      </Field>
      <Field label="Новый пароль ещё раз">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} required />}
      </Field>
    </AuthCard>
  );
}
