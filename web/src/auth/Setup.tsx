import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { Field, Input } from "../ui/Field";
import { AuthCard } from "./AuthCard";

function setupErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 400) return e.detail;
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток. Подождите и повторите.";
  // 403 не раскрывает причину: токен неверен, истёк, погашен или настройка уже выполнена.
  return "Настройка не выполнена. Проверьте токен из вывода aisec-cli init: он одноразовый и действует 24 часа.";
}

// Первичная настройка (ЗИ.4): первый администратор безопасности по одноразовому токену.
export function Setup({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ token: "", login: "", display_name: "", password: "", repeat: "" });
  const [local, setLocal] = useState<string>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const m = useMutation({
    mutationFn: () =>
      api.setup({ token: f.token.trim(), login: f.login.trim(), display_name: f.display_name.trim(), password: f.password }),
    onSuccess: () => {
      onDone();
      return qc.invalidateQueries({ queryKey: ["setup"] });
    },
  });
  const submit = () => {
    if (f.password !== f.repeat) {
      setLocal("Пароль и повтор не совпадают. Введите их ещё раз.");
      return;
    }
    setLocal(undefined);
    m.mutate();
  };
  return (
    <AuthCard
      title="Первичная настройка"
      intro="Создайте первого администратора безопасности. Токен выводит команда aisec-cli init."
      submit="Создать администратора"
      busy={m.isPending}
      error={local ?? (m.isError ? setupErrorText(m.error) : undefined)}
      onSubmit={submit}
    >
      <Field label="Токен настройки">
        {({ id }) => <Input id={id} type="password" autoComplete="off" autoFocus value={f.token} onChange={set("token")} required />}
      </Field>
      <Field label="Логин" hint="Латиница, цифры, «.», «_», «-», до 64 символов.">
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} autoComplete="username" value={f.login} onChange={set("login")} required />}
      </Field>
      <Field label="Имя в интерфейсе">
        {({ id }) => <Input id={id} autoComplete="name" value={f.display_name} onChange={set("display_name")} required />}
      </Field>
      <Field label="Пароль">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={f.password} onChange={set("password")} required />}
      </Field>
      <Field label="Пароль ещё раз">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={f.repeat} onChange={set("repeat")} required />}
      </Field>
    </AuthCard>
  );
}
