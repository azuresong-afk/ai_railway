import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { Field, Input } from "../ui/Field";
import { AuthCard } from "./AuthCard";

// Тексты ошибок входа не различают «нет такого пользователя» и «неверный пароль» (ТЗ 6.4).
export function loginErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток входа. Подождите и повторите.";
  if (e instanceof ApiError && e.status === 503) return "Вход временно недоступен. Обратитесь к администратору.";
  return "Неверный логин или пароль, либо вход сейчас недоступен. Проверьте данные и повторите.";
}

export function Login() {
  const qc = useQueryClient();
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const m = useMutation({
    mutationFn: () => api.login(login.trim(), password),
    onSuccess: (me) => {
      setPassword("");
      qc.setQueryData(["me"], me);
    },
  });
  return (
    <AuthCard
      title="Вход в AISec"
      submit="Войти"
      busy={m.isPending}
      error={m.isError ? loginErrorText(m.error) : undefined}
      onSubmit={() => m.mutate()}
    >
      <Field label="Логин">
        {({ id }) => (
          <Input id={id} autoComplete="username" autoFocus value={login} onChange={(e) => setLogin(e.target.value)} required />
        )}
      </Field>
      <Field label="Пароль">
        {({ id }) => (
          <Input
            id={id}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        )}
      </Field>
    </AuthCard>
  );
}
