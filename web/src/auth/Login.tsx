import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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

// Отказ входа через IdP приходит в адресе /?oidc=код; причина — в журнале аудита, не в адресе (ADR-0025).
export function oidcErrorText(code: string | null): string | undefined {
  switch (code) {
    case null:
      return undefined;
    case "denied":
      return "Вход через IdP отклонён: у учётной записи нет доступа к консоли, роль не определена или не подтверждён второй фактор. Обратитесь к администратору.";
    case "unavailable":
      return "Вход через IdP сейчас недоступен. Войдите по логину и паролю или обратитесь к администратору.";
    default:
      return "Вход через IdP прерван или устарел. Начните вход заново.";
  }
}

// Код отказа читается один раз и убирается из адреса, чтобы не остаться после обновления страницы.
function takeOIDCError(): string | undefined {
  const params = new URLSearchParams(window.location.search);
  const text = oidcErrorText(params.get("oidc"));
  if (text) {
    params.delete("oidc");
    const rest = params.toString();
    window.history.replaceState(null, "", window.location.pathname + (rest ? `?${rest}` : ""));
  }
  return text;
}

export function Login() {
  const qc = useQueryClient();
  const [oidcError] = useState(takeOIDCError);
  const idp = useQuery({ queryKey: ["oidc-option"], queryFn: ({ signal }) => api.oidcOption(signal), retry: false });
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
      error={m.isError ? loginErrorText(m.error) : oidcError}
      onSubmit={() => m.mutate()}
      footer={
        idp.data?.enabled && idp.data.display_name ? (
          <div className="space-y-2 border-t border-line pt-4">
            {/* Переход браузера, а не запрос: IdP открывается в том же окне. */}
            <a
              href="/api/v1/auth/oidc/start"
              className="inline-flex h-[var(--control-h)] w-full items-center justify-center rounded-control border border-line-strong bg-surface px-3 text-base font-medium text-fg hover:bg-surface-hover"
            >
              Войти через {idp.data.display_name}
            </a>
          </div>
        ) : null
      }
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
