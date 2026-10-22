import { useState } from "react";
import { ApiError } from "../api/client";
import { Field, Input } from "../ui/Field";
import { Banner } from "../ui/Layout";

// Поля повторной проверки в теле запроса: второй фактор, если подключён, иначе пароль (Н32, В23–В26 ревью 2.r5).
export type ReauthBody = { password: string } | { code: string } | Record<string, never>;

// Сервер просит повторную проверку: изменение ослабляет защиту, а пароля или кода в запросе нет (400 с полем password).
export function needsReauth(e: unknown): boolean {
  return e instanceof ApiError && e.status === 400 && e.fields.some((f) => f.field === "password" || f.field === "code");
}

// Повторная проверка по ответу сервера: консоль не угадывает, что считается ослаблением, — это решает сервер.
// Пароль или код живёт только в состоянии формы и стирается после успеха и при закрытии.
export function useReauth(mfa: boolean) {
  const [needed, setNeeded] = useState(false);
  const [secret, setSecret] = useState("");
  return {
    mfa,
    needed,
    secret,
    setSecret,
    // Поля для тела запроса; пусто, пока сервер не попросил подтверждение.
    body: (): ReauthBody => (needed && secret !== "" ? (mfa ? { code: secret } : { password: secret }) : {}),
    // Можно отправлять: подтверждение не нужно или уже введено.
    ready: !needed || secret !== "",
    onError: (e: unknown) => {
      if (needsReauth(e)) setNeeded(true);
      setSecret("");
    },
    reset: () => {
      setNeeded(false);
      setSecret("");
    },
  };
}

export type Reauth = ReturnType<typeof useReauth>;

// Ошибка для баннера: просьбу о подтверждении показывает ReauthPrompt, а не баннер ошибки.
export function visibleError(e: unknown): unknown {
  return needsReauth(e) ? null : e;
}

export function ReauthPrompt({ r }: { r: Reauth }) {
  if (!r.needed) return null;
  return (
    <>
      <Banner kind="warning">
        Изменение ослабляет защиту. Подтвердите, что это вы: введите {r.mfa ? "код из приложения-аутентификатора" : "текущий пароль"} и повторите.
        Действие запишется в журнал аудита как ослабление.
      </Banner>
      <Field label={r.mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
        {({ id }) => (
          <Input
            id={id}
            autoFocus
            autoComplete={r.mfa ? "one-time-code" : "current-password"}
            type={r.mfa ? "text" : "password"}
            value={r.secret}
            onChange={(e) => r.setSecret(e.target.value)}
          />
        )}
      </Field>
    </>
  );
}
