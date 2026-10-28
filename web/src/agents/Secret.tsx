import { ApiError } from "../api/client";
import { Field, Input } from "../ui/Field";

// Поле повторной проверки: пароль или код второго фактора, если он подключён. Значение живёт только в состоянии формы.
export function SecretField({ mfa, value, onChange }: { mfa: boolean; value: string; onChange: (v: string) => void }) {
  return (
    <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
      {({ id }) => (
        <Input
          id={id}
          autoComplete={mfa ? "one-time-code" : "current-password"}
          type={mfa ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </Field>
  );
}

// Поля для тела запроса: ровно одно из password и code.
export function secretBody(mfa: boolean, secret: string): { password: string } | { code: string } | Record<string, never> {
  return secret === "" ? {} : mfa ? { code: secret } : { password: secret };
}

// Текст ошибки с учётом конфликта 409 (ADR-0023): описание или запрос изменились, пока открыт диалог.
export function isConflict(e: unknown): boolean {
  return e instanceof ApiError && e.status === 409;
}

export function conflictText(e: unknown, text: string): string | null {
  return isConflict(e) ? text : null;
}
