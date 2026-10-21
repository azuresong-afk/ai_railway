import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { AuthCard } from "./AuthCard";

function verifyErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток. Подождите и повторите.";
  if (e instanceof ApiError && e.status === 409) return "Время ввода кода истекло. Войдите заново.";
  return "Код не подошёл. Проверьте код в приложении и время на устройстве, затем повторите.";
}

// Второй шаг входа: код из приложения или одноразовый код восстановления.
export function MfaVerify({ onCancel }: { onCancel: () => void }) {
  const qc = useQueryClient();
  const [recovery, setRecovery] = useState(false);
  const [value, setValue] = useState("");
  const m = useMutation({
    mutationFn: () => api.mfaVerify(recovery ? { recovery_code: value.trim() } : { code: value.trim() }),
    onSuccess: (me) => qc.setQueryData(["me"], me),
  });
  return (
    <AuthCard
      title="Второй фактор"
      intro={
        recovery
          ? "Введите один из кодов восстановления. Каждый код действует один раз."
          : "Введите шестизначный код из приложения-аутентификатора."
      }
      submit="Подтвердить"
      busy={m.isPending}
      error={m.isError ? verifyErrorText(m.error) : undefined}
      onSubmit={() => m.mutate()}
      footer={
        <div className="flex justify-between">
          <Button
            variant="ghost"
            onClick={() => {
              setRecovery(!recovery);
              setValue("");
              m.reset();
            }}
          >
            {recovery ? "Ввести код из приложения" : "Использовать код восстановления"}
          </Button>
          <Button variant="ghost" onClick={onCancel}>
            Отмена
          </Button>
        </div>
      }
    >
      <Field label={recovery ? "Код восстановления" : "Код из приложения"}>
        {({ id }) => (
          <Input
            id={id}
            key={String(recovery)}
            autoFocus
            autoComplete="one-time-code"
            inputMode={recovery ? "text" : "numeric"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
          />
        )}
      </Field>
    </AuthCard>
  );
}
