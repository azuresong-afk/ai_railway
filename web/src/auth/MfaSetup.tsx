import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api, type RecoveryCodes } from "../api/client";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, Panel, RawText } from "../ui/Layout";
import { AuthCard } from "./AuthCard";
import { QrSvg } from "./QrSvg";

function setupErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток. Подождите и повторите.";
  if (e instanceof ApiError && e.status === 503) return "Второй фактор сейчас недоступен. Обратитесь к администратору.";
  if (e instanceof ApiError && e.status === 409) return "Подключение недоступно в этой сессии. Войдите заново.";
  return "Код не подошёл. Проверьте код в приложении и время на устройстве, затем повторите.";
}

// Подключение второго фактора: QR и секрет показываются один раз, затем коды восстановления.
export function MfaSetup({ onCancel }: { onCancel: () => void }) {
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<RecoveryCodes | null>(null);
  const start = useMutation({ mutationFn: () => api.mfaSetup() });
  const confirm = useMutation({
    mutationFn: () => api.mfaConfirm(code.trim()),
    onSuccess: (r) => setCodes(r),
  });

  if (codes) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4">
        <Panel className="w-full max-w-sm space-y-4 p-6">
          <h1 className="text-xl font-semibold">Коды восстановления</h1>
          <Banner kind="warning">
            Сохраните коды сейчас: они показываются один раз. Каждый код подходит для одного входа без приложения.
          </Banner>
          <RawText>{codes.recovery_codes.join("\n")}</RawText>
          <Button variant="primary" className="w-full" onClick={() => void qc.invalidateQueries({ queryKey: ["me"] })}>
            Я сохранил коды, продолжить
          </Button>
        </Panel>
      </main>
    );
  }

  if (!start.data) {
    return (
      <AuthCard
        title="Подключите второй фактор"
        intro="Для вашей роли второй фактор обязателен. Понадобится приложение-аутентификатор на телефоне."
        submit="Показать QR-код"
        busy={start.isPending}
        error={start.isError ? setupErrorText(start.error) : undefined}
        onSubmit={() => start.mutate()}
        footer={
          <Button variant="ghost" onClick={onCancel}>
            Выйти
          </Button>
        }
      >
        <span />
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Подключите второй фактор"
      intro="Отсканируйте QR-код в приложении-аутентификаторе и введите шестизначный код."
      submit="Подключить"
      busy={confirm.isPending}
      error={confirm.isError ? setupErrorText(confirm.error) : undefined}
      onSubmit={() => confirm.mutate()}
    >
      <div className="flex justify-center">
        <QrSvg rows={start.data.qr} label="QR-код для приложения-аутентификатора" />
      </div>
      <Field label="Секрет для ручного ввода" hint="Показывается один раз.">
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} readOnly value={start.data.secret} className="font-mono" />}
      </Field>
      <Field label="Код из приложения">
        {({ id }) => (
          <Input id={id} autoComplete="one-time-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required />
        )}
      </Field>
    </AuthCard>
  );
}
