import * as AlertDialog from "@radix-ui/react-alert-dialog";
import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { ApiError } from "../api/client";
import { Button } from "../ui/Button";
import { Banner } from "../ui/Layout";

const layer = "rounded-panel border border-line bg-surface text-fg shadow-popup";
const overlay = "fixed inset-0 bg-[var(--c-overlay)]";
const box = `${layer} fixed top-1/2 left-1/2 max-h-[90vh] w-[32rem] max-w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-auto p-5`;

// Текст ошибки для человека (ТЗ 6.7): русский detail сервера, а если ответа нет — совет про связь.
export function describeError(e: unknown): string {
  if (!(e instanceof ApiError)) return "Нет связи с сервером. Проверьте сеть и повторите.";
  switch (e.status) {
    case 401:
      return "Сессия завершена. Войдите снова.";
    case 403:
      return `Сервер отказал в действии. ${e.detail}`;
    case 413:
    case 415:
      return "Запрос отклонён сервером. Обновите страницу и повторите.";
    case 429:
      return "Слишком много запросов. Подождите минуту и повторите.";
    case 500:
      return "Внутренняя ошибка сервера. Повторите позже или обратитесь к администратору.";
    case 503:
      return "Сервер временно недоступен. Повторите позже.";
    default:
      return e.detail;
  }
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  return <Banner kind="error">{describeError(error)}</Banner>;
}

// Диалог с формой под управлением экрана: закрытие сбрасывает состояние, которое держит родитель.
export function FormDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={overlay} />
        <Dialog.Content className={box} {...(description ? {} : { "aria-describedby": undefined })}>
          <Dialog.Title className="text-lg font-semibold">{title}</Dialog.Title>
          {description && <Dialog.Description className="mt-1 text-base text-muted">{description}</Dialog.Description>}
          <div className="mt-4 flex flex-col gap-3">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// Подтверждение действия под управлением экрана: при отказе сервера диалог остаётся с ошибкой.
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  actionLabel,
  busy,
  error,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description: ReactNode;
  actionLabel: string;
  busy: boolean;
  error: unknown;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className={overlay} />
        <AlertDialog.Content className={box}>
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description asChild>
            <div className="mt-1 text-base text-muted">{description}</div>
          </AlertDialog.Description>
          {error ? (
            <div className="mt-3">
              <ErrorBanner error={error} />
            </div>
          ) : null}
          <div className="mt-5 flex justify-end gap-2">
            <AlertDialog.Cancel asChild>
              <Button>Отменить</Button>
            </AlertDialog.Cancel>
            <Button variant="danger" disabled={busy} onClick={onConfirm}>
              {actionLabel}
            </Button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

// Значение «один раз» (временный пароль, токен): живёт в состоянии диалога и стирается при закрытии.
export function SecretDialog({
  open,
  onClose,
  title,
  description,
  label,
  value,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  label: string;
  value: string;
}) {
  return (
    <FormDialog open={open} onOpenChange={(v) => !v && onClose()} title={title} description={description}>
      <label className="flex flex-col gap-1 text-sm font-medium">
        {label}
        <input
          readOnly
          value={value}
          onFocus={(e) => e.currentTarget.select()}
          className="h-[var(--control-h)] w-full rounded-control border border-line-strong bg-bg px-2 font-mono text-base"
        />
      </label>
      <Banner kind="warning">Значение показано один раз. После закрытия окна его нельзя будет посмотреть.</Banner>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onClose}>
          Я сохранил значение
        </Button>
      </div>
    </FormDialog>
  );
}
