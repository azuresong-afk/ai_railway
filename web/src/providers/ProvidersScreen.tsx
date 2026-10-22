import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ConfirmDialog, ErrorBanner, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { type Provider, providersApi } from "./api";
import { ProviderDialog } from "./ProviderDialog";

const typeText = new Map<Provider["type"], string>([
  ["openai", "OpenAI-совместимый"],
  ["gigachat", "GigaChat"],
  ["yandexgpt", "YandexGPT"],
]);

// Учётные данные: только ввод. Значение живёт в состоянии формы и стирается при закрытии и после успеха.
function CredentialDialog({ provider, onClose }: { provider: Provider; onClose: () => void }) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const m = useMutation({
    mutationFn: () => providersApi.setCredential(provider.id, value),
    onSuccess: async () => {
      setValue("");
      await qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
  });
  const close = () => {
    setValue("");
    m.reset();
    onClose();
  };
  const bad = value === "" ? "Введите ключ или данные доступа." : /^[\x20-\x7e]+$/.test(value) ? undefined : "Только видимые символы ASCII и пробел.";
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!bad) m.mutate();
  };
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={`Учётные данные: ${provider.name}`}
      description="Значение шифруется и больше нигде не показывается. Новое значение заменяет прежнее."
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Ключ API или авторизационные данные" error={value === "" ? undefined : bad}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} type="password" autoComplete="off" maxLength={16384} value={value} onChange={(e) => setValue(e.target.value)} />
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || Boolean(bad)}>
            Сохранить учётные данные
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

// Признак «внешний». Снятие — ослабление (DM-40): данные к провайдеру перестают маскироваться в режиме мониторинга.
// Нужны причина и текущий пароль или код. Возврат признака пароля не требует.
function ExternalDialog({ provider, mfa, onClose }: { provider: Provider; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const target = !provider.external;
  const [reason, setReason] = useState("");
  const [secret, setSecret] = useState("");
  const m = useMutation({
    mutationFn: () =>
      providersApi.setExternal(provider.id, {
        external: target,
        reason: reason.trim(),
        // Снятие требует подтверждения сразу; поле пароля или кода видно с начала.
        ...(!target && secret !== "" ? (mfa ? { code: secret } : { password: secret }) : {}),
      }),
    onSuccess: async () => {
      setSecret("");
      await qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
    onError: () => setSecret(""),
  });
  const close = () => {
    setSecret("");
    m.reset();
    onClose();
  };
  const ready = reason.trim() !== "" && (target || secret !== "");
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={target ? `Вернуть признак «внешний»: ${provider.name}` : `Снять признак «внешний»: ${provider.name}`}
      description={
        target
          ? "Данные к этому провайдеру снова будут маскироваться."
          : "Провайдер будет считаться внутренним контуром заказчика: в режиме «Мониторинг» данные к нему перестанут маскироваться. Действие записывается в журнал аудита как ослабление."
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) m.mutate();
        }}
        className="flex flex-col gap-3"
      >
        <Field label="Причина" hint="До 500 знаков, попадёт в журнал аудита.">
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
        {!target && (
          <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
            {({ id }) => (
              <Input id={id} autoComplete={mfa ? "one-time-code" : "current-password"} type={mfa ? "text" : "password"} value={secret} onChange={(e) => setSecret(e.target.value)} />
            )}
          </Field>
        )}
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant={target ? "primary" : "danger"} disabled={m.isPending || !ready}>
            {target ? "Вернуть признак" : "Снять признак «внешний»"}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

// Экран «Провайдеры» (Н44): список, создание, учётные данные, признак «внешний». Кнопки показываются по правам из сессии,
// решение о доступе принимает сервер (providers.external — только администратор безопасности).
export function ProvidersScreen({ me }: { me: Me }) {
  const qc = useQueryClient();
  const has = (p: string) => me.permissions.includes(p);
  const q = useQuery({ queryKey: ["providers", "list"], queryFn: ({ signal }) => providersApi.list(signal) });
  const [edit, setEdit] = useState<{ provider: Provider | null }>();
  const [cred, setCred] = useState<Provider>();
  const [ext, setExt] = useState<Provider>();
  const [del, setDel] = useState<Provider>();
  const delM = useMutation({
    mutationFn: (p: Provider) => providersApi.remove(p.id),
    onSuccess: async () => {
      setDel(undefined);
      await qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
  const canManage = has("providers.manage");

  return (
    <section aria-label="Провайдеры" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Провайдеры</h1>
        {canManage && (
          <Button variant="primary" onClick={() => setEdit({ provider: null })}>
            Создать провайдера
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка провайдеров…</p>}
      {q.data && q.data.items.length === 0 && (
        <EmptyState
          title="Провайдеров пока нет"
          action={canManage ? <Button variant="primary" onClick={() => setEdit({ provider: null })}>Создать первого провайдера</Button> : <p className="text-sm text-muted">Провайдера создаёт администратор.</p>}
        />
      )}
      {q.data && q.data.items.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>ID</Th>
                <Th>Тип</Th>
                <Th>Адрес</Th>
                <Th>Контур</Th>
                <Th>Учётные данные</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((p) => (
                <tr key={p.id}>
                  <Td>{p.name}</Td>
                  <Td className="font-mono">{p.slug}</Td>
                  <Td>{typeText.get(p.type)}</Td>
                  <Td className="font-mono text-sm">{p.base_url}</Td>
                  <Td>{p.external ? "Внешний" : "Внутренний"}</Td>
                  <Td>{p.credential_set ? `Заданы (${p.credential_set_at ? formatAbsolute(p.credential_set_at) : "время неизвестно"})` : "Не заданы"}</Td>
                  <Td>
                    <span className="flex flex-wrap gap-2">
                      {canManage && (
                        <>
                          <Button onClick={() => setEdit({ provider: p })} aria-label={`Изменить провайдера ${p.name}`}>
                            Изменить
                          </Button>
                          <Button onClick={() => setCred(p)} aria-label={`Учётные данные ${p.name}`}>
                            Учётные данные
                          </Button>
                        </>
                      )}
                      {has("providers.external") && (
                        <Button onClick={() => setExt(p)} aria-label={`Признак «внешний» ${p.name}`}>
                          Признак «внешний»
                        </Button>
                      )}
                      {canManage && (
                        <Button
                          variant="danger"
                          aria-label={`Удалить провайдера ${p.name}`}
                          onClick={() => {
                            delM.reset();
                            setDel(p);
                          }}
                        >
                          Удалить
                        </Button>
                      )}
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {q.data && q.data.items.some((p) => !p.credential_set) && <Banner kind="info">У провайдеров без учётных данных шлюз не сможет отправлять запросы.</Banner>}
      {edit && <ProviderDialog key={edit.provider?.id ?? "new"} provider={edit.provider} onClose={() => setEdit(undefined)} />}
      {cred && <CredentialDialog key={cred.id} provider={cred} onClose={() => setCred(undefined)} />}
      {ext && <ExternalDialog key={ext.id} provider={ext} mfa={me.mfa?.enabled === true} onClose={() => setExt(undefined)} />}
      <ConfirmDialog
        open={del !== undefined}
        onOpenChange={(v) => !v && setDel(undefined)}
        title="Удалить провайдера"
        description={<>Провайдер «{del?.name}» и его учётные данные будут удалены. Нельзя удалить провайдера, указанного в приложении, в том числе в архивном.</>}
        actionLabel="Удалить провайдера"
        busy={delM.isPending}
        error={delM.error}
        onConfirm={() => del && delM.mutate(del)}
      />
    </section>
  );
}
