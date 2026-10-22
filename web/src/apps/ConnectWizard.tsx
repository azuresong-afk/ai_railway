import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError } from "../api/client";
import { ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, RawText } from "../ui/Layout";
import { type Application, appsApi, gatewayExample, type NewApplication, slugPattern, splitList, suggestSlug } from "./api";
import { ShownKey } from "./ShownKey";

type Step = "app" | "provider" | "key" | "done";
const steps: [Step, string][] = [
  ["app", "Приложение"],
  ["provider", "Провайдер и политика"],
  ["key", "Ключ"],
  ["done", "Готово"],
];

const modelPattern = /^[A-Za-z0-9._:/-]{1,128}$/;
const cidrPattern = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

// Мастер подключения (ТЗ 6.4, п. 5): приложение, провайдер и политика, ключ, пример запроса. Приложение создаётся
// в конце третьего шага вместе с ключом; если ключ выпустить не удалось, приложение остаётся и ключ выпускается повторно.
export function ConnectWizard({
  open,
  onClose,
  canPolicy,
  canKey,
  mfa,
}: {
  open: boolean;
  onClose: () => void;
  canPolicy: boolean;
  canKey: boolean;
  mfa: boolean;
}) {
  const qc = useQueryClient();
  const [step, setStep] = useState<Step>("app");
  const [f, setF] = useState({
    name: "", slug: "", slugTouched: false, env: "prod", description: "", department: "",
    provider_id: "", models: "", policy: "", policy_mode: "", storage: "",
    key_name: "основной", expires_in_days: "365", cidrs: "",
  });
  const [created, setCreated] = useState<Application>();
  const [secret, setSecret] = useState<string>();
  // Режим «Мониторинг», «Не хранить» или «Полное» ослабляют защиту: сервер просит пароль или код (В25 ревью 2.r5).
  const re = useReauth(mfa);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));

  const providers = useQuery({ queryKey: ["apps", "providers"], queryFn: ({ signal }) => appsApi.providers(signal), enabled: open });
  const policies = useQuery({ queryKey: ["apps", "policies"], queryFn: ({ signal }) => appsApi.policies(signal), enabled: open && canPolicy });

  const models = splitList(f.models);
  const cidrs = splitList(f.cidrs);
  const days = Number(f.expires_in_days);
  const errs = {
    name: f.name.trim() === "" ? "Введите название приложения." : undefined,
    slug: slugPattern.test(f.slug) ? undefined : "ID: латиница в нижнем регистре, цифры и «-», начинается с буквы или цифры, до 63 символов.",
    provider: f.provider_id === "" ? "Выберите провайдера." : undefined,
    models:
      models.length === 0
        ? "Укажите хотя бы одну модель."
        : models.length > 100 || models.some((m) => !modelPattern.test(m))
          ? "Модели: до 100, каждая из латиницы, цифр и символов «. _ : / -»."
          : undefined,
    keyName: f.key_name.trim() === "" ? "Введите название ключа." : undefined,
    days: !Number.isInteger(days) || days < 1 || days > 730 ? "Срок ключа — целое число суток от 1 до 730." : undefined,
    cidrs: cidrs.length > 64 || cidrs.some((c) => !cidrPattern.test(c)) ? "Подсети в виде 10.0.0.0/8, не больше 64." : undefined,
  };

  const reset = () => {
    setStep("app");
    setF((p) => ({ ...p, name: "", slug: "", slugTouched: false, description: "", department: "", provider_id: "", models: "", policy: "", policy_mode: "", storage: "", key_name: "основной", expires_in_days: "365", cidrs: "" }));
    setCreated(undefined);
    setSecret(undefined);
    re.reset();
    create.reset();
  };
  const close = () => {
    // Ключ стирается из состояния при любом закрытии.
    setSecret(undefined);
    reset();
    onClose();
  };

  const create = useMutation({
    mutationFn: async () => {
      let app = created;
      if (!app) {
        // Поля с умолчаниями на сервере (storage, fail_mode) не отправляются: без права applications.policy сервер отвечает на них 422.
        const body = {
          slug: f.slug,
          name: f.name.trim(),
          env: f.env as "prod" | "test",
          provider_id: f.provider_id,
          models,
          user_from: "none",
          ...(f.description.trim() ? { description: f.description.trim() } : {}),
          ...(f.department.trim() ? { department: f.department.trim() } : {}),
          // Поля защиты сервер принимает только при праве applications.policy; пустые не отправляются.
          ...(canPolicy && f.policy ? { policy: f.policy } : {}),
          ...(canPolicy && f.policy_mode ? { policy_mode: f.policy_mode as "monitor" | "enforce" } : {}),
          ...(canPolicy && f.storage ? { storage: f.storage as "none" | "masked" | "full" } : {}),
          ...re.body(),
        } as NewApplication;
        app = await appsApi.create(body);
        re.reset();
        setCreated(app);
        await qc.invalidateQueries({ queryKey: ["apps", "list"] });
      }
      if (canKey) {
        const k = await appsApi.issueKey(app.id, {
          name: f.key_name.trim(),
          expires_in_days: days,
          ...(cidrs.length > 0 ? { allowed_cidrs: cidrs } : {}),
        });
        setSecret(k.key);
        await qc.invalidateQueries({ queryKey: ["apps", "keys", app.id] });
      }
    },
    onSuccess: () => setStep("done"),
    onError: re.onError,
  });

  const next = (to: Step, bad: boolean) => (e: FormEvent) => {
    e.preventDefault();
    if (!bad) setStep(to);
  };
  const submitKey = (e: FormEvent) => {
    e.preventDefault();
    if (!(canKey && (errs.keyName || errs.days || errs.cidrs)) && re.ready) create.mutate();
  };

  const idx = steps.findIndex(([s]) => s === step);
  const providerList = providers.data?.items ?? [];
  const chosen = providerList.find((p) => p.id === f.provider_id);

  return (
    <FormDialog
      open={open}
      onOpenChange={(v) => !v && step !== "done" && close()}
      title="Подключение приложения"
      description={`Шаг ${idx + 1} из ${steps.length}: ${steps.at(idx)?.[1] ?? ""}.`}
    >
      {step === "app" && (
        <form onSubmit={next("provider", Boolean(errs.name || errs.slug))} className="flex flex-col gap-3">
          <Field label="Название" error={f.name !== "" ? errs.name : undefined}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                autoFocus
                value={f.name}
                onChange={(e) => setF((p) => ({ ...p, name: e.target.value, slug: p.slugTouched ? p.slug : suggestSlug(e.target.value) }))}
              />
            )}
          </Field>
          <Field label="ID приложения" hint="Попадает в события и пакет для шлюза; потом не меняется." error={f.slug !== "" ? errs.slug : undefined}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={f.slug}
                onChange={(e) => setF((p) => ({ ...p, slug: e.target.value, slugTouched: true }))}
              />
            )}
          </Field>
          <Field label="Среда">
            {({ id }) => (
              <Select id={id} value={f.env} onChange={set("env")}>
                <option value="prod">Промышленная</option>
                <option value="test">Тестовая</option>
              </Select>
            )}
          </Field>
          <Field label="Подразделение (необязательно)">
            {({ id }) => <Input id={id} value={f.department} onChange={set("department")} maxLength={200} />}
          </Field>
          <Field label="Описание (необязательно)">
            {({ id }) => <Input id={id} value={f.description} onChange={set("description")} maxLength={2000} />}
          </Field>
          <Nav onCancel={close} nextLabel="Далее: провайдер и политика" nextDisabled={Boolean(errs.name || errs.slug)} />
        </form>
      )}

      {step === "provider" && (
        <form onSubmit={next("key", Boolean(errs.provider || errs.models))} className="flex flex-col gap-3">
          <ErrorBanner error={providers.error} />
          <Field label="Провайдер" error={providers.isSuccess && providerList.length === 0 ? "Провайдеров нет. Провайдера пока добавляют через API (/api/v1/providers), см. руководство администратора, раздел 5." : undefined}>
            {({ id, describedBy, invalid }) => (
              <Select id={id} aria-describedby={describedBy} aria-invalid={invalid} value={f.provider_id} onChange={set("provider_id")}>
                <option value="">Выберите провайдера</option>
                {providerList.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                    {p.external ? " (внешний)" : ""}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {chosen?.external && (
            <Banner kind="info">Провайдер вне контура заказчика: данные уходят за его пределы, поэтому защита будет строже.</Banner>
          )}
          <Field label="Разрешённые модели" hint="По одной на строку или через запятую." error={f.models !== "" ? errs.models : undefined}>
            {({ id, describedBy, invalid }) => (
              <textarea
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                rows={3}
                value={f.models}
                onChange={set("models")}
                className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-base aria-[invalid=true]:border-sev-critical"
              />
            )}
          </Field>
          {canPolicy ? (
            <>
              <ErrorBanner error={policies.error} />
              <Field label="Политика" hint="Пусто — «Базовая защита».">
                {({ id, describedBy }) => (
                  <Select id={id} aria-describedby={describedBy} value={f.policy} onChange={set("policy")}>
                    <option value="">Базовая защита (по умолчанию)</option>
                    {(policies.data?.items ?? []).map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                        {p.template ? " (шаблон)" : ""}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label="Режим политики" hint="«Мониторинг» только фиксирует нарушения и защиту ослабляет.">
                {({ id, describedBy }) => (
                  <Select id={id} aria-describedby={describedBy} value={f.policy_mode} onChange={set("policy_mode")}>
                    <option value="">Как в политике</option>
                    <option value="enforce">Защита (enforce)</option>
                    <option value="monitor">Мониторинг (monitor)</option>
                  </Select>
                )}
              </Field>
              <Field label="Хранение содержимого" hint="По умолчанию — режим из «Администрирования» → «Время и хранение».">
                {({ id, describedBy }) => (
                  <Select id={id} aria-describedby={describedBy} value={f.storage} onChange={set("storage")}>
                    <option value="">Как в настройках установки</option>
                    <option value="masked">Маскированное</option>
                    <option value="none">Не хранить</option>
                    <option value="full">Полное (повышенный риск)</option>
                  </Select>
                )}
              </Field>
            </>
          ) : (
            <Banner kind="info">Политика и режимы защиты назначаются администратором безопасности. Сейчас приложение получит «Базовую защиту».</Banner>
          )}
          <Nav onCancel={close} onBack={() => setStep("app")} nextLabel="Далее: ключ" nextDisabled={Boolean(errs.provider || errs.models)} />
        </form>
      )}

      {step === "key" && (
        <form onSubmit={submitKey} className="flex flex-col gap-3">
          {created && <Banner kind="warning">Приложение «{created.name}» уже создано, но ключ выпустить не удалось. Повторите выпуск ключа.</Banner>}
          {canKey ? (
            <>
              <Field label="Название ключа" error={errs.keyName}>
                {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} value={f.key_name} onChange={set("key_name")} maxLength={200} />}
              </Field>
              <Field label="Срок действия, суток" hint="От 1 до 730." error={errs.days}>
                {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={f.expires_in_days} onChange={set("expires_in_days")} />}
              </Field>
              <Field label="Разрешённые подсети (необязательно)" hint="Ключ примут только с этих адресов, например 10.0.0.0/8. Пусто — с любых." error={errs.cidrs}>
                {({ id, describedBy, invalid }) => (
                  <textarea
                    id={id}
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    rows={2}
                    value={f.cidrs}
                    onChange={set("cidrs")}
                    className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-base aria-[invalid=true]:border-sev-critical"
                  />
                )}
              </Field>
            </>
          ) : (
            <Banner kind="info">У вас нет права выпускать ключи. Приложение будет создано, ключ выпустит администратор.</Banner>
          )}
          <ReauthPrompt r={re} />
          <ErrorBanner error={visibleError(create.error)} />
          {create.error instanceof ApiError && create.error.status === 409 && !created && (
            <p className="text-sm text-muted">Вернитесь на первый шаг и выберите другой ID приложения.</p>
          )}
          <Nav
            onCancel={close}
            onBack={() => setStep("provider")}
            nextLabel={canKey ? (created ? "Выпустить ключ" : "Создать приложение и выпустить ключ") : "Создать приложение"}
            nextDisabled={create.isPending || !re.ready || (canKey && Boolean(errs.keyName || errs.days || errs.cidrs))}
          />
        </form>
      )}

      {step === "done" && (
        <div className="flex flex-col gap-3">
          <Banner kind="info">Приложение «{created?.name ?? f.name}» создано.</Banner>
          {secret !== undefined ? (
            <ShownKey secret={secret} onDone={close} />
          ) : (
            <div className="flex justify-end">
              <Button variant="primary" onClick={close}>
                Закрыть
              </Button>
            </div>
          )}
          <section aria-label="Пример запроса" className="flex flex-col gap-1">
            <h3 className="text-sm font-medium">Пример запроса к шлюзу</h3>
            <p className="text-xs text-muted">Подставьте адрес шлюза и положите ключ в переменную окружения AISEC_KEY.</p>
            <RawText>{gatewayExample(models[0] ?? "<модель>")}</RawText>
          </section>
        </div>
      )}
    </FormDialog>
  );
}

function Nav({ onCancel, onBack, nextLabel, nextDisabled }: { onCancel: () => void; onBack?: () => void; nextLabel: string; nextDisabled: boolean }) {
  return (
    <div className="flex justify-end gap-2">
      <Button onClick={onCancel}>Отменить</Button>
      {onBack && <Button onClick={onBack}>Назад</Button>}
      <Button type="submit" variant="primary" disabled={nextDisabled}>
        {nextLabel}
      </Button>
    </div>
  );
}
