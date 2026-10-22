import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { slugPattern, suggestSlug } from "../apps/api";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { type Provider, type ProviderFields, providersApi } from "./api";

const typeText = new Map<Provider["type"], string>([
  ["openai", "OpenAI-совместимый"],
  ["gigachat", "GigaChat"],
  ["yandexgpt", "YandexGPT"],
]);
const scopes = ["GIGACHAT_API_PERS", "GIGACHAT_API_B2B", "GIGACHAT_API_CORP"] as const;
const area = "w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-sm";

const isHttps = (v: string): boolean => {
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
};

// Создание и правка провайдера. Новый провайдер всегда «внешний»; учётные данные задаются отдельным действием.
// Смена узла, корневых сертификатов или типа сбрасывает учётные данные и признак «внешний» (В14 ревью 2.r3b) — сервер,
// а консоль предупреждает об этом.
export function ProviderDialog({ provider, onClose }: { provider: Provider | null; onClose: () => void }) {
  const qc = useQueryClient();
  const creating = provider === null;
  const [f, setF] = useState({
    name: provider?.name ?? "",
    slug: provider?.slug ?? "",
    slugTouched: false,
    type: provider?.type ?? ("openai" as Provider["type"]),
    base_url: provider?.base_url ?? "",
    ca_pem: provider?.ca_pem ?? "",
    auth_url: provider?.auth_url ?? "",
    scope: provider?.scope ?? "GIGACHAT_API_PERS",
    folder_id: provider?.folder_id ?? "",
    connect: String(provider?.timeouts.connect ?? 0),
    header: String(provider?.timeouts.header ?? 0),
    response: String(provider?.timeouts.response ?? 0),
    stream_idle: String(provider?.timeouts.stream_idle ?? 0),
  });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const sec = (v: string) => Number(v);
  const secOk = (v: string) => Number.isInteger(sec(v)) && sec(v) >= 0 && sec(v) <= 600;
  const errs: Record<string, string | undefined> = {
    name: f.name.trim() === "" ? "Введите название." : undefined,
    slug: creating && !slugPattern.test(f.slug) ? "Латиница, цифры и дефис, до 63 знаков; начинается с буквы или цифры." : undefined,
    base_url: !isHttps(f.base_url) ? "Адрес начинается с https:// и содержит версию API, например https://llm.example/v1." : undefined,
    ca_pem: !f.ca_pem.includes("BEGIN CERTIFICATE") ? "Вставьте корневые сертификаты провайдера в формате PEM." : undefined,
    folder_id: f.type === "yandexgpt" && !/^[a-z0-9]{1,50}$/.test(f.folder_id) ? "Идентификатор каталога: строчные латинские буквы и цифры." : undefined,
    timeouts: [f.connect, f.header, f.response, f.stream_idle].every(secOk) ? undefined : "Таймауты — целые секунды от 0 до 600; 0 — значение шлюза.",
  };
  const invalid = Object.values(errs).some(Boolean);
  // Смена адресата сбрасывает учётные данные и признак «внешний».
  const resets =
    provider !== null &&
    (f.base_url !== provider.base_url || f.ca_pem !== provider.ca_pem || f.type !== provider.type || f.auth_url !== (provider.auth_url ?? ""));

  const fields = (): ProviderFields => ({
    name: f.name.trim(),
    type: f.type,
    base_url: f.base_url.trim(),
    ca_pem: f.ca_pem,
    ...(f.type === "gigachat" ? { auth_url: f.auth_url.trim(), scope: f.scope as (typeof scopes)[number] } : {}),
    ...(f.type === "yandexgpt" ? { folder_id: f.folder_id } : {}),
    timeouts: { connect: sec(f.connect), header: sec(f.header), response: sec(f.response), stream_idle: sec(f.stream_idle) },
  });
  const m = useMutation({
    mutationFn: () => (provider === null ? providersApi.create({ ...fields(), slug: f.slug }) : providersApi.update(provider.id, fields())),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
  });
  const close = () => {
    m.reset();
    onClose();
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!invalid) m.mutate();
  };

  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={creating ? "Новый провайдер" : `Провайдер «${provider.name}»`}
      description={creating ? "Новый провайдер считается внешним: данные к нему маскируются. Учётные данные задаются после создания." : undefined}
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Название" error={errs.name}>
          {({ id, describedBy, invalid: inv }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={inv}
              maxLength={200}
              value={f.name}
              onChange={(e) =>
                setF((p) => ({ ...p, name: e.target.value, slug: creating && !p.slugTouched ? suggestSlug(e.target.value) : p.slug }))
              }
            />
          )}
        </Field>
        {creating && (
          <Field label="ID провайдера" hint="Используется в пакете для шлюзов, потом не меняется." error={errs.slug}>
            {({ id, describedBy, invalid: inv }) => (
              <Input id={id} aria-describedby={describedBy} aria-invalid={inv} className="font-mono" value={f.slug} onChange={(e) => setF((p) => ({ ...p, slug: e.target.value, slugTouched: true }))} />
            )}
          </Field>
        )}
        <Field label="Тип">
          {({ id }) => (
            <Select id={id} value={f.type} onChange={set("type")}>
              {[...typeText.keys()].map((k) => (
                <option key={k} value={k}>
                  {typeText.get(k)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Адрес API" hint="https, с версией API, без учётных данных и параметров." error={errs.base_url}>
          {({ id, describedBy, invalid: inv }) => <Input id={id} aria-describedby={describedBy} aria-invalid={inv} className="font-mono" value={f.base_url} onChange={set("base_url")} />}
        </Field>
        {f.type === "gigachat" && (
          <>
            <Field label="Адрес выдачи токена">{({ id }) => <Input id={id} className="font-mono" value={f.auth_url} onChange={set("auth_url")} />}</Field>
            <Field label="Область (scope)">
              {({ id }) => (
                <Select id={id} value={f.scope} onChange={set("scope")}>
                  {scopes.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </>
        )}
        {f.type === "yandexgpt" && (
          <Field label="Идентификатор каталога" error={errs.folder_id}>
            {({ id, describedBy, invalid: inv }) => <Input id={id} aria-describedby={describedBy} aria-invalid={inv} className="font-mono" value={f.folder_id} onChange={set("folder_id")} />}
          </Field>
        )}
        <Field label="Корневые сертификаты провайдера (PEM)" hint="Системное хранилище не используется: доверие только этим сертификатам." error={errs.ca_pem}>
          {({ id, describedBy, invalid: inv }) => <textarea id={id} aria-describedby={describedBy} aria-invalid={inv} rows={4} value={f.ca_pem} onChange={set("ca_pem")} className={area} />}
        </Field>
        <fieldset className="flex flex-col gap-1">
          <legend className="text-sm font-medium">Таймауты, секунд (0 — по умолчанию шлюза)</legend>
          <div className="grid grid-cols-4 gap-2">
            <Field label="Соединение">{({ id }) => <Input id={id} inputMode="numeric" value={f.connect} onChange={set("connect")} />}</Field>
            <Field label="Заголовки">{({ id }) => <Input id={id} inputMode="numeric" value={f.header} onChange={set("header")} />}</Field>
            <Field label="Ответ">{({ id }) => <Input id={id} inputMode="numeric" value={f.response} onChange={set("response")} />}</Field>
            <Field label="Простой потока">{({ id }) => <Input id={id} inputMode="numeric" value={f.stream_idle} onChange={set("stream_idle")} />}</Field>
          </div>
          {errs.timeouts && <p role="alert" className="text-xs">{errs.timeouts}</p>}
        </fieldset>
        {resets && (
          <Banner kind="warning">
            Смена адреса, сертификатов или типа сбрасывает учётные данные и возвращает признак «внешний»: задайте их заново.
          </Banner>
        )}
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || invalid}>
            {creating ? "Создать провайдера" : "Сохранить провайдера"}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
