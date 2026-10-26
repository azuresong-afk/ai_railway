import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { splitList } from "../apps/api";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { alertsApi, type NotifyChannel } from "./api";
import { severityOrder, severityTitle } from "./format";

type Kind = "email" | "webhook" | "syslog";
const kindTitle = new Map<Kind, string>([
  ["email", "Почта (SMTP, STARTTLS)"],
  ["webhook", "Webhook (https)"],
  ["syslog", "Syslog (RFC 5424 по TLS)"],
]);
type SecretName = "password" | "url" | "signing_key";
const secretTitle = new Map<SecretName, string>([
  ["password", "Пароль SMTP"],
  ["url", "Адрес webhook"],
  ["signing_key", "Ключ подписи"],
]);

const area = "w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-sm";

const isHttps = (v: string): boolean => {
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
};

// Секрет канала: значение только вводится. Если секрет уже задан, поле пустое, и пустое значение оставляет прежний.
// autoComplete="new-password": браузер не подставляет сохранённый пароль консоли (autoComplete="off" у поля пароля
// он не соблюдает) и не уводит его как секрет канала (3В20 ревью 3.r2).
function SecretField({ name, set, value, onChange, hint }: { name: SecretName; set: boolean; value: string; onChange: (v: string) => void; hint?: string }) {
  return (
    <Field label={secretTitle.get(name)!} hint={set ? `Задан. Оставьте пустым, чтобы не менять. ${hint ?? ""}` : hint}>
      {({ id, describedBy }) => (
        <Input id={id} name={`channel-secret-${name}`} aria-describedby={describedBy} type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} placeholder={set ? "••••••••" : ""} />
      )}
    </Field>
  );
}

// Создание и правка канала уведомлений (ТЗ 5.6). Секреты не возвращаются сервером и не хранятся на экране после отправки.
export function ChannelDialog({ channel, mfa, onClose }: { channel: NotifyChannel | null; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const creating = channel === null;
  const s = channel?.settings;
  const [f, setF] = useState({
    type: (channel?.type ?? "email") as Kind,
    name: channel?.name ?? "",
    enabled: channel?.enabled ?? true,
    min_severity: channel?.min_severity ?? "medium",
    host: s?.host ?? "",
    port: s?.port ? String(s.port) : "",
    username: s?.username ?? "",
    from: s?.from ?? "",
    to: (s?.to ?? []).join("\n"),
    format: s?.format ?? "",
    facility: s?.facility !== undefined ? String(s.facility) : "",
    hostname: s?.hostname ?? "",
    ca_pem: s?.ca_pem ?? "",
  });
  const [sec, setSec] = useState({ password: "", url: "", signing_key: "" });
  // Удалить пароль SMTP вместе с логином (3Н38 ревью 3.r2): пустое поле значит «не менять», поэтому удаление — отдельный
  // флажок. Сервер считает удаление ослаблением и просит пароль или код. Ключ подписи webhook обязателен: он только заменяется.
  const [dropPassword, setDropPassword] = useState(false);
  const re = useReauth(mfa);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const isSet = (k: SecretName) => channel?.secrets_set.includes(k) === true;

  const errs: Record<string, string | undefined> = {
    name: f.name.trim() === "" ? "Введите название." : undefined,
    host: f.type !== "webhook" && f.host.trim() === "" ? "Введите адрес сервера." : undefined,
    port: f.port !== "" && !(Number.isInteger(Number(f.port)) && Number(f.port) >= 1 && Number(f.port) <= 65535) ? "Порт от 1 до 65535." : undefined,
    ca_pem: !f.ca_pem.includes("BEGIN CERTIFICATE") ? "Вставьте корневые сертификаты получателя в формате PEM." : undefined,
    url: f.type === "webhook" && !isSet("url") && !isHttps(sec.url) ? "Адрес webhook начинается с https://." : undefined,
    key: f.type === "webhook" && sec.signing_key !== "" && sec.signing_key.length < 32 ? "Не короче 32 знаков." : undefined,
  };
  const invalid = Object.values(errs).some(Boolean);

  const settings = () => {
    const port = f.port === "" ? {} : { port: Number(f.port) };
    if (f.type === "email") return { host: f.host.trim(), ...port, username: dropPassword ? "" : f.username, from: f.from.trim(), to: splitList(f.to), ca_pem: f.ca_pem };
    if (f.type === "webhook") return { format: (f.format || "generic") as "generic", ca_pem: f.ca_pem };
    return {
      host: f.host.trim(),
      ...port,
      format: (f.format || "json") as "json",
      ...(f.facility === "" ? {} : { facility: Number(f.facility) }),
      ...(f.hostname === "" ? {} : { hostname: f.hostname }),
      ca_pem: f.ca_pem,
    };
  };
  // Передаются только введённые секреты: пустой — «не менять», пустая строка уходит только при удалении флажком.
  const secrets = () => ({
    ...(f.type === "email" && dropPassword ? { password: "" } : {}),
    ...(f.type === "email" && !dropPassword && sec.password !== "" ? { password: sec.password } : {}),
    ...(f.type === "webhook" && sec.url !== "" ? { url: sec.url } : {}),
    ...(f.type === "webhook" && sec.signing_key !== "" ? { signing_key: sec.signing_key } : {}),
  });

  const m = useMutation({
    mutationFn: () => {
      const base = { name: f.name.trim(), enabled: f.enabled, min_severity: f.min_severity, settings: settings(), secrets: secrets() };
      if (channel === null) return alertsApi.createChannel({ ...base, type: f.type, min_severity: f.min_severity as "medium" });
      return alertsApi.updateChannel(channel.id, { ...base, min_severity: f.min_severity as "medium", version: channel.version, ...re.body() });
    },
    onSuccess: async () => {
      re.reset();
      setSec({ password: "", url: "", signing_key: "" });
      await qc.invalidateQueries({ queryKey: ["alerts", "channels"] });
      onClose();
    },
    onError: re.onError,
  });
  const close = () => {
    re.reset();
    m.reset();
    setSec({ password: "", url: "", signing_key: "" });
    onClose();
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!invalid && re.ready) m.mutate();
  };

  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={creating ? "Новый канал уведомлений" : `Канал «${channel.name}»`}
      description="Секреты шифруются и больше не показываются. Ослабление доставки подтверждается паролем или кодом."
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        {creating ? (
          <Field label="Тип канала">
            {({ id }) => (
              <Select id={id} value={f.type} onChange={(e) => setF((p) => ({ ...p, type: e.target.value as Kind, format: "" }))}>
                {[...kindTitle.keys()].map((k) => (
                  <option key={k} value={k}>
                    {kindTitle.get(k)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <p className="text-sm text-muted">Тип: {kindTitle.get(f.type)}</p>
        )}
        <Field label="Название" error={errs.name}>
          {({ id, describedBy, invalid: inv }) => <Input id={id} aria-describedby={describedBy} aria-invalid={inv} maxLength={200} value={f.name} onChange={set("name")} />}
        </Field>
        <Field label="Наименьшая серьёзность оповещения">
          {({ id }) => (
            <Select id={id} value={f.min_severity} onChange={set("min_severity")}>
              {severityOrder.map((v) => (
                <option key={v} value={v}>
                  {severityTitle.get(v)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Check label="Канал включён" checked={f.enabled} onCheckedChange={(v) => setF((p) => ({ ...p, enabled: v }))} />

        {f.type !== "webhook" && (
          <div className="grid grid-cols-[1fr_7rem] gap-2">
            <Field label="Адрес сервера" error={errs.host}>
              {({ id, describedBy, invalid: inv }) => <Input id={id} aria-describedby={describedBy} aria-invalid={inv} value={f.host} onChange={set("host")} />}
            </Field>
            <Field label="Порт" error={errs.port} hint={f.type === "email" ? "587" : "6514"}>
              {({ id, describedBy, invalid: inv }) => <Input id={id} aria-describedby={describedBy} aria-invalid={inv} inputMode="numeric" value={f.port} onChange={set("port")} />}
            </Field>
          </div>
        )}
        {f.type === "email" && (
          <>
            <Field label="Логин SMTP">
              {({ id }) => <Input id={id} name="smtp-account" autoComplete="off" disabled={dropPassword} value={dropPassword ? "" : f.username} onChange={set("username")} />}
            </Field>
            {!dropPassword && <SecretField name="password" set={isSet("password")} value={sec.password} onChange={(v) => setSec((p) => ({ ...p, password: v }))} />}
            {isSet("password") && (
              <Check
                label="Удалить пароль и логин SMTP"
                checked={dropPassword}
                onCheckedChange={(v) => {
                  setDropPassword(v);
                  setSec((p) => ({ ...p, password: "" }));
                }}
              />
            )}
            {dropPassword && <p className="text-xs text-muted">Письма пойдут без проверки подлинности. Удаление ослабляет доставку: понадобится пароль или код.</p>}
            <Field label="Отправитель (From)">{({ id }) => <Input id={id} type="email" value={f.from} onChange={set("from")} />}</Field>
            <Field label="Адресаты" hint="По одному на строку, не больше 20. Удаление адресата — ослабление.">
              {({ id, describedBy }) => <textarea id={id} aria-describedby={describedBy} rows={3} value={f.to} onChange={set("to")} className={area} />}
            </Field>
          </>
        )}
        {f.type === "webhook" && (
          <>
            <Field label="Формат">
              {({ id }) => (
                <Select id={id} value={f.format || "generic"} onChange={set("format")}>
                  <option value="generic">Общий JSON</option>
                  <option value="mattermost">Mattermost</option>
                </Select>
              )}
            </Field>
            <SecretField name="url" set={isSet("url")} value={sec.url} onChange={(v) => setSec((p) => ({ ...p, url: v }))} hint="Адрес — секрет, показывается только узел." />
            {errs.url && <p role="alert" className="text-xs">{errs.url}</p>}
            <SecretField name="signing_key" set={isSet("signing_key")} value={sec.signing_key} onChange={(v) => setSec((p) => ({ ...p, signing_key: v }))} hint="Не короче 32 знаков; подпись — заголовок AISec-Signature." />
            {errs.key && <p role="alert" className="text-xs">{errs.key}</p>}
            {channel?.settings.url_origin && <p className="text-xs text-muted">Текущий узел: {channel.settings.url_origin}</p>}
          </>
        )}
        {f.type === "syslog" && (
          <div className="grid grid-cols-3 gap-2">
            <Field label="Формат">
              {({ id }) => (
                <Select id={id} value={f.format || "json"} onChange={set("format")}>
                  <option value="json">JSON</option>
                  <option value="cef">CEF</option>
                </Select>
              )}
            </Field>
            <Field label="Facility (0–23)">{({ id }) => <Input id={id} inputMode="numeric" value={f.facility} onChange={set("facility")} placeholder="10" />}</Field>
            <Field label="Имя хоста">{({ id }) => <Input id={id} value={f.hostname} onChange={set("hostname")} placeholder="aisec-server" />}</Field>
          </div>
        )}
        <Field label="Корневые сертификаты получателя (PEM)" hint="Системное хранилище не используется: доверие только этим сертификатам. Смена сертификатов — ослабление." error={errs.ca_pem}>
          {({ id, describedBy, invalid: inv }) => <textarea id={id} aria-describedby={describedBy} aria-invalid={inv} rows={4} value={f.ca_pem} onChange={set("ca_pem")} className={area} />}
        </Field>
        <ReauthPrompt r={re} />
        <ErrorBanner error={visibleError(m.error)} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || invalid || !re.ready}>
            {creating ? "Создать канал" : "Сохранить канал"}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
