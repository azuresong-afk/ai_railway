import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, type Me } from "../api/client";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner, RawText } from "../ui/Layout";
import { type IdPSettings, adminApi } from "./api";
import { ConfirmDialog, ErrorBanner } from "./common";
import type { ReauthBody } from "./reauth";

// Вход через внешний IdP по OpenID Connect (ИАФ.7, ADR-0025): настройки видит право auth_idp.read,
// меняет и удаляет — auth_idp.manage с повторной проверкой паролем или кодом локальной учётной записи.

const area = "w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-sm";
// Предустановленные роли — если списка ролей нет (нет права roles.read).
const builtinRoles = ["security_admin", "system_admin", "analyst", "auditor", "app_owner"];

type Row = { group: string; role: string };
type Draft = {
  enabled: boolean;
  display_name: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  console_url: string;
  ca_pem: string;
  scopes: string;
  groups_claim: string;
  required_acr: string;
  required_amr: string;
  group_roles: Row[];
};

const words = (s: string) => s.split(/\s+/).filter((w) => w !== "");

function toDraft(s: IdPSettings): Draft {
  return {
    enabled: s.configured ? (s.enabled ?? false) : true,
    display_name: s.display_name ?? "",
    issuer: s.issuer ?? "",
    client_id: s.client_id ?? "",
    client_secret: "",
    console_url: s.console_url || window.location.origin,
    ca_pem: s.ca_pem ?? "",
    scopes: (s.scopes ?? []).join(" "),
    groups_claim: s.groups_claim || "groups",
    required_acr: (s.required_acr ?? []).join(" "),
    required_amr: (s.required_amr ?? []).join(" "),
    group_roles: (s.group_roles ?? []).map((g) => ({ group: g.group, role: g.role })),
  };
}

// Ошибка поля из ответа сервера (400 с fields).
function fieldError(e: unknown, field: string): string | undefined {
  return e instanceof ApiError ? e.fields.find((f) => f.field === field)?.detail : undefined;
}

export function IdPTab({ me }: { me: Me }) {
  const canManage = me.permissions.includes("auth_idp.manage");
  // Признак «сохранено» — здесь: после сохранения форма пересоздаётся с новыми значениями.
  const [saved, setSaved] = useState(false);
  const q = useQuery({ queryKey: ["admin", "idp"], queryFn: ({ signal }) => adminApi.idp(signal) });
  const roles = useQuery({
    queryKey: ["admin", "roles"],
    queryFn: ({ signal }) => adminApi.roles(signal),
    enabled: me.permissions.includes("roles.read"),
  });
  if (q.isError) return <ErrorBanner error={q.error} />;
  if (!q.data) return <p className="text-sm text-muted">Загрузка настроек…</p>;
  const roleIds = roles.data ? roles.data.items.map((r) => r.id) : builtinRoles;
  return (
    <IdPForm
      key={`${q.data.version ?? 0}-${q.data.configured}`}
      initial={q.data}
      roleIds={roleIds}
      canManage={canManage}
      mfa={me.mfa?.enabled === true}
      saved={saved}
      setSaved={setSaved}
    />
  );
}

function IdPForm({
  initial,
  roleIds,
  canManage,
  mfa,
  saved,
  setSaved,
}: {
  initial: IdPSettings;
  roleIds: string[];
  canManage: boolean;
  mfa: boolean;
  saved: boolean;
  setSaved: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const [d, setD] = useState<Draft>(() => toDraft(initial));
  const [secret, setSecret] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const reauth = (): ReauthBody => (secret === "" ? {} : mfa ? { code: secret } : { password: secret });
  const set = (k: keyof Draft) => (e: { target: { value: string } }) => {
    setSaved(false);
    setD({ ...d, [k]: e.target.value });
  };
  const setRow = (i: number, r: Partial<Row>) => {
    setSaved(false);
    setD({ ...d, group_roles: d.group_roles.map((x, j) => (j === i ? { ...x, ...r } : x)) });
  };
  const save = useMutation({
    mutationFn: () =>
      adminApi.saveIdP({
        enabled: d.enabled,
        display_name: d.display_name.trim(),
        issuer: d.issuer.trim(),
        client_id: d.client_id.trim(),
        client_secret: d.client_secret,
        console_url: d.console_url.trim(),
        ca_pem: d.ca_pem,
        scopes: words(d.scopes),
        groups_claim: d.groups_claim.trim(),
        required_acr: words(d.required_acr),
        required_amr: words(d.required_amr),
        group_roles: d.group_roles.filter((r) => r.group.trim() !== "").map((r) => ({ group: r.group.trim(), role: r.role })),
        ...reauth(),
      }),
    onSuccess: (s) => {
      setSecret("");
      qc.setQueryData(["admin", "idp"], s);
      setSaved(true);
    },
    onError: () => setSecret(""),
  });
  const del = useMutation({
    mutationFn: () => adminApi.deleteIdP(reauth()),
    onSuccess: () => {
      setSecret("");
      setConfirmDelete(false);
      void qc.invalidateQueries({ queryKey: ["admin", "idp"] });
    },
    onError: () => setSecret(""),
  });
  const err = save.error;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    save.mutate();
  };
  const disabled = !canManage;
  return (
    <form onSubmit={submit} className="flex max-w-2xl flex-col gap-3">
      <p className="text-sm text-muted">
        Вход в консоль через корпоративный IdP по OpenID Connect (Keycloak, Microsoft Entra ID, ADFS и другие). Учётная запись создаётся при первом
        входе, роль назначается по группам пользователя в IdP. Локальный вход по паролю остаётся для аварийного доступа.
      </p>
      {initial.redirect_uri && (
        <div className="flex flex-col gap-1">
          <span className="text-sm font-medium">Адрес возврата для регистрации клиента в IdP</span>
          <RawText>{initial.redirect_uri}</RawText>
        </div>
      )}
      <Check label="Вход через IdP включён" checked={d.enabled} disabled={disabled} onCheckedChange={(v) => { setSaved(false); setD({ ...d, enabled: v }); }} />
      <Field label="Название на кнопке входа" hint="Например, «Корпоративный вход». До 64 символов." error={fieldError(err, "display_name")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} maxLength={64} value={d.display_name} onChange={set("display_name")} />}
      </Field>
      <Field label="Адрес издателя (issuer)" hint="Адрес с протоколом https, как в документе discovery IdP, например адрес realm в Keycloak. Сервер обращается только к нему." error={fieldError(err, "issuer")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} inputMode="url" value={d.issuer} onChange={set("issuer")} />}
      </Field>
      <Field label="Идентификатор клиента (client_id)" error={fieldError(err, "client_id")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.client_id} onChange={set("client_id")} />}
      </Field>
      <Field
        label="Секрет клиента (client_secret)"
        hint={initial.configured ? "Секрет сохранён и не показывается. Оставьте поле пустым, чтобы не менять его." : "Выдаёт IdP при регистрации клиента. Хранится в зашифрованном виде."}
        error={fieldError(err, "client_secret")}
      >
        {({ id, describedBy, invalid }) => (
          <Input id={id} type="password" autoComplete="new-password" aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.client_secret} onChange={set("client_secret")} />
        )}
      </Field>
      <Field label="Адрес консоли" hint="Протокол https, имя и при необходимости порт, без пути — как консоль открывают пользователи. Из него строится адрес возврата." error={fieldError(err, "console_url")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} inputMode="url" value={d.console_url} onChange={set("console_url")} />}
      </Field>
      <Field label="Корневые сертификаты IdP (PEM)" hint="Сертификат УЦ, выпустившего сертификат IdP. Системные корни не используются." error={fieldError(err, "ca_pem")}>
        {({ id, describedBy, invalid }) => (
          <textarea id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} rows={5} value={d.ca_pem} onChange={set("ca_pem")} className={area} />
        )}
      </Field>
      <Field label="Дополнительные области (scope)" hint="Через пробел, например «profile email». openid добавляется всегда." error={fieldError(err, "scopes")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.scopes} onChange={set("scopes")} />}
      </Field>
      <Field label="Утверждение с группами" hint="Имя поля ID-токена со списком групп, обычно groups." error={fieldError(err, "groups_claim")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.groups_claim} onChange={set("groups_claim")} />}
      </Field>
      <Field
        label="Допустимые значения acr"
        hint="Через пробел. Если заданы acr или amr, вход без подтверждённого второго фактора в IdP отклоняется. Для ролей с обязательным вторым фактором их нужно задать."
        error={fieldError(err, "required_acr")}
      >
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.required_acr} onChange={set("required_acr")} />}
      </Field>
      <Field label="Допустимые значения amr" hint="Через пробел, например «otp mfa hwk». Достаточно одного совпадения." error={fieldError(err, "required_amr")}>
        {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.required_amr} onChange={set("required_amr")} />}
      </Field>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Группы IdP и роли</legend>
        <p className="text-xs text-muted">
          У пользователя одна роль. Если его группы сопоставлены с разными ролями или ни одна не сопоставлена, вход отклоняется.
        </p>
        {d.group_roles.map((r, i) => (
          <div key={i} className="flex items-end gap-2">
            <div className="flex-1">
              <Field label={`Группа ${i + 1}`}>
                {({ id }) => <Input id={id} disabled={disabled} value={r.group} onChange={(e) => setRow(i, { group: e.target.value })} />}
              </Field>
            </div>
            <div className="w-48">
              <Field label="Роль">
                {({ id }) => (
                  <Select id={id} disabled={disabled} value={r.role} onChange={(e) => setRow(i, { role: e.target.value })}>
                    {(roleIds.includes(r.role) ? roleIds : [r.role, ...roleIds]).map((x) => (
                      <option key={x} value={x}>
                        {x}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            {canManage && (
              <Button type="button" onClick={() => setD({ ...d, group_roles: d.group_roles.filter((_, j) => j !== i) })}>
                Удалить
              </Button>
            )}
          </div>
        ))}
        {fieldError(err, "group_roles") && <Banner kind="error">{fieldError(err, "group_roles")}</Banner>}
        {canManage && (
          <div>
            <Button type="button" onClick={() => setD({ ...d, group_roles: [...d.group_roles, { group: "", role: "analyst" }] })}>
              Добавить группу
            </Button>
          </div>
        )}
      </fieldset>

      {canManage ? (
        <>
          <Field
            label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}
            hint="Изменение входа в консоль подтверждается локальной учётной записью. Сессии пользователей IdP будут завершены."
            error={fieldError(err, "password") ?? fieldError(err, "code")}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                autoComplete={mfa ? "one-time-code" : "current-password"}
                type={mfa ? "text" : "password"}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            )}
          </Field>
          <ErrorBanner error={err instanceof ApiError && err.fields.length > 0 ? null : err} />
          {saved && <Banner kind="info">Настройки сохранены. Сессии пользователей IdP завершены.</Banner>}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={save.isPending || secret === ""}>
              Сохранить настройки
            </Button>
            {initial.configured && (
              <Button type="button" variant="danger" disabled={secret === ""} onClick={() => setConfirmDelete(true)}>
                Удалить настройки
              </Button>
            )}
          </div>
        </>
      ) : (
        <p className="text-sm text-muted">Менять настройки может администратор безопасности.</p>
      )}
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Удалить настройки входа через IdP?"
        description="Вход через IdP станет недоступен, сессии его пользователей завершатся. Учётные записи и журнал аудита сохранятся."
        actionLabel="Удалить"
        busy={del.isPending}
        error={del.error}
        onConfirm={() => del.mutate()}
      />
    </form>
  );
}
