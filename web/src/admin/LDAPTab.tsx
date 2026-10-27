import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ApiError, type Me } from "../api/client";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { type LDAPSettings, type LDAPSettingsUpdate, adminApi } from "./api";
import { ConfirmDialog, ErrorBanner, area, builtinRoles, fieldError } from "./common";
import type { ReauthBody } from "./reauth";

// Вход через каталог LDAP (ИАФ.7, ADR-0025, раздел 2): FreeIPA, ALD Pro, Active Directory и другие.
// Настройки видит право auth_idp.read, меняет и удаляет — auth_idp.manage с повторной проверкой
// паролем или кодом локальной учётной записи.

type Row = { group: string; role: string };
type IDAttribute = LDAPSettingsUpdate["id_attribute"];
type GroupMode = LDAPSettingsUpdate["group_mode"];
type Draft = {
  enabled: boolean;
  url: string;
  ca_pem: string;
  bind_dn: string;
  bind_password: string;
  user_base_dn: string;
  user_filter: string;
  id_attribute: IDAttribute;
  display_attribute: string;
  group_mode: GroupMode;
  group_base_dn: string;
  group_roles: Row[];
};

const idAttributes: { value: IDAttribute; title: string }[] = [
  { value: "entryUUID", title: "entryUUID (OpenLDAP, 389 DS, ALD Pro)" },
  { value: "ipaUniqueID", title: "ipaUniqueID (FreeIPA)" },
  { value: "nsUniqueId", title: "nsUniqueId (389 DS)" },
  { value: "objectGUID", title: "objectGUID (Active Directory)" },
];
const groupModes: { value: GroupMode; title: string }[] = [
  { value: "member_of", title: "Атрибут memberOf у пользователя" },
  { value: "member", title: "Поиск групп по member или uniqueMember" },
  { value: "ad_nested", title: "Вложенные группы Active Directory" },
];

function toDraft(s: LDAPSettings): Draft {
  return {
    enabled: s.configured ? (s.enabled ?? false) : true,
    url: s.url ?? "",
    ca_pem: s.ca_pem ?? "",
    bind_dn: s.bind_dn ?? "",
    bind_password: "",
    user_base_dn: s.user_base_dn ?? "",
    user_filter: s.user_filter || "(&(objectClass=person)(uid={login}))",
    id_attribute: s.id_attribute ?? "entryUUID",
    display_attribute: s.display_attribute || "displayName",
    group_mode: s.group_mode ?? "member_of",
    group_base_dn: s.group_base_dn ?? "",
    group_roles: (s.group_roles ?? []).map((g) => ({ group: g.group, role: g.role })),
  };
}

export function LDAPTab({ me }: { me: Me }) {
  const canManage = me.permissions.includes("auth_idp.manage");
  // Признак «сохранено» — здесь: после сохранения форма пересоздаётся с новыми значениями.
  const [saved, setSaved] = useState(false);
  const q = useQuery({ queryKey: ["admin", "ldap"], queryFn: ({ signal }) => adminApi.ldap(signal) });
  const roles = useQuery({
    queryKey: ["admin", "roles"],
    queryFn: ({ signal }) => adminApi.roles(signal),
    enabled: me.permissions.includes("roles.read"),
  });
  if (q.isError) return <ErrorBanner error={q.error} />;
  if (!q.data) return <p className="text-sm text-muted">Загрузка настроек…</p>;
  const roleIds = roles.data ? roles.data.items.map((r) => r.id) : builtinRoles;
  return (
    <LDAPForm
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

function LDAPForm({
  initial,
  roleIds,
  canManage,
  mfa,
  saved,
  setSaved,
}: {
  initial: LDAPSettings;
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
  const update = (patch: Partial<Draft>) => {
    setSaved(false);
    setD({ ...d, ...patch });
  };
  const set = (k: keyof Draft) => (e: { target: { value: string } }) => update({ [k]: e.target.value });
  const setRow = (i: number, r: Partial<Row>) => update({ group_roles: d.group_roles.map((x, j) => (j === i ? { ...x, ...r } : x)) });
  const save = useMutation({
    mutationFn: () =>
      adminApi.saveLDAP({
        enabled: d.enabled,
        url: d.url.trim(),
        ca_pem: d.ca_pem,
        bind_dn: d.bind_dn.trim(),
        bind_password: d.bind_password,
        user_base_dn: d.user_base_dn.trim(),
        user_filter: d.user_filter.trim(),
        id_attribute: d.id_attribute,
        display_attribute: d.display_attribute.trim(),
        group_mode: d.group_mode,
        group_base_dn: d.group_mode === "member_of" ? "" : d.group_base_dn.trim(),
        group_roles: d.group_roles.filter((r) => r.group.trim() !== "").map((r) => ({ group: r.group.trim(), role: r.role })),
        ...reauth(),
      }),
    onSuccess: (s) => {
      setSecret("");
      qc.setQueryData(["admin", "ldap"], s);
      setSaved(true);
    },
    onError: () => setSecret(""),
  });
  const del = useMutation({
    mutationFn: () => adminApi.deleteLDAP(reauth()),
    onSuccess: () => {
      setSecret("");
      setConfirmDelete(false);
      void qc.invalidateQueries({ queryKey: ["admin", "ldap"] });
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
  // Однострочное поле: метка, подсказка и ошибка сервера по имени поля.
  const text = (k: keyof Draft & keyof LDAPSettingsUpdate, value: string, label: string, hint?: string, extra?: { inputMode?: "url" }) => (
    <Field label={label} hint={hint} error={fieldError(err, k)}>
      {({ id, describedBy, invalid }) => (
        <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={value} onChange={set(k)} {...extra} />
      )}
    </Field>
  );
  return (
    <form onSubmit={submit} className="flex max-w-2xl flex-col gap-3">
      <p className="text-sm text-muted">
        Вход в консоль с логином и паролем из корпоративного каталога LDAP (FreeIPA, ALD Pro, Active Directory и другие). Учётная запись создаётся при
        первом входе, роль назначается по группам пользователя в каталоге. Если в консоли есть локальная учётная запись с тем же логином, входит она:
        локальный вход остаётся для аварийного доступа.
      </p>
      <Check label="Вход через каталог включён" checked={d.enabled} disabled={disabled} onCheckedChange={(v) => update({ enabled: v })} />
      {text("url", d.url, "Адрес каталога", "ldaps://имя:636 или ldap://имя:389 — тогда соединение защищается через StartTLS. Без TLS сервер к каталогу не подключается.", {
        inputMode: "url",
      })}
      <Field label="Корневые сертификаты каталога (PEM)" hint="Сертификат УЦ, выпустившего сертификат сервера каталога. Системные корни не используются." error={fieldError(err, "ca_pem")}>
        {({ id, describedBy, invalid }) => (
          <textarea id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} rows={5} value={d.ca_pem} onChange={set("ca_pem")} className={area} />
        )}
      </Field>
      {text("bind_dn", d.bind_dn, "DN сервисной учётной записи", "Учётная запись только для поиска пользователей и групп, например uid=aisec-svc,cn=sysaccounts,cn=etc,dc=example,dc=ru.")}
      <Field
        label="Пароль сервисной учётной записи"
        hint={initial.configured ? "Пароль сохранён и не показывается. Оставьте поле пустым, чтобы не менять его; при смене адреса, сертификатов или DN введите его заново." : "Хранится в зашифрованном виде."}
        error={fieldError(err, "bind_password")}
      >
        {({ id, describedBy, invalid }) => (
          <Input id={id} type="password" autoComplete="new-password" aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.bind_password} onChange={set("bind_password")} />
        )}
      </Field>
      {text("user_base_dn", d.user_base_dn, "Ветка пользователей", "DN, например cn=users,cn=accounts,dc=example,dc=ru.")}
      {text("user_filter", d.user_filter, "Фильтр поиска пользователя", "Фильтр LDAP с {login} на месте логина. Для Active Directory: (&(objectClass=user)(sAMAccountName={login})).")}
      <Field label="Атрибут постоянного идентификатора" hint="Не меняется при переименовании: по нему учётная запись в консоли связана с записью каталога." error={fieldError(err, "id_attribute")}>
        {({ id, describedBy, invalid }) => (
          <Select id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.id_attribute} onChange={(e) => update({ id_attribute: e.target.value as IDAttribute })}>
            {idAttributes.map((a) => (
              <option key={a.value} value={a.value}>
                {a.title}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {text("display_attribute", d.display_attribute, "Атрибут отображаемого имени", "Обычно displayName или cn.")}
      <Field label="Как получать группы" error={fieldError(err, "group_mode")}>
        {({ id, describedBy, invalid }) => (
          <Select id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={disabled} value={d.group_mode} onChange={(e) => update({ group_mode: e.target.value as GroupMode })}>
            {groupModes.map((m) => (
              <option key={m.value} value={m.value}>
                {m.title}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {d.group_mode !== "member_of" && text("group_base_dn", d.group_base_dn, "Ветка групп", "DN, в котором искать группы, например cn=groups,cn=accounts,dc=example,dc=ru.")}

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Группы каталога и роли</legend>
        <p className="text-xs text-muted">
          Группа указывается полным DN. У пользователя одна роль: если его группы сопоставлены с разными ролями или ни одна не сопоставлена, вход
          отклоняется.
        </p>
        {d.group_roles.map((r, i) => (
          <div key={i} className="flex items-end gap-2">
            <div className="flex-1">
              <Field label={`DN группы ${i + 1}`}>
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
              <Button type="button" onClick={() => update({ group_roles: d.group_roles.filter((_, j) => j !== i) })}>
                Удалить
              </Button>
            )}
          </div>
        ))}
        {fieldError(err, "group_roles") && <Banner kind="error">{fieldError(err, "group_roles")}</Banner>}
        {canManage && (
          <div>
            <Button type="button" onClick={() => update({ group_roles: [...d.group_roles, { group: "", role: "analyst" }] })}>
              Добавить группу
            </Button>
          </div>
        )}
      </fieldset>

      {canManage ? (
        <>
          <Field
            label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}
            hint="Изменение входа в консоль подтверждается локальной учётной записью. Сервер проверит подключение к каталогу, сессии его пользователей будут завершены."
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
          {saved && <Banner kind="info">Настройки сохранены. Сессии пользователей каталога завершены.</Banner>}
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
        title="Удалить настройки входа через каталог?"
        description="Вход через каталог станет недоступен, сессии его пользователей завершатся. Учётные записи и журнал аудита сохранятся."
        actionLabel="Удалить"
        busy={del.isPending}
        error={del.error}
        onConfirm={() => del.mutate()}
      />
    </form>
  );
}
