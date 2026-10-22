import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { Field, Input, Select } from "../ui/Field";
import { AuthCard } from "./AuthCard";

// Часовые пояса России и UTC (ВРМ.2); остальные имена IANA сервер тоже примет, список нужен для удобства.
const timezones: [string, string][] = [
  ["Europe/Kaliningrad", "Калининград (UTC+2)"],
  ["Europe/Moscow", "Москва (UTC+3)"],
  ["Europe/Samara", "Самара (UTC+4)"],
  ["Asia/Yekaterinburg", "Екатеринбург (UTC+5)"],
  ["Asia/Omsk", "Омск (UTC+6)"],
  ["Asia/Krasnoyarsk", "Красноярск (UTC+7)"],
  ["Asia/Irkutsk", "Иркутск (UTC+8)"],
  ["Asia/Yakutsk", "Якутск (UTC+9)"],
  ["Asia/Vladivostok", "Владивосток (UTC+10)"],
  ["Asia/Magadan", "Магадан (UTC+11)"],
  ["Asia/Kamchatka", "Камчатка (UTC+12)"],
  ["UTC", "UTC"],
];

// Режимы хранения содержимого по умолчанию для новых приложений (ТЗ 5.5).
const retentionModes: [string, string][] = [
  ["masked", "Маскированное: персональные данные заменены метками (рекомендуется)"],
  ["none", "Не хранить содержимое: только метаданные"],
  ["full", "Полное: содержимое как есть (повышенный риск, нужны сроки хранения)"],
];

function setupErrorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 400) return e.detail;
  if (e instanceof ApiError && e.status === 429) return "Слишком много попыток. Подождите и повторите.";
  // 403 не раскрывает причину: токен неверен, истёк, погашен или настройка уже выполнена.
  return "Настройка не выполнена. Проверьте токен из вывода aisec-cli init: он одноразовый и действует 24 часа.";
}

// Первичная настройка (ЗИ.4): первый администратор безопасности по одноразовому токену.
export function Setup({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ token: "", login: "", display_name: "", password: "", repeat: "", timezone: "Europe/Moscow", retention_mode: "masked" });
  const [local, setLocal] = useState<string>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const m = useMutation({
    mutationFn: () =>
      api.setup({ token: f.token.trim(), login: f.login.trim(), display_name: f.display_name.trim(), password: f.password,
        timezone: f.timezone, retention_mode: f.retention_mode as "none" | "masked" | "full" }),
    onSuccess: () => {
      onDone();
      return qc.invalidateQueries({ queryKey: ["setup"] });
    },
  });
  const submit = () => {
    if (f.password !== f.repeat) {
      setLocal("Пароль и повтор не совпадают. Введите их ещё раз.");
      return;
    }
    setLocal(undefined);
    m.mutate();
  };
  return (
    <AuthCard
      title="Первичная настройка"
      intro="Создайте первого администратора безопасности. Токен выводит команда aisec-cli init."
      submit="Создать администратора"
      busy={m.isPending}
      error={local ?? (m.isError ? setupErrorText(m.error) : undefined)}
      onSubmit={submit}
    >
      <Field label="Токен настройки">
        {({ id }) => <Input id={id} type="password" autoComplete="off" autoFocus value={f.token} onChange={set("token")} required />}
      </Field>
      <Field label="Логин" hint="Латиница, цифры, «.», «_», «-», до 64 символов.">
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} autoComplete="username" value={f.login} onChange={set("login")} required />}
      </Field>
      <Field label="Имя в интерфейсе">
        {({ id }) => <Input id={id} autoComplete="name" value={f.display_name} onChange={set("display_name")} required />}
      </Field>
      <Field label="Пароль">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={f.password} onChange={set("password")} required />}
      </Field>
      <Field label="Пароль ещё раз">
        {({ id }) => <Input id={id} type="password" autoComplete="new-password" value={f.repeat} onChange={set("repeat")} required />}
      </Field>
      <Field label="Часовой пояс" hint="Так показывается время в консоли; хранится оно всегда в UTC.">
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={f.timezone} onChange={set("timezone")}>
            {timezones.map(([v, t]) => (
              <option key={v} value={v}>
                {t}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label="Хранение содержимого по умолчанию" hint="Для новых приложений; у каждого приложения режим можно изменить.">
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={f.retention_mode} onChange={set("retention_mode")}>
            {retentionModes.map(([v, t]) => (
              <option key={v} value={v}>
                {t}
              </option>
            ))}
          </Select>
        )}
      </Field>
    </AuthCard>
  );
}
