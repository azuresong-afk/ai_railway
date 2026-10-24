import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { adminApi } from "../admin/api";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { type AlertCondition, type AlertRule, type AlertRuleInput, alertsApi } from "./api";
import { kindText, severityOrder, severityTitle } from "./format";

const groupFields = ["type", "app", "env", "user", "provider", "model", "source", "gateway", "action", "rule", "severity", "policy_mode"];
const groupTitle = new Map<string, string>(Object.entries({
  type: "Тип", app: "Приложение", env: "Окружение", user: "Пользователь", provider: "Провайдер", model: "Модель", source: "Источник",
  gateway: "Шлюз", action: "Действие", rule: "Правило обнаружения", severity: "Серьёзность", policy_mode: "Режим политики",
}));
const newFields: [string, string][] = [["model", "Новая модель"], ["provider", "Новый провайдер"], ["user", "Новый пользователь"], ["app", "Новое приложение"]];
type GroupBy = NonNullable<AlertRuleInput["group_by"]>;
const editable = new Set(["threshold", "new"]);

// Создание и правка правила «порог» и «новое»; у остальных видов меняются имя, серьёзность, окно подавления, получатели.
// У системных правил и правил безопасности (locked) — только получатели (сервер отвечает 422 на остальное).
// Ослабление сервер подтверждает паролем или кодом — поле появляется по его ответу (как в «Защите» приложения).
export function RuleDialog({ rule, mfa, canUsers, canRoles, onClose }: { rule: AlertRule | null; mfa: boolean; canUsers: boolean; canRoles: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const creating = rule === null;
  const locked = rule?.locked === true;
  const kind = rule?.kind ?? "threshold";
  const [f, setF] = useState({
    kind: kind === "new" ? "new" : "threshold",
    name: rule?.name ?? "",
    description: rule?.description ?? "",
    enabled: rule?.enabled ?? true,
    severity: rule?.severity ?? "medium",
    filter: rule?.condition.filter ?? "",
    min_severity: rule?.condition.min_severity ?? "",
    field: rule?.condition.field ?? "model",
    group_by: rule?.group_by ?? [],
    suppress: String(rule?.suppress_minutes ?? 60),
    roles: rule?.recipients.roles ?? [],
    users: rule?.recipients.users ?? [],
  });
  const re = useReauth(mfa);
  const roles = useQuery({ queryKey: ["alerts", "roles"], queryFn: ({ signal }) => adminApi.roles(signal), enabled: canRoles });
  const users = useQuery({ queryKey: ["alerts", "users"], queryFn: ({ signal }) => adminApi.users(signal), enabled: canUsers });
  const suppress = Number(f.suppress);
  const suppressErr = !Number.isInteger(suppress) || suppress < 0 || suppress > 10080 ? "Целое число от 0 до 10 080 минут." : undefined;
  const nameErr = f.name.trim() === "" ? "Введите название." : undefined;
  const conditionOk = f.kind === "new" || f.filter.trim() !== "" || f.min_severity !== "";
  const conditionErr = conditionOk ? undefined : "Задайте фильтр событий или наименьшую серьёзность.";

  const condition = (): AlertCondition => {
    if (rule && !editable.has(rule.kind)) return rule.condition;
    if (f.kind === "new") return { field: f.field as "model" };
    const c: AlertCondition = {};
    if (f.filter.trim() !== "") c.filter = f.filter.trim();
    if (f.min_severity !== "") c.min_severity = f.min_severity as "high";
    return c;
  };
  const recipients = { roles: f.roles, users: f.users };

  const m = useMutation({
    mutationFn: () => {
      if (rule === null) {
        return alertsApi.createRule({
          kind: f.kind as "threshold",
          name: f.name.trim(),
          description: f.description,
          enabled: f.enabled,
          severity: f.severity as "medium",
          condition: condition(),
          group_by: f.kind === "new" ? [] : (f.group_by as GroupBy),
          suppress_minutes: suppress,
          recipients,
        });
      }
      return alertsApi.updateRule(rule.id, {
        version: rule.version,
        recipients,
        ...(locked
          ? {}
          : {
              name: f.name.trim(),
              description: f.description,
              enabled: f.enabled,
              severity: f.severity as "medium",
              condition: condition(),
              group_by: f.kind === "new" ? [] : f.group_by,
              suppress_minutes: suppress,
            }),
        ...re.body(),
      });
    },
    onSuccess: async () => {
      re.reset();
      await qc.invalidateQueries({ queryKey: ["alerts", "rules"] });
      onClose();
    },
    onError: re.onError,
  });
  const close = () => {
    re.reset();
    m.reset();
    onClose();
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!suppressErr && !nameErr && !conditionErr && re.ready) m.mutate();
  };
  const toggle = (list: string[], v: string, on: boolean) => (on ? [...new Set([...list, v])] : list.filter((x) => x !== v));
  const roleIds = [...new Set([...(roles.data?.items.map((r) => r.id) ?? []), ...f.roles])];
  const mandatory = rule?.effective_roles.filter((r) => !f.roles.includes(r)) ?? ["security_admin", "auditor"];

  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={creating ? "Новое правило оповещения" : `Правило «${rule.name}»`}
      description={
        locked
          ? "Системное правило и правило безопасности не отключаются: можно изменить только получателей."
          : "Изменение записывается в журнал аудита. Ослабление подтверждается паролем или кодом."
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        {creating && (
          <Field label="Вид правила">
            {({ id }) => (
              <Select id={id} value={f.kind} onChange={(e) => setF((p) => ({ ...p, kind: e.target.value }))}>
                <option value="threshold">{kindText.get("threshold")}: события по фильтру</option>
                <option value="new">{kindText.get("new")}: впервые встреченное значение</option>
              </Select>
            )}
          </Field>
        )}
        {!creating && <p className="text-sm text-muted">Вид: {kindText.get(kind) ?? kind}</p>}
        <Field label="Название" error={nameErr}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} disabled={locked} maxLength={200} value={f.name} onChange={(e) => setF((p) => ({ ...p, name: e.target.value }))} />
          )}
        </Field>
        <Field label="Описание">
          {({ id }) => <Input id={id} disabled={locked} maxLength={2000} value={f.description} onChange={(e) => setF((p) => ({ ...p, description: e.target.value }))} />}
        </Field>
        {(creating || editable.has(kind)) && !locked && f.kind === "threshold" && (
          <>
            <Field label="Фильтр событий" hint='Язык экрана «События», например: severity in ("high", "critical") and app = "crm-bot".' error={conditionErr}>
              {({ id, describedBy, invalid }) => (
                <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} className="font-mono" maxLength={2048} value={f.filter} onChange={(e) => setF((p) => ({ ...p, filter: e.target.value }))} />
              )}
            </Field>
            <Field label="Наименьшая серьёзность события">
              {({ id }) => (
                <Select id={id} value={f.min_severity} onChange={(e) => setF((p) => ({ ...p, min_severity: e.target.value as typeof p.min_severity }))}>
                  <option value="">Любая</option>
                  {severityOrder.map((s) => (
                    <option key={s} value={s}>
                      {severityTitle.get(s)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <fieldset className="flex flex-col gap-1">
              <legend className="text-sm font-medium">Группировать по (до 4 полей)</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {groupFields.map((g) => (
                  <Check
                    key={g}
                    label={groupTitle.get(g) ?? g}
                    checked={f.group_by.includes(g)}
                    disabled={!f.group_by.includes(g) && f.group_by.length >= 4}
                    onCheckedChange={(on) => setF((p) => ({ ...p, group_by: toggle(p.group_by, g, on) }))}
                  />
                ))}
              </div>
            </fieldset>
          </>
        )}
        {(creating || kind === "new") && !locked && f.kind === "new" && (
          <Field label="За чем следить">
            {({ id }) => (
              <Select id={id} value={f.field} onChange={(e) => setF((p) => ({ ...p, field: e.target.value as typeof p.field }))}>
                {newFields.map(([v, t]) => (
                  <option key={v} value={v}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {!locked && (
          <>
            <Field label="Серьёзность оповещения">
              {({ id }) => (
                <Select id={id} value={f.severity} onChange={(e) => setF((p) => ({ ...p, severity: e.target.value as typeof p.severity }))}>
                  {severityOrder.map((s) => (
                    <option key={s} value={s}>
                      {severityTitle.get(s)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Окно подавления после закрытия, минут" hint="Повтор в это окно не создаёт нового оповещения." error={suppressErr}>
              {({ id, describedBy, invalid }) => (
                <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={f.suppress} onChange={(e) => setF((p) => ({ ...p, suppress: e.target.value }))} />
              )}
            </Field>
            <Check label="Правило включено" checked={f.enabled} onCheckedChange={(v) => setF((p) => ({ ...p, enabled: v }))} />
          </>
        )}

        <fieldset className="flex flex-col gap-1">
          <legend className="text-sm font-medium">Получатели оповещений</legend>
          <p className="text-xs text-muted">
            Всегда получают: {mandatory.join(", ") || "администратор безопасности и аудитор"}. Их нельзя убрать. Удаление получателя — ослабление.
          </p>
          {canRoles ? (
            <div className="flex flex-wrap gap-x-4 gap-y-1" role="group" aria-label="Роли-получатели">
              {roleIds
                .filter((r) => !["security_admin", "auditor"].includes(r))
                .map((r) => (
                  <Check
                    key={r}
                    label={roles.data?.items.find((x) => x.id === r)?.display_name ?? r}
                    checked={f.roles.includes(r)}
                    onCheckedChange={(on) => setF((p) => ({ ...p, roles: toggle(p.roles, r, on) }))}
                  />
                ))}
            </div>
          ) : (
            <p className="text-xs text-muted">Роли: {f.roles.join(", ") || "не заданы"}. Для выбора ролей нужно право «roles.read».</p>
          )}
          {canUsers ? (
            <div className="flex max-h-32 flex-wrap gap-x-4 gap-y-1 overflow-auto" role="group" aria-label="Пользователи-получатели">
              {(users.data ?? []).map((u) => (
                <Check
                  key={u.id}
                  label={u.display_name || u.login}
                  checked={f.users.includes(u.id)}
                  onCheckedChange={(on) => setF((p) => ({ ...p, users: toggle(p.users, u.id, on) }))}
                />
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted">Пользователей-получателей: {f.users.length}. Для выбора нужно право «users.read».</p>
          )}
        </fieldset>
        <ErrorBanner error={roles.error ?? users.error} />
        <ReauthPrompt r={re} />
        <ErrorBanner error={visibleError(m.error)} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || Boolean(suppressErr || nameErr || conditionErr) || !re.ready}>
            {creating ? "Создать правило" : "Сохранить правило"}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
