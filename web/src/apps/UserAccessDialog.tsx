import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { type Application, type UserAccess, appsApi } from "./api";

type Mode = UserAccess["mode"];

// Пределы как на сервере.
const maxLeeway = 300;
const maxGroupsPerModel = 64;

// Группы через запятую или с новой строки: имя группы может содержать пробелы; повторы убираются.
export function splitGroups(text: string): string[] {
  return [...new Set(text.split(/[,\n;]+/).map((g) => g.trim()).filter((g) => g !== ""))];
}

function modeHint(mode: Mode): string {
  switch (mode) {
    case "off":
      return "Пользователь — из заголовка X-AISec-User или поля user, как настроено у приложения. JWT не проверяется.";
    case "optional":
      return "Если приложение передало JWT в X-AISec-User-Token, шлюз проверяет его и берёт пользователя и группы из него; без JWT — X-AISec-User.";
    case "required":
      return "Запрос без действительного JWT в X-AISec-User-Token отклоняется шлюзом до обращения к модели.";
  }
}

// Пользователь приложения по JWT корпоративного IdP и доступ к моделям по группам (задача 4.21, DM-33; право
// applications.policy). Смягчение режима, смена издателя и расширение доступа к модели — ослабление: сервер просит
// пароль или код, поле появляется по его ответу.
export function UserAccessDialog({ app, mfa, onClose }: { app: Application; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const key = ["apps", "user-access", app.id];
  const q = useQuery({ queryKey: key, queryFn: ({ signal }) => appsApi.userAccess(app.id, signal) });
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`Пользователи и группы «${app.name}»`}
      description="Шлюз проверяет JWT корпоративного IdP по ключам из пакета конфигурации и открывает модели только нужным группам. Изменение записывается в журнал аудита."
    >
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка настройки…</p>}
      {q.data && (
        <AccessForm
          app={app}
          current={q.data}
          mfa={mfa}
          onDone={async () => {
            await qc.invalidateQueries({ queryKey: key });
            onClose();
          }}
          onCancel={onClose}
        />
      )}
    </FormDialog>
  );
}

function AccessForm({
  app,
  current,
  mfa,
  onDone,
  onCancel,
}: {
  app: Application;
  current: UserAccess;
  mfa: boolean;
  onDone: () => Promise<void>;
  onCancel: () => void;
}) {
  const names = [...app.models, ...Object.keys(app.aliases ?? {}).filter((a) => !app.models.includes(a))];
  const [mode, setMode] = useState<Mode>(current.mode);
  const [issuer, setIssuer] = useState(current.issuer);
  const [audience, setAudience] = useState(current.audience);
  const [claim, setClaim] = useState(current.groups_claim);
  const [leeway, setLeeway] = useState(String(current.leeway));
  const [groups, setGroups] = useState<Record<string, string>>(() =>
    Object.fromEntries(names.map((m) => [m, (current.model_groups[m] ?? []).join(", ")])),
  );
  const re = useReauth(mfa);
  const jwt = mode !== "off";
  const lw = Number(leeway);
  const issuerErr = jwt && !issuer.trim().startsWith("https://") ? "Адрес издателя JWT, как iss в токене: https://…" : undefined;
  const audErr = jwt && audience.trim() === "" ? "Значение aud, которое IdP выдаёт для этого приложения." : undefined;
  const leewayErr = !Number.isInteger(lw) || lw < 0 || lw > maxLeeway ? `Целое число от 0 до ${maxLeeway} секунд.` : undefined;
  const modelGroups = Object.fromEntries(
    Object.entries(groups)
      .map(([m, text]) => [m, splitGroups(text)] as const)
      .filter(([, g]) => g.length > 0),
  );
  const groupsErr = Object.values(modelGroups).some((g) => g.length > maxGroupsPerModel)
    ? `Не больше ${maxGroupsPerModel} групп на модель.`
    : !jwt && Object.keys(modelGroups).length > 0
      ? "Доступ по группам работает только с JWT: выберите режим «JWT или X-AISec-User» или «JWT обязателен»."
      : undefined;
  const invalid = Boolean(issuerErr || audErr || leewayErr || groupsErr);
  const save = useMutation({
    mutationFn: () =>
      appsApi.setUserAccess(app.id, {
        mode,
        issuer: issuer.trim(),
        audience: audience.trim(),
        groups_claim: claim.trim(),
        leeway: lw,
        model_groups: modelGroups,
        ...re.body(),
      }),
    onSuccess: async () => {
      re.reset();
      await onDone();
    },
    onError: re.onError,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!invalid && re.ready) save.mutate();
  };
  const cancel = () => {
    re.reset();
    onCancel();
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      {current.configured && current.updated_at && <p className="text-xs text-muted">Изменена {formatAbsolute(current.updated_at)}.</p>}
      <Field label="Пользователь запроса" hint={modeHint(mode)}>
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
            <option value="off">Только X-AISec-User (как раньше)</option>
            <option value="optional">JWT или X-AISec-User</option>
            <option value="required">JWT обязателен</option>
          </Select>
        )}
      </Field>
      <Field label="Издатель JWT (iss)" hint="Должен совпадать с издателем IdP во «Входе через IdP»: ключи подписи шлюзы получают оттуда." error={issuerErr}>
        {({ id, describedBy, invalid: inv }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={inv} value={issuer} onChange={(e) => setIssuer(e.target.value)} />
        )}
      </Field>
      <Field label="Аудитория (aud)" error={audErr}>
        {({ id, describedBy, invalid: inv }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={inv} value={audience} onChange={(e) => setAudience(e.target.value)} />
        )}
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Утверждение с группами" hint="По умолчанию groups.">
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={claim} onChange={(e) => setClaim(e.target.value)} />}
        </Field>
        <Field label="Допуск часов, секунд" hint="Для exp, nbf и iat токена." error={leewayErr}>
          {({ id, describedBy, invalid: inv }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={inv}
              inputMode="numeric"
              value={leeway}
              onChange={(e) => setLeeway(e.target.value)}
            />
          )}
        </Field>
      </div>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Доступ к моделям по группам</legend>
        <p className="text-xs text-muted">
          Пусто — модель доступна всем пользователям приложения. Группы через запятую — только пользователям с одной из них в JWT,
          остальные получают отказ без списка групп.
        </p>
        {names.map((m) => (
          <Field key={m} label={`Группы для ${m}`}>
            {({ id, describedBy }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                value={groups[m] ?? ""}
                onChange={(e) => setGroups((g) => ({ ...g, [m]: e.target.value }))}
              />
            )}
          </Field>
        ))}
        {groupsErr && <p className="text-sm text-sev-critical">{groupsErr}</p>}
      </fieldset>
      <ReauthPrompt r={re} />
      <ErrorBanner error={visibleError(save.error)} />
      <div className="flex justify-end gap-2">
        <Button onClick={cancel}>Отменить</Button>
        <Button type="submit" variant="primary" disabled={save.isPending || invalid || !re.ready}>
          Сохранить
        </Button>
      </div>
    </form>
  );
}
