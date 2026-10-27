import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import type { Me } from "../api/client";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, Panel } from "../ui/Layout";
import { incidentsApi } from "./api";

// Срок хранения закрытых инцидентов (365–1825 суток, по умолчанию 3 года). Сокращение необратимо и подтверждается паролем или кодом.
export function RetentionPanel({ me }: { me: Me }) {
  const qc = useQueryClient();
  const canManage = me.permissions.includes("incident_categories.manage");
  const q = useQuery({ queryKey: ["incidents", "settings"], queryFn: ({ signal }) => incidentsApi.settings(signal) });
  const [value, setValue] = useState<string>();
  const re = useReauth(me.mfa?.enabled === true);
  const current = q.data?.retention_days;
  const text = value ?? (current === undefined ? "" : String(current));
  const days = Number(text);
  const err = !Number.isInteger(days) || days < 365 || days > 1825 ? "Целое число суток от 365 до 1825." : undefined;
  const m = useMutation({
    mutationFn: () => incidentsApi.setSettings({ retention_days: days, ...re.body() }),
    onSuccess: async () => {
      re.reset();
      setValue(undefined);
      await qc.invalidateQueries({ queryKey: ["incidents", "settings"] });
    },
    onError: re.onError,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!err && re.ready) m.mutate();
  };
  return (
    <Panel className="max-w-xl">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Срок хранения инцидентов</h2>
        <p className="text-sm text-muted">
          Закрытые инциденты старше срока (от закрытия) удаляются вместе с хронологией, комментариями, ссылками на события и связанными
          оповещениями. Незакрытые инциденты не удаляются.
        </p>
        <ErrorBanner error={q.error} />
        {current !== undefined && <p className="text-sm">Сейчас: {current} сут.</p>}
        <Field label="Срок хранения закрытых инцидентов, суток" error={err}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" disabled={!canManage || current === undefined} value={text} onChange={(e) => setValue(e.target.value)} />
          )}
        </Field>
        {canManage && !err && current !== undefined && days < current && (
          <Banner kind="warning">Сокращение срока необратимо: инциденты старше нового срока будут удалены. Потребуется пароль или код.</Banner>
        )}
        <ReauthPrompt r={re} />
        <ErrorBanner error={visibleError(m.error)} />
        {canManage && (
          <div>
            <Button type="submit" variant="primary" disabled={m.isPending || Boolean(err) || current === undefined || days === current || !re.ready}>
              Сохранить срок
            </Button>
          </div>
        )}
      </form>
    </Panel>
  );
}
