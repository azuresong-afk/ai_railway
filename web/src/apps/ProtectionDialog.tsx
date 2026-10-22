import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { type Application, appsApi, splitList } from "./api";

// Защита приложения (право applications.policy, В15 ревью 2.r3b, В25 ревью 2.r5): политика, режимы, режим отказа и
// домены-исключения. Словари меняются через API. Ослабление сервер подтверждает паролем или кодом — поле появляется по
// его ответу; что считается ослаблением, решает сервер.
export function ProtectionDialog({ app, mfa, onClose }: { app: Application; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["apps", "policies"], queryFn: ({ signal }) => appsApi.policies(signal) });
  const [f, setF] = useState({
    policy: app.policy,
    policy_mode: app.policy_mode,
    storage: app.storage,
    fail_mode: app.fail_mode,
    domains: app.exfil_allow_domains.join("\n"),
  });
  const re = useReauth(mfa);
  const domains = splitList(f.domains.toLowerCase());
  // Формат доменов проверяет сервер (400 с полем); консоль ограничивает только число.
  const domainsErr = domains.length > 1000 ? "Не больше 1000 доменов." : undefined;
  const m = useMutation({
    mutationFn: () =>
      appsApi.setProtection(app.id, {
        policy: f.policy,
        policy_mode: f.policy_mode,
        storage: f.storage,
        fail_mode: f.fail_mode,
        exfil_allow_domains: domains,
        ...re.body(),
      }),
    onSuccess: async () => {
      re.reset();
      await qc.invalidateQueries({ queryKey: ["apps", "list"] });
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
    if (!domainsErr && re.ready) m.mutate();
  };
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={`Защита приложения «${app.name}»`}
      description="Изменение записывается в журнал аудита. Ослабление защиты подтверждается паролем или кодом."
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <ErrorBanner error={policies.error} />
        <Field label="Политика">
          {({ id }) => (
            <Select id={id} value={f.policy} onChange={set("policy")}>
              {!(policies.data?.items ?? []).some((p) => p.id === f.policy) && <option value={f.policy}>{f.policy}</option>}
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
              <option value="enforce">Защита (enforce)</option>
              <option value="monitor">Мониторинг (monitor)</option>
            </Select>
          )}
        </Field>
        <Field label="Хранение содержимого">
          {({ id }) => (
            <Select id={id} value={f.storage} onChange={set("storage")}>
              <option value="masked">Маскированное</option>
              <option value="none">Не хранить</option>
              <option value="full">Полное (повышенный риск)</option>
            </Select>
          )}
        </Field>
        <Field label="При сбое проверки" hint="«Пропускать» — запрос уходит к модели без проверки, это ослабление.">
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={f.fail_mode} onChange={set("fail_mode")}>
              <option value="fail_closed">Блокировать запрос (fail_closed)</option>
              <option value="fail_open">Пропускать запрос (fail_open)</option>
            </Select>
          )}
        </Field>
        <Field label="Домены-исключения для защиты от утечки" hint="По одному на строку. Новый домен ослабляет защиту." error={domainsErr}>
          {({ id, describedBy, invalid }) => (
            <textarea
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              rows={3}
              value={f.domains}
              onChange={set("domains")}
              className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-base aria-[invalid=true]:border-sev-critical"
            />
          )}
        </Field>
        <p className="text-xs text-muted">Словари приложения ({app.lists.length}) меняются через API и здесь не затрагиваются.</p>
        <ReauthPrompt r={re} />
        <ErrorBanner error={visibleError(m.error)} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || Boolean(domainsErr) || !re.ready}>
            Сохранить защиту
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
