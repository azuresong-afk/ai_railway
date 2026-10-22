import { useMutation, useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { ApiError } from "../api/client";
import { appsApi } from "../apps/api";
import { DecisionBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { Banner, RawText, Table, Td, Th } from "../ui/Layout";
import { actionText, type PolicyTestResult, policiesApi, type PolicyVersion } from "./api";

const maxText = 200_000;

// Песочница (ТЗ 5.3): текст проверяется тем же конвейером, что Check API шлюза; к модели он не уходит и нигде не сохраняется.
export function Sandbox({
  policyId,
  versions,
  canReadApps,
}: {
  policyId: string;
  versions: PolicyVersion[];
  canReadApps: boolean;
}) {
  const [text, setText] = useState("");
  const [direction, setDirection] = useState<"input" | "output">("input");
  const [version, setVersion] = useState("");
  const [appId, setAppId] = useState("");
  const apps = useQuery({ queryKey: ["apps", "list"], queryFn: ({ signal }) => appsApi.applications(signal), enabled: canReadApps });
  const m = useMutation({
    mutationFn: () =>
      policiesApi.test({
        policy_id: policyId,
        ...(version ? { version: Number(version) } : {}),
        ...(appId ? { application_id: appId } : {}),
        request: { direction, text },
      }),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (text !== "" && text.length <= maxText) m.mutate();
  };
  const tooLong = text.length > maxText;

  return (
    <div className="flex flex-col gap-3">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Проверяемый текст" hint="Текст не уходит модели и не сохраняется." error={tooLong ? `Текст длиннее ${maxText} символов. Сократите его.` : undefined}>
          {({ id, describedBy, invalid }) => (
            <textarea
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              rows={6}
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-base aria-[invalid=true]:border-sev-critical"
            />
          )}
        </Field>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Направление">
            {({ id }) => (
              <Select id={id} value={direction} onChange={(e) => setDirection(e.target.value as "input" | "output")}>
                <option value="input">Запрос к модели</option>
                <option value="output">Ответ модели</option>
              </Select>
            )}
          </Field>
          <Field label="Версия политики">
            {({ id }) => (
              <Select id={id} value={version} onChange={(e) => setVersion(e.target.value)}>
                <option value="">Текущая</option>
                {versions.map((v) => (
                  <option key={v.version} value={v.version}>
                    Версия {v.version}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {canReadApps && (
            <Field label="Приложение" hint="Нужно, если в политике есть правила по словарям приложения.">
              {({ id, describedBy }) => (
                <Select id={id} aria-describedby={describedBy} value={appId} onChange={(e) => setAppId(e.target.value)}>
                  <option value="">Без приложения</option>
                  {(apps.data ?? []).filter((a) => a.status === "active").map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
        </div>
        {m.error instanceof ApiError && m.error.status === 422 ? <UnprocessableHint detail={m.error.detail} /> : <ErrorBanner error={m.error} />}
        <div>
          <Button type="submit" variant="primary" disabled={m.isPending || text === "" || tooLong}>
            Проверить текст
          </Button>
        </div>
      </form>
      {m.data && <Result r={m.data} />}
    </div>
  );
}

// H-Р5: ответ 422 — не поломка интерфейса, а подсказка, что делать со словарём приложения.
function UnprocessableHint({ detail }: { detail: string }) {
  return (
    <Banner kind="warning">
      {detail} Если правило политики ссылается на словарь (категория <code>lists.…</code>), он задаётся в приложении: выберите приложение, у
      которого словарь есть, или добавьте словарь в <a className="underline" href="#/apps">разделе «Приложения»</a>.
    </Banner>
  );
}

function Result({ r }: { r: PolicyTestResult }) {
  // Форма и подпись метки — из дизайн-системы; в режиме мониторинга блокировка только «была бы».
  const decision = r.blocked ? "blocked" : r.decision === "allow" ? (r.action === "block" ? "would_block" : "allowed") : "masked";
  return (
    <section aria-label="Результат проверки" className="flex flex-col gap-3">
      <h3 className="text-md font-semibold">Результат</h3>
      <p>
        <DecisionBadge decision={decision} />
      </p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted">Решение политики</dt>
        <dd>{actionText[r.action]}</dd>
        <dt className="text-muted">Режим</dt>
        <dd>{r.mode === "enforce" ? "Защита" : "Мониторинг"}</dd>
        {r.rule && (
          <>
            <dt className="text-muted">Сработавшее правило</dt>
            <dd className="font-mono">{r.rule}</dd>
          </>
        )}
        {r.message && (
          <>
            <dt className="text-muted">Сообщение</dt>
            <dd>{r.message}</dd>
          </>
        )}
      </dl>
      {r.fail_block && <Banner kind="warning">Сбой детектора при режиме «fail_closed»: шлюз ответил бы 503.</Banner>}
      {r.incomplete && <Banner kind="warning">Часть детекторов не дала результата, проверка неполная.</Banner>}
      {r.unchecked && <Banner kind="info">У политики нет правил для этого направления: детекторы не запускались, «пропущено» не означает «проверено».</Banner>}
      {r.failures.length > 0 && (
        <p className="text-sm">Сбои детекторов: {r.failures.map((f) => `${f.detector} (${f.reason === "timeout" ? "таймаут" : "ошибка"})`).join(", ")}.</p>
      )}
      <div>
        <h4 className="text-sm font-medium">Находки {r.findings_truncated ? "(показана часть)" : ""}</h4>
        {r.findings.length === 0 ? (
          <p className="text-sm text-muted">Находок нет.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Детектор</Th>
                <Th>Категория</Th>
                <Th>Оценка</Th>
                <Th>Правило</Th>
                <Th>Действие</Th>
              </tr>
            </thead>
            <tbody>
              {r.findings.map((f, i) => (
                <tr key={`${f.detector}-${f.start}-${i}`}>
                  <Td className="font-mono">{f.detector}</Td>
                  <Td>{f.category}</Td>
                  <Td>{f.score.toFixed(2).replace(".", ",")}</Td>
                  <Td className="font-mono">{f.rule ?? "—"}</Td>
                  <Td>{f.apply === "redact" ? "Замаскировано" : (f.action ?? "—")}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
      {r.texts.length > 0 && (
        <div className="flex flex-col gap-2">
          <h4 className="text-sm font-medium">Текст после защиты</h4>
          {r.texts.map((t, i) => (
            <div key={`${t.location}-${i}`}>
              <p className="text-xs text-muted">
                {t.location}
                {t.role ? `, ${t.role}` : ""}
                {t.changed ? ": изменён" : ": без изменений"}
              </p>
              <RawText>{t.text}</RawText>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
