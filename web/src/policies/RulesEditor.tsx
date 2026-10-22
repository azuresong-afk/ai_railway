import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { severityOrder, severityTitle } from "../alerts/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, Table, Td, Th } from "../ui/Layout";
import { actionText, type Policy, policiesApi, type PolicyRule, type PolicySpec } from "./api";
import { DiffView } from "./DiffView";
import { localDiff } from "./localDiff";

const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
const modeText = { monitor: "Мониторинг", enforce: "Защита" } as const;

// Порог вводится по-русски («0,8»); пустая строка — порога нет. null — значение неверно.
function parseThreshold(v: string): number | undefined | null {
  const t = v.trim().replace(",", ".");
  if (t === "") return undefined;
  const n = Number(t);
  return Number.isFinite(n) && n > 0 && n <= 1 ? n : null;
}
const showThreshold = (n: number | undefined) => (n === undefined ? "" : String(n).replace(".", ","));

// Редактор правил текущей версии (Н46): изменения сначала показываются списком различий с пометкой «ослабляет защиту»,
// сохраняются новой версией (PUT /policies/{id}); исключения версии редактор не трогает.
export function RulesEditor({ policy, mfa, onSaved }: { policy: Policy; mfa: boolean; onSaved: () => void }) {
  const qc = useQueryClient();
  const base = policy.spec;
  const [mode, setMode] = useState(base.mode);
  const [rules, setRules] = useState<PolicyRule[]>(base.rules);
  const [thr, setThr] = useState<Record<string, string>>({});
  const [comment, setComment] = useState("");
  const [nr, setNr] = useState({ id: "", detector: "", action: "log" as PolicyRule["action"], severity: "medium" as PolicyRule["severity"] });
  const re = useReauth(mfa);

  const bad = Object.values(thr).some((v) => parseThreshold(v) === null);
  const draft: PolicySpec = useMemo(() => {
    const withThr = rules.map((r) => {
      const t = thr[r.id] !== undefined ? parseThreshold(thr[r.id]!) : r.threshold;
      const rest = Object.fromEntries(Object.entries(r).filter(([k]) => k !== "threshold")) as PolicyRule;
      return t === undefined || t === null ? rest : { ...rest, threshold: t };
    });
    return { ...base, mode, rules: withThr };
  }, [base, mode, rules, thr]);
  const diff = useMemo(() => localDiff(base, draft), [base, draft]);
  const changed = diff.fields.length + diff.rules_added.length + diff.rules_removed.length + diff.rules_changed.length > 0 || diff.reordered;

  const patch = (id: string, p: Partial<PolicyRule>) => setRules((rs) => rs.map((r) => (r.id === id ? { ...r, ...p } : r)));
  const nrBad = nr.id !== "" && (!idPattern.test(nr.id) || rules.some((r) => r.id === nr.id)) ? "ID: латиница в нижнем регистре, цифры и «-», уникальный в политике." : undefined;
  const canAdd = nr.id !== "" && nr.detector.trim() !== "" && !nrBad;

  const m = useMutation({
    mutationFn: () => {
      // Исключения версии сервер сохраняет сам, если поле не передано.
      const spec = Object.fromEntries(Object.entries(draft).filter(([k]) => k !== "exceptions")) as PolicySpec;
      return policiesApi.update(policy.id, policy.current_version ?? 1, spec, comment.trim(), re.body());
    },
    onSuccess: async () => {
      re.reset();
      setComment("");
      await qc.invalidateQueries({ queryKey: ["policies"] });
      onSaved();
    },
    onError: re.onError,
  });

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">Изменения сохраняются новой версией политики. Исключения версии редактор не меняет — они на вкладке «Исключения».</p>
      <Field label="Режим политики">
        {({ id }) => (
          <Select id={id} value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
            {Object.entries(modeText).map(([k, t]) => (
              <option key={k} value={k}>
                {t}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Table aria-label="Правила версии">
        <thead>
          <tr>
            <Th>Правило</Th>
            <Th>Детектор</Th>
            <Th>Действие</Th>
            <Th>Серьёзность</Th>
            <Th>Порог</Th>
            <Th>Действия</Th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => {
            const tv = thr[r.id] ?? showThreshold(r.threshold);
            return (
              <tr key={r.id}>
                <Td className="font-mono">{r.id}</Td>
                <Td className="font-mono">{r.detector}</Td>
                <Td>
                  <Select aria-label={`Действие правила ${r.id}`} value={r.action} onChange={(e) => patch(r.id, { action: e.target.value as PolicyRule["action"] })}>
                    {Object.entries(actionText).map(([a, t]) => (
                      <option key={a} value={a}>
                        {t}
                      </option>
                    ))}
                  </Select>
                </Td>
                <Td>
                  <Select aria-label={`Серьёзность правила ${r.id}`} value={r.severity} onChange={(e) => patch(r.id, { severity: e.target.value as PolicyRule["severity"] })}>
                    {severityOrder.map((s) => (
                      <option key={s} value={s}>
                        {severityTitle.get(s)}
                      </option>
                    ))}
                  </Select>
                </Td>
                <Td>
                  <Input
                    aria-label={`Порог правила ${r.id}`}
                    aria-invalid={parseThreshold(tv) === null}
                    inputMode="decimal"
                    className="w-20"
                    value={tv}
                    onChange={(e) => setThr((t) => ({ ...t, [r.id]: e.target.value }))}
                  />
                  {parseThreshold(tv) === null && <span role="alert" className="block text-xs">Число больше 0 и не больше 1.</span>}
                </Td>
                <Td>
                  <Button variant="danger" aria-label={`Убрать правило ${r.id}`} onClick={() => setRules((rs) => rs.filter((x) => x.id !== r.id))}>
                    Убрать
                  </Button>
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
      <fieldset className="flex flex-wrap items-end gap-2">
        <legend className="text-sm font-medium">Добавить правило</legend>
        <Field label="ID правила" {...(nrBad ? { error: nrBad } : {})}>{({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} value={nr.id} onChange={(e) => setNr({ ...nr, id: e.target.value })} />}</Field>
        <Field label="Детектор" hint="Например, pii.ru.">{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={nr.detector} onChange={(e) => setNr({ ...nr, detector: e.target.value })} />}</Field>
        <Field label="Действие нового правила">
          {({ id }) => (
            <Select id={id} value={nr.action} onChange={(e) => setNr({ ...nr, action: e.target.value as PolicyRule["action"] })}>
              {Object.entries(actionText).map(([a, t]) => (
                <option key={a} value={a}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button
          disabled={!canAdd}
          onClick={() => {
            setRules((rs) => [...rs, { id: nr.id, detector: nr.detector.trim(), action: nr.action, severity: nr.severity }]);
            setNr({ ...nr, id: "", detector: "" });
          }}
        >
          Добавить правило
        </Button>
      </fieldset>
      {changed ? <DiffView diff={diff} preview /> : <p className="text-sm text-muted">Изменений нет.</p>}
      {changed && <p className="text-xs text-muted">Пометка «ослабляет защиту» — предварительная оценка консоли; окончательно решает сервер и при ослаблении попросит пароль или код.</p>}
      <Field label="Комментарий к версии (необязательно)">{({ id }) => <Input id={id} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} />}</Field>
      <ReauthPrompt r={re} />
      <ErrorBanner error={visibleError(m.error)} />
      {m.isSuccess && <Banner kind="info">Версия сохранена.</Banner>}
      <div>
        <Button variant="primary" disabled={!changed || bad || m.isPending || !re.ready} onClick={() => m.mutate()}>
          Сохранить новую версию
        </Button>
      </div>
    </div>
  );
}
