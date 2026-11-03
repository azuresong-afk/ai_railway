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
import { JudgeEditor, type JudgeFields } from "./JudgeEditor";
import { criterionError, isJudgeRule, judgeActions, judgeDetector, judgeLimits, type PolicyJudgeRule, parseWhole, sectionErrors, sectionFromFields } from "./judge";
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
export function RulesEditor({ policy, mfa, onSaved, canReadProviders = false }: { policy: Policy; mfa: boolean; onSaved: () => void; canReadProviders?: boolean }) {
  const qc = useQueryClient();
  const base = policy.spec;
  const [mode, setMode] = useState(base.mode);
  const [rules, setRules] = useState<PolicyRule[]>(base.rules);
  const [thr, setThr] = useState<Record<string, string>>({});
  const [comment, setComment] = useState("");
  // Оценщик judge.llm: раздел judge и срок оценки правил — строки ввода (пусто — по умолчанию).
  const [jf, setJf] = useState<JudgeFields>({
    provider: base.judge?.provider ?? "",
    model: base.judge?.model ?? "",
    calls: base.judge?.max_calls_per_minute ? String(base.judge.max_calls_per_minute) : "",
    tokens: base.judge?.max_tokens_per_hour ? String(base.judge.max_tokens_per_hour) : "",
  });
  const [tmo, setTmo] = useState<Record<string, string>>({});
  const [nr, setNr] = useState({ id: "", detector: "", action: "log" as PolicyRule["action"], severity: "medium" as PolicyRule["severity"] });
  const re = useReauth(mfa);

  const judgeRules = rules.filter(isJudgeRule);
  const judgeTouched = jf.provider.trim() !== "" || jf.model.trim() !== "" || judgeRules.length > 0;
  const judgeBad =
    (judgeTouched && Object.keys(sectionErrors(jf)).length > 0) ||
    judgeRules.length > judgeLimits.rules ||
    judgeRules.some(
      (r) =>
        !r.judge ||
        criterionError(r.judge.criterion) !== undefined ||
        (r.judge.mode === "sync" && tmo[r.id] !== undefined && parseWhole(tmo[r.id]!, judgeLimits.timeoutMin, judgeLimits.timeoutMax) === null),
    );
  const bad = Object.values(thr).some((v) => parseThreshold(v) === null) || judgeBad;
  const draft: PolicySpec = useMemo(() => {
    const withThr = rules.map((r) => {
      const t = thr[r.id] !== undefined ? parseThreshold(thr[r.id]!) : r.threshold;
      const rest = Object.fromEntries(Object.entries(r).filter(([k]) => k !== "threshold")) as PolicyRule;
      const out = t === undefined || t === null ? rest : { ...rest, threshold: t };
      if (!isJudgeRule(out) || !out.judge) return out;
      // Срок оценки: строка ввода → число; в режиме async срока и режима при отказе нет.
      const jr: PolicyJudgeRule = { kind: out.judge.kind, criterion: out.judge.criterion.trim() };
      if (out.judge.mode === "sync") {
        jr.mode = "sync";
        const raw = tmo[out.id];
        const ms = raw === undefined ? out.judge.timeout_ms : parseWhole(raw, judgeLimits.timeoutMin, judgeLimits.timeoutMax);
        if (typeof ms === "number") jr.timeout_ms = ms;
        if (out.judge.on_failure) jr.on_failure = out.judge.on_failure;
      }
      return { ...out, judge: jr };
    });
    const section = sectionFromFields(jf);
    const rest = Object.fromEntries(Object.entries(base).filter(([k]) => k !== "judge")) as PolicySpec;
    return { ...rest, mode, rules: withThr, ...(section ? { judge: section } : {}) };
  }, [base, mode, rules, thr, jf, tmo]);
  const diff = useMemo(() => localDiff(base, draft), [base, draft]);
  const changed = diff.fields.length + diff.rules_added.length + diff.rules_removed.length + diff.rules_changed.length > 0 || diff.reordered;

  const patch = (id: string, p: Partial<PolicyRule>) => setRules((rs) => rs.map((r) => (r.id === id ? { ...r, ...p } : r)));
  // Подраздел judge правила: режим async не имеет срока и режима при отказе, а блокировать в нём нельзя.
  const patchJudge = (id: string, p: Partial<PolicyJudgeRule>) => {
    if (p.mode === "async") setTmo((t) => Object.fromEntries(Object.entries(t).filter(([k]) => k !== id)));
    setRules((rs) =>
      rs.map((r) => {
        if (r.id !== id || !r.judge) return r;
        if (p.mode === "async") return { ...r, action: r.action === "block" ? "log" : r.action, judge: { kind: r.judge.kind, criterion: r.judge.criterion } };
        return { ...r, judge: { ...r.judge, ...p } };
      }),
    );
  };
  const removeRule = (id: string) => {
    setRules((rs) => rs.filter((x) => x.id !== id));
    setTmo((t) => Object.fromEntries(Object.entries(t).filter(([k]) => k !== id)));
  };
  const nrBad =
    nr.id !== "" && (!idPattern.test(nr.id) || rules.some((r) => r.id === nr.id))
      ? "ID: латиница в нижнем регистре, цифры и «-», уникальный в политике."
      : nr.detector.trim() === judgeDetector
        ? "Правила judge.llm добавляются ниже, в блоке «Модель-оценщик»: им нужен критерий."
        : undefined;
  const canAdd = nr.id !== "" && nr.detector.trim() !== "" && !nrBad && nr.detector.trim() !== judgeDetector;

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
                    {Object.entries(actionText)
                      .filter(([a]) => !isJudgeRule(r) || judgeActions(r).includes(a as PolicyRule["action"]))
                      .map(([a, t]) => (
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
                  <Button variant="danger" aria-label={`Убрать правило ${r.id}`} onClick={() => removeRule(r.id)}>
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
      <JudgeEditor
        fields={jf}
        setFields={setJf}
        rules={rules}
        patchJudge={patchJudge}
        timeouts={tmo}
        setTimeouts={setTmo}
        addRule={(r) => setRules((rs) => [...rs, r])}
        removeRule={removeRule}
        canReadProviders={canReadProviders}
      />
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
