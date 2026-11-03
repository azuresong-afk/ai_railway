import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { providersApi } from "../providers/api";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import type { PolicyRule } from "./api";
import {
  criterionError,
  failureText,
  isJudgeRule,
  judgeDetector,
  judgeLimits,
  kindText,
  modeText,
  parseWhole,
  type PolicyJudgeRule,
  sectionErrors,
} from "./judge";

const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
const area = "w-full rounded-control border border-line-strong bg-surface px-2 py-1 text-base aria-[invalid=true]:border-sev-critical";

export interface JudgeFields {
  provider: string;
  model: string;
  calls: string;
  tokens: string;
}

const dirText = { output: "Ответ модели", input: "Запрос пользователя", both: "Запрос и ответ" } as const;
type Dir = keyof typeof dirText;

// Раздел judge и правила judge.llm политики (задача 5.29, ADR-0030, раздел 2): оценщик у заказчика, критерии на
// естественном языке, режим и поведение при отказе. Сам редактор правил хранит состояние и считает различия:
// здесь только поля и подсказки; пределы — как в API.
export function JudgeEditor({
  fields,
  setFields,
  rules,
  patchJudge,
  timeouts,
  setTimeouts,
  addRule,
  removeRule,
  canReadProviders,
}: {
  fields: JudgeFields;
  setFields: (f: JudgeFields) => void;
  rules: PolicyRule[];
  patchJudge: (id: string, p: Partial<PolicyJudgeRule>) => void;
  timeouts: Record<string, string>;
  setTimeouts: (t: Record<string, string>) => void;
  addRule: (r: PolicyRule) => void;
  removeRule: (id: string) => void;
  canReadProviders: boolean;
}) {
  const listId = useId();
  const providers = useQuery({ queryKey: ["providers", "list"], queryFn: ({ signal }) => providersApi.list(signal), enabled: canReadProviders });
  const onPrem = (providers.data?.items ?? []).filter((p) => p.on_premise && p.type === "openai");
  const judgeRules = rules.filter(isJudgeRule);
  const sectionTouched = fields.provider.trim() !== "" || fields.model.trim() !== "" || judgeRules.length > 0;
  const errs = sectionTouched ? sectionErrors(fields) : {};
  const known = providers.data !== undefined && fields.provider.trim() !== "";
  const notOnPrem = known && !onPrem.some((p) => p.slug === fields.provider.trim());

  const [nr, setNr] = useState({ id: "", kind: "business" as PolicyJudgeRule["kind"], dir: "output" as Dir, criterion: "" });
  const nrIdErr = nr.id !== "" && (!idPattern.test(nr.id) || rules.some((r) => r.id === nr.id)) ? "ID: латиница в нижнем регистре, цифры и «-», уникальный в политике." : undefined;
  const nrCritErr = nr.criterion !== "" ? criterionError(nr.criterion) : undefined;
  const full = judgeRules.length >= judgeLimits.rules;
  const canAdd = nr.id !== "" && !nrIdErr && nr.criterion !== "" && !nrCritErr && !full;

  return (
    <fieldset className="flex flex-col gap-3 rounded-panel border border-line p-3">
      <legend className="px-1 text-sm font-medium">Модель-оценщик (judge.llm)</legend>
      <p className="text-sm text-muted">
        Правила на естественном языке проверяет модель, размещённая у вашей организации: текст запросов и ответов уходит на её адрес. Оценщик — провайдер с признаком «размещён у заказчика»; признак ставит администратор безопасности в разделе «Провайдеры».
      </p>
      {judgeRules.length > 0 && !fields.provider.trim() && <Banner kind="warning">В политике есть правила judge.llm, но оценщик не задан: укажите провайдера и модель, иначе политику не сохранить.</Banner>}
      <div className="flex flex-wrap items-start gap-2">
        <Field label="Провайдер-оценщик" hint="Краткое имя (slug) провайдера." {...(errs.provider ? { error: errs.provider } : {})}>
          {({ id, describedBy, invalid }) => (
            <>
              <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} list={listId} value={fields.provider} onChange={(e) => setFields({ ...fields, provider: e.target.value })} />
              <datalist id={listId}>
                {onPrem.map((p) => (
                  <option key={p.id} value={p.slug}>
                    {p.name}
                  </option>
                ))}
              </datalist>
            </>
          )}
        </Field>
        <Field label="Модель оценщика" hint="Имя модели у провайдера." {...(errs.model ? { error: errs.model } : {})}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} value={fields.model} onChange={(e) => setFields({ ...fields, model: e.target.value })} />}
        </Field>
        <Field label="Вызовов в минуту" hint={`Пусто — ${judgeLimits.callsDefault}.`} {...(errs.calls ? { error: errs.calls } : {})}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" className="w-28" value={fields.calls} onChange={(e) => setFields({ ...fields, calls: e.target.value })} />}
        </Field>
        <Field label="Токенов в час" hint={`Пусто — ${judgeLimits.tokensDefault}.`} {...(errs.tokens ? { error: errs.tokens } : {})}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" className="w-32" value={fields.tokens} onChange={(e) => setFields({ ...fields, tokens: e.target.value })} />}
        </Field>
      </div>
      {!canReadProviders && <p className="text-xs text-muted">Список провайдеров вам недоступен (нужно право «Провайдеры: просмотр»): введите имя вручную.</p>}
      {canReadProviders && providers.data !== undefined && onPrem.length === 0 && (
        <p className="text-xs text-muted">Нет провайдеров с признаком «размещён у заказчика». Пока он не поставлен, оценка не выполняется и событие получает отметку «не проверено».</p>
      )}
      {notOnPrem && <p role="status" className="text-xs">Провайдер «{fields.provider.trim()}» не найден среди размещённых у заказчика: правила получат отметку «не проверено», пока администратор безопасности не поставит признак.</p>}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="danger"
          disabled={judgeRules.length > 0 || (fields.provider === "" && fields.model === "" && fields.calls === "" && fields.tokens === "")}
          onClick={() => setFields({ provider: "", model: "", calls: "", tokens: "" })}
        >
          Убрать оценщика
        </Button>
        {judgeRules.length > 0 && <span className="text-xs text-muted">Сначала уберите правила judge.llm.</span>}
      </div>

      <h3 className="text-sm font-medium">Правила judge.llm ({judgeRules.length} из {judgeLimits.rules})</h3>
      {judgeRules.length === 0 && <p className="text-sm text-muted">Правил нет: оценщик не вызывается.</p>}
      {judgeRules.map((r) => (
        <JudgeRuleCard
          key={r.id}
          rule={r}
          timeout={timeouts[r.id]}
          onTimeout={(v) => setTimeouts({ ...timeouts, [r.id]: v })}
          patchJudge={patchJudge}
          onRemove={() => removeRule(r.id)}
        />
      ))}
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Добавить правило judge.llm</legend>
        <div className="flex flex-wrap items-start gap-2">
          <Field label="ID правила judge" {...(nrIdErr ? { error: nrIdErr } : {})}>
            {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} value={nr.id} onChange={(e) => setNr({ ...nr, id: e.target.value })} />}
          </Field>
          <Field label="Вид правила judge">
            {({ id }) => (
              <Select id={id} value={nr.kind} onChange={(e) => setNr({ ...nr, kind: e.target.value as PolicyJudgeRule["kind"] })}>
                {Object.entries(kindText).map(([k, t]) => (
                  <option key={k} value={k}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="К чему применять">
            {({ id }) => (
              <Select id={id} value={nr.dir} onChange={(e) => setNr({ ...nr, dir: e.target.value as Dir })}>
                {Object.entries(dirText).map(([k, t]) => (
                  <option key={k} value={k}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Field
          label="Критерий нового правила"
          hint={`Что запрещено, одним абзацем: от ${judgeLimits.criterionMin} до ${judgeLimits.criterionMax} символов. Например: «Ассистент не обещает возврат денег и скидки».`}
          {...(nrCritErr ? { error: nrCritErr } : {})}
        >
          {({ id, describedBy, invalid }) => <textarea id={id} aria-describedby={describedBy} aria-invalid={invalid} rows={3} maxLength={judgeLimits.criterionMax * 2} className={area} value={nr.criterion} onChange={(e) => setNr({ ...nr, criterion: e.target.value })} />}
        </Field>
        {full && <p className="text-xs">В политике уже {judgeLimits.rules} правил judge.llm — это предел. Уберите ненужные правила или объедините критерии.</p>}
        <div>
          <Button
            disabled={!canAdd}
            onClick={() => {
              addRule({
                id: nr.id,
                detector: judgeDetector,
                ...(nr.dir === "both" ? {} : { directions: [nr.dir] }),
                action: "log",
                severity: nr.kind === "content" ? "high" : "medium",
                judge: { kind: nr.kind, criterion: nr.criterion.trim() },
              });
              setNr({ ...nr, id: "", criterion: "" });
            }}
          >
            Добавить правило judge.llm
          </Button>
        </div>
      </fieldset>
    </fieldset>
  );
}

function JudgeRuleCard({
  rule,
  timeout,
  onTimeout,
  patchJudge,
  onRemove,
}: {
  rule: PolicyRule;
  timeout: string | undefined;
  onTimeout: (v: string) => void;
  patchJudge: (id: string, p: Partial<PolicyJudgeRule>) => void;
  onRemove: () => void;
}) {
  const j = rule.judge;
  if (!j) return null;
  const sync = j.mode === "sync";
  const critErr = criterionError(j.criterion);
  const tv = timeout ?? (j.timeout_ms === undefined ? "" : String(j.timeout_ms));
  const tErr = sync && parseWhole(tv, judgeLimits.timeoutMin, judgeLimits.timeoutMax) === null
    ? `Целое число миллисекунд от ${judgeLimits.timeoutMin} до ${judgeLimits.timeoutMax} или пусто (${judgeLimits.timeoutDefault}).`
    : undefined;
  return (
    <section aria-label={`Правило judge.llm ${rule.id}`} className="flex flex-col gap-2 rounded-panel border border-line p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm font-medium">{rule.id}</span>
        <Button variant="danger" aria-label={`Убрать правило judge.llm ${rule.id}`} onClick={onRemove}>
          Убрать
        </Button>
      </div>
      <Field label={`Критерий правила ${rule.id}`} {...(critErr ? { error: critErr } : {})}>
        {({ id, describedBy, invalid }) => (
          <textarea id={id} aria-describedby={describedBy} aria-invalid={invalid} rows={3} maxLength={judgeLimits.criterionMax * 2} className={area} value={j.criterion} onChange={(e) => patchJudge(rule.id, { criterion: e.target.value })} />
        )}
      </Field>
      <p className="text-xs text-muted">Действие, серьёзность и порог уверенности оценщика правила — в таблице правил выше.</p>
      <div className="flex flex-wrap items-start gap-2">
        <Field label={`Вид правила ${rule.id}`}>
          {({ id }) => (
            <Select id={id} value={j.kind} onChange={(e) => patchJudge(rule.id, { kind: e.target.value as PolicyJudgeRule["kind"] })}>
              {Object.entries(kindText).map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={`Режим правила ${rule.id}`} hint={sync ? "Оценка идёт до решения и добавляет задержку." : "Оценка после ответа: решение не меняется, находка появится в событии."}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={sync ? "sync" : "async"} onChange={(e) => patchJudge(rule.id, { mode: e.target.value as "async" | "sync" })}>
              {Object.entries(modeText).map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {sync && (
          <>
            <Field label={`Срок оценки правила ${rule.id}, мс`} hint={`Пусто — ${judgeLimits.timeoutDefault}.`} {...(tErr ? { error: tErr } : {})}>
              {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" className="w-28" value={tv} onChange={(e) => onTimeout(e.target.value)} />}
            </Field>
            <Field label={`При отказе оценщика, правило ${rule.id}`} hint="Оценщик не ответил в срок или недоступен.">
              {({ id, describedBy }) => (
                <Select id={id} aria-describedby={describedBy} value={j.on_failure ?? "allow"} onChange={(e) => patchJudge(rule.id, { on_failure: e.target.value as "allow" | "block" })}>
                  {Object.entries(failureText).map(([k, t]) => (
                    <option key={k} value={k}>
                      {t}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </>
        )}
      </div>
    </section>
  );
}
