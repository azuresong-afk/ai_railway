import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { Button } from "../ui/Button";
import { Check, Field, Input } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { policiesApi } from "../policies/api";
import { type ExceptionCondition, eventsApi } from "./api";

type Key = "category" | "pattern" | "fragment" | "app" | "user" | "source";
const keyTitle = new Map<Key, string>([
  ["category", "Категория находки"],
  ["pattern", "Правило детектора"],
  ["fragment", "Фрагмент текста (по хешу)"],
  ["app", "Приложение"],
  ["user", "Пользователь (псевдоним)"],
  ["source", "Источник текста"],
]);
const keys: Key[] = ["category", "pattern", "fragment", "app", "user", "source"];
// Детектор целиком для всех приложений не отключается: нужно хотя бы одно из этих условий (сервер проверяет так же).
const scoping: Key[] = ["pattern", "fragment", "app", "user"];

// Значение условия черновика по ключу (без обращения по произвольному индексу).
function valueOf(c: ExceptionCondition, k: Key): string {
  switch (k) {
    case "category":
      return c.category ?? "";
    case "pattern":
      return c.pattern ?? "";
    case "fragment":
      return c.fragment ?? "";
    case "app":
      return c.app ?? "";
    case "user":
      return c.user ?? "";
    case "source":
      return c.source ?? "";
  }
}

const sourceText = new Map<string, string>([
  ["user", "запрос пользователя"],
  ["rag", "данные RAG"],
  ["tool", "результат инструмента"],
  ["output", "ответ модели"],
]);
const shown = (k: Key, v: string) => (k === "fragment" ? `…${v.slice(-8)}` : k === "source" ? (sourceText.get(v) ?? v) : v);
const label = (c: ExceptionCondition) => [c.detector, c.category, c.pattern, c.source ? sourceText.get(c.source) ?? c.source : ""].filter(Boolean).join(" / ");

// «Создать исключение» по черновику события (ТЗ 5.3, задача 3.22): условия выбирает человек, срок 30 суток по умолчанию,
// не больше 365; добавление ослабляет защиту, поэтому нужен пароль или код. Исключение — новая версия политики.
export function ExceptionDialog({ eventId, mfa, defaultReason, onClose }: { eventId: string; mfa: boolean; defaultReason: string; onClose: () => void }) {
  const qc = useQueryClient();
  const draft = useQuery({ queryKey: ["event", eventId, "exception-draft"], queryFn: ({ signal }) => eventsApi.exceptionDraft(eventId, signal) });
  const [item, setItem] = useState(0);
  const [off, setOff] = useState<Set<Key>>(new Set());
  const [days, setDays] = useState("30");
  const [reason, setReason] = useState(defaultReason);
  const [secret, setSecret] = useState("");
  const [done, setDone] = useState<string>();

  const d = draft.data;
  const cond = d?.items.at(item);
  const picked = cond ? keys.filter((k) => valueOf(cond, k) !== "" && !off.has(k)) : [];
  const daysN = Number(days);
  const daysOk = Number.isInteger(daysN) && daysN >= 1 && daysN <= 365;
  const scoped = picked.some((k) => scoping.includes(k));
  const blocked = !d?.policy ? "У события нет политики, в которую можно добавить исключение." : d.template ? "template" : d.items.length === 0 ? "none" : undefined;

  const m = useMutation({
    mutationFn: () => {
      const body = {
        detector: cond!.detector,
        ...Object.fromEntries(picked.map((k) => [k, valueOf(cond!, k)])),
        reason: reason.trim(),
        expires_in_days: daysN,
        event_id: eventId,
        base_version: d!.base_version!,
        ...(mfa ? { code: secret } : { password: secret }),
      };
      return policiesApi.addException(d!.policy!, body);
    },
    onSuccess: async (r) => {
      setSecret("");
      setDone(`Исключение добавлено: версия ${r.policy.current_version ?? ""} политики «${r.policy.name}». Срок — ${days} сут.`);
      await qc.invalidateQueries({ queryKey: ["policies"] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: () => setSecret(""),
  });
  const close = () => {
    setSecret("");
    m.reset();
    onClose();
  };
  const toggle = (k: Key, on: boolean) =>
    setOff((prev) => {
      const next = new Set(prev);
      if (on) next.delete(k);
      else next.add(k);
      return next;
    });
  const ready = Boolean(cond) && !blocked && scoped && daysOk && reason.trim() !== "" && secret !== "" && d?.base_version !== undefined;

  return (
    <FormDialog open onOpenChange={(v) => !v && close()} title="Создать исключение" description="Шлюз перестанет применять правило к находкам, подходящим под выбранные условия, пока не истечёт срок.">
      {done ? (
        <>
          <Banner kind="info">{done}</Banner>
          <div className="flex justify-end">
            <Button variant="primary" onClick={close}>
              Готово
            </Button>
          </div>
        </>
      ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) m.mutate();
          }}
        >
          <ErrorBanner error={draft.error} />
          {draft.isPending && <p className="text-sm text-muted">Загружаю черновик…</p>}
          {blocked === "template" && (
            <Banner kind="warning">
              Событие обработано по шаблону политики, а шаблон менять нельзя. Создайте свою политику на основе шаблона, назначьте её приложению и добавьте исключение после следующего события.
            </Banner>
          )}
          {blocked === "none" && <Banner kind="info">По этому событию нечего исключать: находок, давших итоговое действие, нет.</Banner>}
          {blocked && blocked !== "template" && blocked !== "none" && <Banner kind="warning">{blocked}</Banner>}
          {d && !blocked && cond && (
            <>
              {d.items.length > 1 && (
                <Field label="Находка">
                  {({ id }) => (
                    <select
                      id={id}
                      value={item}
                      onChange={(e) => {
                        setItem(Number(e.target.value));
                        setOff(new Set());
                      }}
                      className="h-[var(--control-h)] w-full rounded-control border border-line-strong bg-surface px-2 text-base"
                    >
                      {d.items.map((c, i) => (
                        <option key={i} value={i}>
                          {label(c)}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
              )}
              <fieldset className="flex flex-col gap-1.5">
                <legend className="text-sm font-medium">Условия исключения (соединяются «и»)</legend>
                <p className="text-sm">Детектор: <span className="font-mono">{cond.detector}</span></p>
                {keys
                  .filter((k) => valueOf(cond, k) !== "")
                  .map((k) => (
                    <Check key={k} label={`${keyTitle.get(k)}: ${shown(k, valueOf(cond, k))}`} checked={!off.has(k)} onCheckedChange={(on) => toggle(k, on)} />
                  ))}
              </fieldset>
              {!scoped && <Banner kind="warning">Оставьте хотя бы одно из условий: правило, фрагмент, приложение или пользователь. Детектор целиком для всех приложений отключить нельзя.</Banner>}
              {cond.source && off.has("source") && (
                <Banner kind="warning">
                  Без условия «Источник текста» исключение действует на все тексты: запрос пользователя, данные RAG и инструментов и ответ модели. Ложное срабатывание в одном
                  источнике обычно не повод отключать проверку в остальных.
                </Banner>
              )}
              {scoped && !picked.some((k) => k === "app" || k === "fragment" || k === "user") && (
                <Banner kind="warning">Исключение только по правилу действует во всех приложениях этой политики. Добавьте приложение или фрагмент, если нужно уже.</Banner>
              )}
              <Field label="Срок, суток" hint="От 1 до 365, по умолчанию 30." {...(!daysOk ? { error: "Введите целое число от 1 до 365." } : {})}>
                {({ id, describedBy, invalid }) => (
                  <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
                )}
              </Field>
              <Field label="Причина" hint="До 500 знаков. Причина попадёт в политику, историю её версий и на все шлюзы: не вставляйте содержимое запроса.">
                {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />}
              </Field>
              <Banner kind="warning">
                Исключение ослабляет защиту. Подтвердите, что это вы: введите {mfa ? "код из приложения-аутентификатора" : "текущий пароль"}. Действие запишется в журнал аудита как ослабление.
              </Banner>
              <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
                {({ id }) => (
                  <Input id={id} type={mfa ? "text" : "password"} autoComplete={mfa ? "one-time-code" : "current-password"} value={secret} onChange={(e) => setSecret(e.target.value)} />
                )}
              </Field>
            </>
          )}
          <ErrorBanner error={m.error} />
          <div className="flex justify-end gap-2">
            <Button onClick={close}>Отменить</Button>
            <Button type="submit" variant="primary" disabled={!ready || m.isPending}>
              Добавить исключение
            </Button>
          </div>
        </form>
      )}
    </FormDialog>
  );
}
