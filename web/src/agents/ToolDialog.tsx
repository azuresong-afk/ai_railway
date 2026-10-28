import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { hasInvisible, revealInvisible } from "../ui/reveal";
import { type AgentTool, agentsApi, type Risk } from "./api";
import { type DiffRow, descriptorLines, diffLines } from "./diff";
import { RiskBadge, riskLabel, riskOrder, StatusBadge } from "./labels";
import { conflictText, isConflict, SecretField, secretBody } from "./Secret";

const mark = new Map<DiffRow["kind"], string>([
  ["same", "  "],
  ["add", "+ "],
  ["del", "− "],
]);
const rowStyle = new Map<DiffRow["kind"], string>([
  ["same", ""],
  ["add", "bg-surface-hover font-medium"],
  ["del", "bg-surface-hover line-through"],
]);

// Описание инструмента и аргументы приходят от внешнего сервера: выводятся только как текст, с префиксом + или − у строки.
export function Diff({ rows }: { rows: DiffRow[] }) {
  return (
    <pre aria-label="Разница описаний" className="max-h-72 overflow-auto rounded-control border border-line bg-bg p-2 font-mono text-xs">
      {rows.map((r, i) => (
        <div key={i} data-kind={r.kind} className={`whitespace-pre-wrap break-words ${rowStyle.get(r.kind)}`}>
          {mark.get(r.kind)}
          {revealInvisible(r.text)}
        </div>
      ))}
    </pre>
  );
}

const rank = (r: Risk) => riskOrder.indexOf(r);

// Карточка инструмента: разница одобренного и текущего описания, одобрение, смена риска и снятие одобрения.
export function ToolDialog({ tool, canApprove, mfa, onClose }: { tool: AgentTool; canApprove: boolean; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["agent-tool", tool.id], queryFn: ({ signal }) => agentsApi.tool(tool.id, signal) });
  const d = q.data;
  const [risk, setRisk] = useState<Risk | undefined>();
  const [comment, setComment] = useState("");
  const [secret, setSecret] = useState("");
  const cur = d ?? tool;
  const chosen = risk ?? cur.risk;
  const lowering = rank(chosen) < rank(cur.risk);
  const weakening = cur.status === "changed" || cur.status === "suspicious" || lowering;

  const done = async () => {
    setSecret("");
    await qc.invalidateQueries({ queryKey: ["agent-tools"] });
    await qc.invalidateQueries({ queryKey: ["agent-tool", tool.id] });
  };
  const fail = () => setSecret("");
  const approve = useMutation({
    mutationFn: () => agentsApi.approve(tool.id, { risk: chosen, hash: cur.hash, ...(comment ? { comment } : {}), ...secretBody(mfa, secret) }),
    onSuccess: async () => {
      await done();
      onClose();
    },
    onError: async (e) => {
      fail();
      // Описание изменилось, пока администратор смотрел: показываем новое, одобрение не выполняется.
      if (isConflict(e)) await qc.invalidateQueries({ queryKey: ["agent-tool", tool.id] });
    },
  });
  const setRiskM = useMutation({
    mutationFn: () => agentsApi.setRisk(tool.id, { risk: chosen, ...(comment ? { comment } : {}), ...secretBody(mfa, secret) }),
    onSuccess: async () => {
      await done();
      onClose();
    },
    onError: fail,
  });
  const revoke = useMutation({
    mutationFn: () => agentsApi.revoke(tool.id, comment),
    onSuccess: async () => {
      await done();
      onClose();
    },
  });
  const busy = approve.isPending || setRiskM.isPending || revoke.isPending;

  const rows = d ? diffLines(d.approved_descriptor ? descriptorLines(d.approved_descriptor) : [], descriptorLines(d.descriptor)) : [];
  const conflict = conflictText(approve.error, "Описание изменилось, пока вы его смотрели. Проверьте новое описание ниже и повторите одобрение.");
  const canSetRisk = cur.status === "approved" && chosen !== cur.risk;
  const canRevoke = cur.status === "approved" || cur.status === "changed" || cur.status === "suspicious";
  const secretMissing = secret === "";

  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Инструмент: ${tool.name}`} description="Описание пришло от MCP-сервера и показано как текст.">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge status={cur.status} />
        <RiskBadge risk={cur.risk} />
        <span className="text-xs text-muted">Последний раз виден: {formatAbsolute(cur.last_seen)}</span>
      </div>
      {q.isPending && <p className="text-sm text-muted">Загрузка описания…</p>}
      <ErrorBanner error={q.error} />
      {d && (
        <>
          {cur.status === "suspicious" && (
            <Banner kind="error">В описании найдены внедрённые инструкции для модели (DM-24). Одобрять такой инструмент не рекомендуется.</Banner>
          )}
          {cur.status === "changed" && <Banner kind="warning">Описание изменилось после одобрения. Проверьте разницу перед повторным одобрением.</Banner>}
          {rows.some((r) => hasInvisible(r.text)) && (
            <Banner kind="error">
              В описании есть скрытые управляющие символы: они могут менять видимый порядок текста. Ниже они показаны как ⟦U+…⟧.
            </Banner>
          )}
          <section aria-label="Описание" className="flex flex-col gap-1">
            <h3 className="text-md font-semibold">{d.approved_descriptor ? "Что изменилось" : "Описание"}</h3>
            <p className="text-xs text-muted">
              {d.approved_descriptor ? "Строки со знаком − были в одобренном описании, со знаком + появились в текущем." : "Инструмент ещё не одобрялся."}
            </p>
            <Diff rows={rows} />
            <p className="font-mono text-xs break-all text-muted">Хеш ({cur.hash_alg}): {cur.hash}</p>
          </section>
        </>
      )}
      {canApprove && d && (
        <>
          <Field label="Уровень риска" hint="От него зависят правила политики вызовов.">
            {({ id, describedBy }) => (
              <Select id={id} aria-describedby={describedBy} value={chosen} onChange={(e) => setRisk(e.target.value as Risk)}>
                {riskOrder.map((r) => (
                  <option key={r} value={r}>
                    {riskLabel.get(r)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Комментарий" hint="До 500 знаков, попадёт в журнал аудита.">
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} />}
          </Field>
          {weakening && <Banner kind="warning">Это действие ослабляет защиту. Оно запишется в журнал аудита как ослабление.</Banner>}
          <SecretField mfa={mfa} value={secret} onChange={setSecret} />
          {conflict && <Banner kind="warning">{conflict}</Banner>}
          {!conflict && <ErrorBanner error={approve.error ?? setRiskM.error ?? revoke.error} />}
          <div className="flex flex-wrap justify-end gap-2">
            <Button onClick={onClose}>Закрыть</Button>
            {canRevoke && (
              <Button variant="danger" disabled={busy} onClick={() => revoke.mutate()}>
                Снять одобрение
              </Button>
            )}
            {canSetRisk && (
              <Button disabled={busy || (lowering && secretMissing)} onClick={() => setRiskM.mutate()}>
                {lowering ? "Понизить риск (ослабляет защиту)" : "Повысить риск"}
              </Button>
            )}
            {cur.status !== "approved" && (
              <Button variant="primary" disabled={busy || secretMissing} onClick={() => approve.mutate()}>
                {weakening ? "Одобрить (ослабляет защиту)" : "Одобрить инструмент"}
              </Button>
            )}
          </div>
        </>
      )}
      {!canApprove && (
        <div className="flex justify-end">
          <Button onClick={onClose}>Закрыть</Button>
        </div>
      )}
    </FormDialog>
  );
}
