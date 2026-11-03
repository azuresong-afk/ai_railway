import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Field, Select } from "../ui/Field";
import { Banner, Table, Td, Th } from "../ui/Layout";
import { redteamApi } from "./api";
import { countOf, verdictOrder, verdictTitle } from "./format";
import { VerdictBadge } from "./Verdict";

// Вкладка «Покрытие матрицы»: какие строки матрицы обнаружения (ТЗ 5.16) проверены сценариями выбранного запуска и с каким итогом.
// Строка без результатов — «не проверялась»: сценариев по ней в базе нет или запуск их не включал.
export function CoverageTab() {
  const [picked, setPicked] = useState("");
  const runs = useQuery({ queryKey: ["redteam", "runs"], queryFn: ({ signal }) => redteamApi.runs(signal) });
  const scen = useQuery({ queryKey: ["redteam", "scenarios"], queryFn: ({ signal }) => redteamApi.scenarios(signal) });
  const done = (runs.data?.items ?? []).filter((r) => r.status === "done");
  const runId = picked || done[0]?.id || "";
  const card = useQuery({
    queryKey: ["redteam", "run", runId],
    queryFn: ({ signal }) => redteamApi.run(runId, signal),
    enabled: runId !== "",
  });

  const inBase = new Map<string, number>();
  for (const s of scen.data?.scenarios ?? []) inBase.set(s.threat, (inBase.get(s.threat) ?? 0) + 1);
  const byThreat = new Map<string, Record<string, number>>();
  for (const r of card.data?.results ?? []) {
    const c = byThreat.get(r.threat) ?? {};
    c[r.verdict] = (c[r.verdict] ?? 0) + 1;
    byThreat.set(r.threat, c);
  }
  const rows = [...new Set([...inBase.keys(), ...byThreat.keys()])].sort();
  const checked = rows.filter((r) => byThreat.has(r)).length;
  const succeeded = rows.filter((r) => (byThreat.get(r)?.succeeded ?? 0) > 0).length;

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-sm text-muted">
        Строки матрицы обнаружения — это угрозы, от которых защищает продукт. Здесь видно, по каким строкам есть проверка атаками и чем она закончилась.
      </p>
      <ErrorBanner error={runs.error ?? scen.error ?? card.error} />
      {(runs.isPending || scen.isPending) && <p className="text-sm text-muted">Загрузка…</p>}
      {runs.data && done.length === 0 && <Banner kind="info">Завершённых запусков ещё нет: покрытие появится после первого запуска.</Banner>}
      {done.length > 0 && (
        <Field label="Запуск">
          {({ id }) => (
            <Select id={id} value={runId} onChange={(e) => setPicked(e.target.value)} className="max-w-md">
              {done.map((r) => (
                <option key={r.id} value={r.id}>
                  {formatAbsolute(r.started_at)}, {r.target_name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
      {card.data && (
        <p className="text-sm">
          Проверено строк: <span className="font-medium">{formatNumber(checked)}</span> из {formatNumber(rows.length)}. Есть удавшиеся атаки по строкам:{" "}
          <span className="font-medium">{formatNumber(succeeded)}</span>.
        </p>
      )}
      {rows.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Покрытие строк матрицы обнаружения">
            <thead>
              <tr>
                <Th>Строка</Th>
                <Th className="text-right">Сценариев в базе</Th>
                <Th>Состояние</Th>
                {verdictOrder.map((v) => (
                  <Th key={v} className="text-right">
                    {verdictTitle.get(v)}
                  </Th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const c = byThreat.get(r);
                return (
                  <tr key={r}>
                    <Td className="font-mono text-sm">{r}</Td>
                    <Td className="text-right">{formatNumber(inBase.get(r) ?? 0)}</Td>
                    <Td>{c ? <Status counts={c} /> : <span className="text-muted">не проверялась</span>}</Td>
                    {verdictOrder.map((v) => (
                      <Td key={v} className="text-right">
                        {c && countOf(c, v) > 0 ? formatNumber(countOf(c, v)) : <span className="text-muted">—</span>}
                      </Td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </div>
      )}
    </div>
  );
}

// Состояние строки по худшему итогу: удалась → заблокирована или отражена → не проверено/ошибка.
function Status({ counts }: { counts: Record<string, number> }) {
  if (counts.succeeded) return <VerdictBadge verdict="succeeded" />;
  if (counts.error) return <VerdictBadge verdict="error" />;
  if (counts.unchecked) return <VerdictBadge verdict="unchecked" />;
  if (counts.blocked) return <VerdictBadge verdict="blocked" />;
  if (counts.defended) return <VerdictBadge verdict="defended" />;
  return <VerdictBadge verdict="skipped" />;
}
