import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { ErrorBanner, FormDialog } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { type ReportFormat, type Result, type Run, redteamApi, saveBlob, type Target } from "./api";
import { conditionTitle, countOf, errorTitle, langTitle, reasonTitle, statusTitle, succeededShare, verdictOrder, verdictTitle } from "./format";
import { VerdictBadge } from "./Verdict";

export const runsKey = ["redteam", "runs"] as const;
const active = (r: Run) => r.status === "queued" || r.status === "running";
const statusText = (r: Run) => `${statusTitle.get(r.status) ?? r.status}${r.reason ? ` (${reasonTitle.get(r.reason) ?? r.reason})` : ""}`;

// Сводка запуска: сколько сценариев с каким итогом. Доля удавшихся считается среди проверенных (удалась, заблокирована, отражена).
function Counts({ run }: { run: Run }) {
  const share = succeededShare(run.counts);
  return (
    <div className="flex flex-col gap-1">
      <ul className="flex flex-wrap gap-x-4 gap-y-1">
        {verdictOrder
          .filter((v) => countOf(run.counts, v) > 0)
          .map((v) => (
            <li key={v} className="flex items-center gap-1.5">
              <VerdictBadge verdict={v} />
              <span className="font-medium">{formatNumber(countOf(run.counts, v))}</span>
            </li>
          ))}
      </ul>
      {share !== undefined && <p className="text-sm text-muted">Доля удавшихся атак среди проверенных сценариев: {share} %.</p>}
    </div>
  );
}

// Вкладка «Запуски»: список, запуск, итоги и отчёт. Промптов атак и ответов цели API не отдаёт — в итогах только вердикты и ссылки на события шлюза.
export function RunsTab({ canRun, canExport, canReadContent }: { canRun: boolean; canExport: boolean; canReadContent: boolean }) {
  const [params, setParams] = useSearchParams();
  const [starting, setStarting] = useState(false);
  const selected = params.get("run");
  const q = useQuery({
    queryKey: runsKey,
    queryFn: ({ signal }) => redteamApi.runs(signal),
    // Пока есть идущие запуски, список обновляется.
    refetchInterval: (query) => (query.state.data?.items.some(active) ? 5000 : false),
  });
  const targets = useQuery({ queryKey: ["redteam", "targets"], queryFn: ({ signal }) => redteamApi.targets(signal) });

  if (selected) {
    return (
      <RunView
        id={selected}
        canRun={canRun}
        canExport={canExport}
        canReadContent={canReadContent}
        onBack={() => {
          const next = new URLSearchParams(params);
          next.delete("run");
          setParams(next);
        }}
      />
    );
  }
  const items = q.data?.items ?? [];
  const open = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("run", id);
    setParams(next);
  };
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          Запуск отправляет сценарии атак на выбранную цель и проверяет, удались ли они. Атаки идут только на адреса из списка целей. Так проверяется защита
          ваших приложений, а не чужих.
        </p>
        {canRun && (
          <Button variant="primary" disabled={(targets.data?.items.length ?? 0) === 0} onClick={() => setStarting(true)}>
            Запустить тестирование
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка запусков…</p>}
      {q.data && items.length === 0 && (
        <EmptyState
          title="Запусков ещё не было."
          action={<p className="text-sm text-muted">{canRun ? "Добавьте цель на вкладке «Цели» и запустите тестирование." : "Запуск доступен администратору безопасности."}</p>}
        />
      )}
      {items.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Запуски тестирования">
            <thead>
              <tr>
                <Th>Начат</Th>
                <Th>Цель</Th>
                <Th>Состояние</Th>
                <Th className="text-right">Сценариев</Th>
                <Th>Итоги</Th>
                <Th>Запустил</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <Td>
                    <button type="button" className="underline" onClick={() => open(r.id)}>
                      {formatAbsolute(r.started_at)}
                    </button>
                  </Td>
                  <Td className="break-words">{r.target_name}</Td>
                  <Td>{statusText(r)}</Td>
                  <Td className="text-right">{formatNumber(r.scenarios)}</Td>
                  <Td>
                    <Counts run={r} />
                  </Td>
                  <Td className="break-words">{r.started_by}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {starting && targets.data && (
        <StartDialog
          targets={targets.data.items}
          onClose={() => setStarting(false)}
          onStarted={(id) => {
            setStarting(false);
            open(id);
          }}
        />
      )}
    </div>
  );
}

function StartDialog({ targets, onClose, onStarted }: { targets: Target[]; onClose: () => void; onStarted: (id: string) => void }) {
  const qc = useQueryClient();
  const scen = useQuery({ queryKey: ["redteam", "scenarios"], queryFn: ({ signal }) => redteamApi.scenarios(signal) });
  const [target, setTarget] = useState(targets[0]?.id ?? "");
  const [lang, setLang] = useState("");
  const [threats, setThreats] = useState<string[]>([]);
  const [secret, setSecret] = useState("");
  const t = targets.find((x) => x.id === target);
  const rows = [...new Set((scen.data?.scenarios ?? []).map((s) => s.threat))].sort();
  const start = useMutation({
    mutationFn: () =>
      redteamApi.start({
        target_id: target,
        ...(lang ? { lang: lang as "ru" | "en" } : {}),
        ...(threats.length ? { threats } : {}),
        ...(t?.auth_header && secret ? { auth_value: secret } : {}),
      }),
    onSuccess: async (r) => {
      // Секрет живёт только в состоянии диалога и стирается при закрытии.
      setSecret("");
      await qc.invalidateQueries({ queryKey: runsKey });
      onStarted(r.id);
    },
  });
  const noSecret = Boolean(t?.auth_header) && secret === "";
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title="Запуск тестирования устойчивости" description="Сценарии пойдут на выбранную цель. Запуск можно отменить.">
      <Field label="Цель">
        {({ id }) => (
          <Select id={id} value={target} onChange={(e) => setTarget(e.target.value)}>
            {targets.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {t?.auth_header && (
        <Field label={`Значение заголовка ${t.auth_header}`} hint="Секрет не сохраняется: он хранится в памяти сервера до конца запуска.">
          {({ id, describedBy }) => (
            <Input id={id} aria-describedby={describedBy} type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
          )}
        </Field>
      )}
      <Field label="Язык сценариев">
        {({ id }) => (
          <Select id={id} value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">Все</option>
            {[...langTitle].map(([v, title]) => (
              <option key={v} value={v}>
                {title}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {rows.length > 0 && (
        <fieldset className="flex flex-col gap-1">
          <legend className="text-sm font-medium">Строки матрицы обнаружения</legend>
          <p className="text-xs text-muted">Без отметок — все строки, по которым есть сценарии.</p>
          <div className="grid grid-cols-3 gap-1">
            {rows.map((r) => (
              <Check key={r} label={r} checked={threats.includes(r)} onCheckedChange={(v) => setThreats(v ? [...threats, r] : threats.filter((x) => x !== r))} />
            ))}
          </div>
        </fieldset>
      )}
      {scen.data && scen.data.scenarios.length === 0 && <Banner kind="warning">База сценариев не загружена: запускать нечего. Загрузите её на вкладке «Сценарии».</Banner>}
      <ErrorBanner error={start.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={!target || noSecret || start.isPending || scen.data?.scenarios.length === 0} onClick={() => start.mutate()}>
          Запустить
        </Button>
      </div>
    </FormDialog>
  );
}

function RunView({ id, canRun, canExport, canReadContent, onBack }: { id: string; canRun: boolean; canExport: boolean; canReadContent: boolean; onBack: () => void }) {
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const q = useQuery({
    queryKey: ["redteam", "run", id],
    queryFn: ({ signal }) => redteamApi.run(id, signal),
    refetchInterval: (query) => (query.state.data && active(query.state.data) ? 5000 : false),
  });
  const cancel = useMutation({
    mutationFn: () => redteamApi.cancel(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["redteam"] });
    },
  });
  const run = q.data;
  const results = (run?.results ?? []).filter((r) => filter === "" || r.verdict === filter);
  return (
    <div className="flex flex-col gap-4">
      <div>
        <Button variant="ghost" onClick={onBack}>
          ← К списку запусков
        </Button>
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка запуска…</p>}
      {run && (
        <>
          <Panel role="region" aria-label="Запуск" className="flex flex-col gap-3">
            <h2 className="text-lg font-semibold">Запуск от {formatAbsolute(run.started_at)}</h2>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
              <dt className="text-muted">Цель</dt>
              <dd className="break-words">
                {run.target_name}
                {!run.target_id && <span className="text-muted"> (цель удалена)</span>}
              </dd>
              <dt className="text-muted">Состояние</dt>
              <dd>{statusText(run)}</dd>
              <dt className="text-muted">Запустил</dt>
              <dd className="break-words">{run.started_by}</dd>
              <dt className="text-muted">Версия базы сценариев</dt>
              <dd>{run.db_version}</dd>
              {run.finished_at && (
                <>
                  <dt className="text-muted">Завершён</dt>
                  <dd>{formatAbsolute(run.finished_at)}</dd>
                </>
              )}
            </dl>
            <Counts run={run} />
            {active(run) && <p className="text-sm text-muted">Запуск идёт, страница обновляется сама. Срок запуска: до {formatAbsolute(run.deadline)}.</p>}
            <div className="flex flex-wrap gap-2">
              {canRun && active(run) && (
                <Button variant="danger" disabled={cancel.isPending} onClick={() => cancel.mutate()}>
                  Отменить запуск
                </Button>
              )}
              {canExport && !active(run) && <ReportButtons runId={run.id} canExamples={canReadContent} />}
            </div>
            <ErrorBanner error={cancel.error} />
          </Panel>
          {run.counts.succeeded ? (
            <Banner kind="warning">
              Удалось атак: {run.counts.succeeded}. Это уязвимости: усильте политику приложения или системный промпт и повторите запуск.
            </Banner>
          ) : null}
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Итог">
              {({ id: fid }) => (
                <Select id={fid} value={filter} onChange={(e) => setFilter(e.target.value)}>
                  <option value="">Все</option>
                  {verdictOrder.map((v) => (
                    <option key={v} value={v}>
                      {verdictTitle.get(v)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <p className="pb-2 text-sm text-muted">Показано сценариев: {formatNumber(results.length)}</p>
          </div>
          <div className="overflow-auto">
            <ResultsTable results={results} />
          </div>
        </>
      )}
    </div>
  );
}

// Причина доступа к выдержкам (УПД.7, задача 6.12): как при открытии содержимого события — от 3 до 500 символов.
function ReportReasonDialog({
  onClose,
  onSubmit,
  pending,
  error,
}: {
  onClose: () => void;
  onSubmit: (reason: string) => void;
  pending: boolean;
  error: unknown;
}) {
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);
  const trimmed = reason.trim();
  const len = [...trimmed].length;
  const invalid = len < 3 || len > 500;
  const local = touched && invalid ? "Опишите причину: от 3 до 500 символов." : undefined;
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title="Отчёт с выдержками ответов"
      description="Выгрузка запишется в журнал аудита вместе с вашей причиной."
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (!invalid) onSubmit(trimmed);
        }}
      >
        <Field label="Причина доступа к выдержкам" hint="Например: разбор запуска по заявке 1234." {...(local ? { error: local } : {})}>
          {({ id, describedBy, invalid: inv }) => (
            <Input
              id={id}
              value={reason}
              maxLength={500}
              autoComplete="off"
              aria-invalid={inv}
              {...(describedBy ? { "aria-describedby": describedBy } : {})}
              onChange={(e) => setReason(e.target.value)}
            />
          )}
        </Field>
        <ErrorBanner error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={pending}>
            Выгрузить отчёт
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

// Кнопки отчёта. Отчёт собирает сервер и сам пишет выгрузку в журнал аудита; консоль только сохраняет файл.
// С выдержками консоль сначала спрашивает причину доступа; причина живёт только в открытом окне.
function ReportButtons({ runId, canExamples }: { runId: string; canExamples: boolean }) {
  const [examples, setExamples] = useState(false);
  const [asking, setAsking] = useState<ReportFormat | null>(null);
  const save = useMutation({
    mutationFn: async ({ format, reason }: { format: ReportFormat; reason: string }) => {
      const blob = await redteamApi.report(runId, format, examples, reason);
      saveBlob(blob, `redteam-${runId.slice(0, 8)}.${format}`);
    },
    onSuccess: () => setAsking(null),
  });
  const pick = (format: ReportFormat) => {
    save.reset();
    if (examples) setAsking(format);
    else save.mutate({ format, reason: "" });
  };
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">Отчёт:</span>
        {(["html", "csv", "xlsx"] as const).map((f) => (
          <Button key={f} disabled={save.isPending} onClick={() => pick(f)}>
            {f.toUpperCase()}
          </Button>
        ))}
      </div>
      {canExamples && (
        <div>
          <Check label="Добавить выдержки ответов цели (только у целей с хранением «замаскировано»)" checked={examples} onCheckedChange={setExamples} />
          <p className="text-xs text-muted">
            Выдержка — до 1 КиБ ответа, ПДн и секреты заменены категорией. Консоль спросит причину доступа; выгрузка запишется в журнал аудита вместе с ней.
          </p>
        </div>
      )}
      {asking && (
        <ReportReasonDialog
          onClose={() => {
            setAsking(null);
            save.reset();
          }}
          onSubmit={(reason) => save.mutate({ format: asking, reason })}
          pending={save.isPending}
          error={save.error}
        />
      )}
      {!asking && <ErrorBanner error={save.error} />}
    </div>
  );
}

function ResultsTable({ results }: { results: Result[] }) {
  if (results.length === 0) return <p className="text-sm text-muted">Сценариев с таким итогом нет.</p>;
  return (
    <Table aria-label="Результаты сценариев">
      <thead>
        <tr>
          <Th>Сценарий</Th>
          <Th>Строка</Th>
          <Th>Категория</Th>
          <Th>Итог</Th>
          <Th>Подробности</Th>
          <Th>События шлюза</Th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => (
          <tr key={r.scenario_id}>
            <Td className="font-mono text-sm">
              {r.scenario_id}
              <div className="text-xs text-muted">{langTitle.get(r.lang) ?? r.lang}</div>
            </Td>
            <Td className="font-mono text-sm">{r.threat}</Td>
            <Td className="break-words">{r.category}</Td>
            <Td>
              <VerdictBadge verdict={r.verdict} />
              {r.step > 0 && <div className="text-xs text-muted">на шаге {r.step}</div>}
            </Td>
            <Td className="text-sm break-words">
              {r.matched.length > 0 && <div>Сработало: {r.matched.map((m) => conditionTitle.get(m) ?? m).join(", ")}</div>}
              {r.findings.length > 0 && <div>Находки: {[...new Set(r.findings.map((f) => f.category))].join(", ")}</div>}
              {r.error_code && <div>Ошибка: {errorTitle.get(r.error_code) ?? r.error_code}</div>}
              {r.http_status ? <div>Код ответа: {r.http_status}</div> : null}
            </Td>
            <Td className="font-mono text-xs break-all">
              {r.event_ids.length > 0 ? (
                r.event_ids.slice(0, 3).map((e) => (
                  <div key={e}>
                    <a className="underline" href={`#/events?event=${encodeURIComponent(e)}`}>
                      {e.slice(0, 8)}
                    </a>
                  </div>
                ))
              ) : (
                <span className="text-muted">—</span>
              )}
              {r.event_ids.length > 3 && <div className="text-muted">и ещё {r.event_ids.length - 3}</div>}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
