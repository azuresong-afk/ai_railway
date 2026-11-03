import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { Banner, Panel, Table, Td, Th } from "../ui/Layout";
import { ServiceDBVersions } from "../ui/ServiceDBVersions";
import { langTitle } from "./format";
import { redteamApi } from "./api";

const key = ["redteam", "scenarios"] as const;

// Вкладка «Сценарии»: подписанная база сценариев атак (ADR-0031, ADR-0028). Загрузка и возврат предыдущей версии — право redteam.scenarios.load;
// возврат сервер принимает только из сессии консоли. Текстов атак API не отдаёт: показываются название, язык, строка матрицы, число шагов, источник.
export function ScenariosTab({ canLoad }: { canLoad: boolean }) {
  const qc = useQueryClient();
  const file = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState(false);
  const [lang, setLang] = useState("");
  const [threat, setThreat] = useState("");
  const q = useQuery({ queryKey: key, queryFn: ({ signal }) => redteamApi.scenarios(signal) });
  const load = useMutation({
    mutationFn: () => redteamApi.uploadScenarios(file.current!.files![0]!),
    onSuccess: async () => {
      if (file.current) file.current.value = "";
      setPicked(false);
      rollback.reset();
      await qc.invalidateQueries({ queryKey: key });
    },
  });
  const rollback = useMutation({
    mutationFn: () => redteamApi.rollbackScenarios(),
    onSuccess: async () => {
      load.reset();
      await qc.invalidateQueries({ queryKey: key });
    },
  });
  const d = q.data;
  const stored = d !== undefined && (d.state.current !== undefined || d.state.previous !== undefined);
  const threats = [...new Set((d?.scenarios ?? []).map((s) => s.threat))].sort();
  const shown = (d?.scenarios ?? []).filter((s) => (lang === "" || s.lang === lang) && (threat === "" || s.threat === threat));

  return (
    <div className="flex flex-col gap-4">
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка базы сценариев…</p>}
      {d && (
        <Panel role="region" aria-label="База сценариев атак" className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">База сценариев атак</h2>
          <p className="text-sm text-muted">
            Сценарии — это примеры атак на языковую модель (инъекции, утечка системного промпта, обход ограничений) на русском и английском. База подписана
            производителем: сервер принимает только подписанный файл, новее загруженного.
          </p>
          {!stored ? (
            <Banner kind="warning">База сценариев не загружена: тестирование запускать нечем. Загрузите подписанный файл базы из выпуска (.aisecdb).</Banner>
          ) : (
            <>
              {d.state.active === "previous" && (
                <Banner kind="warning">
                  Текущая версия базы не прошла проверку подписи и не используется: действует предыдущая. Загрузите подписанную базу из выпуска заново.
                </Banner>
              )}
              {d.state.active === "none" && <Banner kind="error">Ни одна из сохранённых версий не прошла проверку подписи: сценарии не действуют.</Banner>}
              <ServiceDBVersions
                title="базу сценариев"
                recordsTitle="Сценариев"
                current={d.state.current}
                previous={d.state.previous}
                active={d.state.active}
                canManage={canLoad}
                pending={rollback.isPending}
                onRollback={() => rollback.mutate()}
              />
            </>
          )}
          {canLoad ? (
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Файл базы сценариев" hint="Подписанный файл из выпуска, до 4 МиБ. Версия должна быть новее загруженной.">
                {({ id, describedBy }) => (
                  <input id={id} aria-describedby={describedBy} ref={file} type="file" accept=".aisecdb" className="text-sm" onChange={(e) => setPicked(Boolean(e.target.files?.length))} />
                )}
              </Field>
              <Button variant="primary" disabled={!picked || load.isPending} onClick={() => load.mutate()}>
                Загрузить базу сценариев
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted">Загружать базу и возвращать предыдущую версию может администратор безопасности.</p>
          )}
          <ErrorBanner error={load.error ?? rollback.error} />
          {load.data?.state.current && (
            <Banner kind="info">
              База сценариев версии {load.data.state.current.version} загружена{load.data.state.current.uploaded_at ? ` ${formatAbsolute(load.data.state.current.uploaded_at)}` : ""}.
            </Banner>
          )}
          {rollback.data?.state.current && <Banner kind="info">Возвращена предыдущая версия базы сценариев: {rollback.data.state.current.version}.</Banner>}
        </Panel>
      )}

      {d && d.scenarios.length > 0 && (
        <Panel role="region" aria-label="Сценарии действующей версии" className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">Сценарии действующей версии</h2>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Язык">
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
            <Field label="Строка матрицы">
              {({ id }) => (
                <Select id={id} value={threat} onChange={(e) => setThreat(e.target.value)}>
                  <option value="">Все</option>
                  {threats.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <p className="pb-2 text-sm text-muted">
              Показано {formatNumber(shown.length)} из {formatNumber(d.scenarios.length)}. Тексты атак сервер не показывает.
            </p>
          </div>
          <div className="overflow-auto">
            <Table aria-label="Сценарии">
              <thead>
                <tr>
                  <Th>ID</Th>
                  <Th>Название</Th>
                  <Th>Язык</Th>
                  <Th>Строка</Th>
                  <Th>Категория</Th>
                  <Th className="text-right">Шагов</Th>
                  <Th>Условие успеха</Th>
                  <Th>Источник</Th>
                </tr>
              </thead>
              <tbody>
                {shown.map((s) => (
                  <tr key={s.id}>
                    <Td className="font-mono text-sm">{s.id}</Td>
                    <Td className="break-words">{s.title}</Td>
                    <Td>{langTitle.get(s.lang) ?? s.lang}</Td>
                    <Td className="font-mono text-sm">{s.threat}</Td>
                    <Td className="break-words">{s.category}</Td>
                    <Td className="text-right">{s.steps}</Td>
                    <Td>{s.judge ? "оценщик judge.llm" : "правила"}</Td>
                    <Td className="text-sm break-words">
                      {s.source}
                      <div className="text-xs text-muted">{s.license}</div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </Panel>
      )}
    </div>
  );
}
