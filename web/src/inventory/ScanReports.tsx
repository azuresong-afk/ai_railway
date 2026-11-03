import { useQuery } from "@tanstack/react-query";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { formatBytes } from "../system/format";
import { Banner, Panel, RawText, Table, Td, Th } from "../ui/Layout";
import { inventoryApi, type ScanReport } from "./api";
import { blockReasonTitle, findingTitle, hashesTitle, mismatchTitle, reportKindTitle, roleTitle, sourceTitle, templatesTitle } from "./format";
import { Verdict } from "./Marks";

const hash = "font-mono text-xs break-all";

function Findings({ items }: { items: ScanReport["report_findings"] }) {
  return (
    <ul className="list-disc pl-5 text-base">
      {items.map((f, i) => (
        <li key={i}>
          {findingTitle.get(f.code) ?? f.code} ({f.severity === "block" ? "запрет" : "предупреждение"})
          {f.detail ? <span className="text-muted"> — {f.detail}</span> : null}
        </li>
      ))}
    </ul>
  );
}

function ReportBody({ r }: { r: ScanReport }) {
  return (
    <div className="mt-3 flex flex-col gap-3">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
        <dt className="text-muted">Узел</dt>
        <dd className="break-words">{r.host}</dd>
        <dt className="text-muted">Версия сканера</dt>
        <dd>{r.scanner_version}</dd>
        <dt className="text-muted">Прислал</dt>
        <dd className="break-words">{r.received_by}</dd>
        <dt className="text-muted">Файлов в отчёте</dt>
        <dd>{formatNumber(r.files)}</dd>
        <dt className="text-muted">Находок</dt>
        <dd>{formatNumber(r.findings)}</dd>
        <dt className="text-muted">Хеши с реестром</dt>
        <dd>{hashesTitle.get(r.hashes)}</dd>
        <dt className="text-muted">Шаблоны чата</dt>
        <dd>{templatesTitle.get(r.templates)}</dd>
      </dl>
      {r.truncated && <Banner kind="warning">В каталоге больше файлов, чем проверяет сканер: часть файлов не проверена.</Banner>}
      {r.blocked && (
        <Banner kind="error">
          Этот отчёт перевёл модель в состояние «Запрещена»
          {r.block_reasons.length ? `: ${r.block_reasons.map((x) => blockReasonTitle.get(x) ?? x).join(", ")}` : ""}.
        </Banner>
      )}

      {r.report_findings.length > 0 && (
        <section aria-label="Находки по каталогу" className="flex flex-col gap-1">
          <h4 className="text-base font-medium">Находки по каталогу</h4>
          <Findings items={r.report_findings} />
        </section>
      )}

      {r.finding_files.length > 0 && (
        <section aria-label="Файлы с находками" className="flex flex-col gap-1">
          <h4 className="text-base font-medium">Файлы с находками</h4>
          <div className="overflow-auto">
            <Table aria-label="Файлы с находками сканера">
              <thead>
                <tr>
                  <Th>Файл</Th>
                  <Th>Формат</Th>
                  <Th className="text-right">Размер</Th>
                  <Th>Находки</Th>
                </tr>
              </thead>
              <tbody>
                {r.finding_files.map((f) => (
                  <tr key={f.path}>
                    <Td className="break-all font-mono text-sm">{f.path}</Td>
                    <Td>{f.format || "—"}</Td>
                    <Td className="text-right">{formatBytes(f.size)}</Td>
                    <Td>
                      <Findings items={f.findings} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </section>
      )}

      {r.mismatches.length > 0 && (
        <section aria-label="Расхождения хешей" className="flex flex-col gap-1">
          <h4 className="text-base font-medium">Расхождения хешей с реестром</h4>
          <div className="overflow-auto">
            <Table aria-label="Расхождения хешей">
              <thead>
                <tr>
                  <Th>Файл</Th>
                  <Th>Роль</Th>
                  <Th>Что не так</Th>
                  <Th>Хеш в реестре</Th>
                  <Th>Хеш на узле</Th>
                </tr>
              </thead>
              <tbody>
                {r.mismatches.map((m) => (
                  <tr key={m.path}>
                    <Td className="break-all font-mono text-sm">{m.path}</Td>
                    <Td>{m.role ? roleTitle.get(m.role) : "—"}</Td>
                    <Td>{mismatchTitle.get(m.problem) ?? m.problem}</Td>
                    <Td className={hash}>{m.expected_sha256 || "—"}</Td>
                    <Td className={hash}>{m.actual_sha256 || "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
          {r.mismatch_total > r.mismatches.length && (
            <p className="text-sm text-muted">
              Показаны первые {formatNumber(r.mismatches.length)} из {formatNumber(r.mismatch_total)} расхождений.
            </p>
          )}
        </section>
      )}

      {r.chat_templates.length > 0 && (
        <section aria-label="Шаблоны чата в отчёте" className="flex flex-col gap-2">
          <h4 className="text-base font-medium">Шаблоны чата</h4>
          {r.chat_templates.map((t, i) => (
            <div key={i} className="flex flex-col gap-1 rounded-panel border border-line p-3">
              <div className="text-base">
                <span className="break-all font-mono text-sm">{t.file}</span> — {sourceTitle.get(t.source) ?? t.source}
                {t.name ? `, «${t.name}»` : ""}
              </div>
              <div className="text-base">
                {templatesTitle.get(t.result as ScanReport["templates"])}
                {t.family ? `; семейство ${t.family}${t.variant ? `, вариант ${t.variant}` : ""}` : ""}
                {t.base_version > 0 ? `; база эталонов версии ${t.base_version}` : "; базы эталонов не было"}
              </div>
              <div className={`${hash} text-muted`}>SHA-256 нормализованного шаблона: {t.sha256}</div>
              {t.findings && t.findings.length > 0 && (
                <ul className="list-disc pl-5 text-base">
                  {t.findings.map((f, j) => (
                    <li key={j}>
                      {f.detector}: {f.category}
                      {f.rule ? `, правило ${f.rule}` : ""}
                    </li>
                  ))}
                </ul>
              )}
              {t.text && (
                <details>
                  <summary className="cursor-pointer text-sm underline">Показать текст шаблона</summary>
                  <div className="mt-2">
                    <RawText>{t.text}</RawText>
                  </div>
                </details>
              )}
            </div>
          ))}
        </section>
      )}
    </div>
  );
}

// Отчёты сканера модели (задачи 5.21–5.22): последние до 20 отчётов aisec-cli models scan и models verify, новые первыми.
export function ScanReports({ modelId }: { modelId: string }) {
  const q = useQuery({ queryKey: ["inventory", "scan-reports", modelId], queryFn: ({ signal }) => inventoryApi.scanReports(modelId, signal) });
  const items = q.data?.items ?? [];
  return (
    <Panel role="region" aria-label="Отчёты сканера" className="flex flex-col gap-2">
      <h3 className="text-lg font-semibold">Отчёты сканера</h3>
      <p className="text-sm text-muted">
        Отчёты присылает aisec-cli на узле, где лежат файлы модели: «models scan» проверяет форматы и шаблоны чата, «models verify» сверяет хеши с реестром.
        Хранятся последние 20.
      </p>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка отчётов…</p>}
      {q.data && items.length === 0 && <p className="text-sm text-muted">Отчётов ещё нет. Запустите проверку на узле с файлами модели.</p>}
      {items.map((r) => (
        <details key={r.id} className="rounded-panel border border-line p-3">
          <summary className="flex cursor-pointer flex-wrap items-center gap-3 text-base">
            <span className="font-medium">{formatAbsolute(r.received_at)}</span>
            <span>{reportKindTitle.get(r.kind)}</span>
            <Verdict verdict={r.verdict} />
            <span className="text-muted">{r.host}</span>
          </summary>
          <ReportBody r={r} />
        </details>
      ))}
    </Panel>
  );
}
