import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Check, Field, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { type LogFormat, type ShadowCatalog, type ShadowImport, shadowApi } from "./api";
import { formatTitle } from "./format";

const formats: LogFormat[] = ["squid", "cef", "csv"];

// Итог импорта: счётчики строк и номера первых ошибочных строк (без содержимого).
function ImportResult({ r }: { r: ShadowImport }) {
  return (
    <div className="flex flex-col gap-1" aria-live="polite">
      <Banner kind={r.errors > 0 ? "warning" : "info"}>
        Журнал импортирован: строк {formatNumber(r.lines)}, обращений к сервисам каталога {formatNumber(r.matched)}, к прочим узлам{" "}
        {formatNumber(r.unmatched)}, ошибок разбора {formatNumber(r.errors)}
        {r.excluded ? `, исключённых ${formatNumber(r.excluded)}` : ""}
        {r.outdated ? `, старше срока хранения ${formatNumber(r.outdated)}` : ""}. Сервисов найдено: {formatNumber(r.services)}.
        {r.users_pseudonymized ? "" : " Ключа псевдонимов нет: пользователи не учтены."}
      </Banner>
      {r.error_lines.length > 0 && (
        <p className="text-sm">
          {r.errors > r.error_lines.length ? `Первые ${r.error_lines.length} ошибочных строк` : "Ошибочные строки"}: {r.error_lines.join(", ")}. Проверьте
          формат журнала: строки с ошибками не учтены.
        </p>
      )}
    </div>
  );
}

function CatalogPanel({ catalog, canManage }: { catalog: ShadowCatalog | undefined; canManage: boolean }) {
  const qc = useQueryClient();
  const file = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState(false);
  const load = useMutation({
    mutationFn: () => shadowApi.uploadCatalog(file.current!.files![0]!),
    onSuccess: async () => {
      if (file.current) file.current.value = "";
      setPicked(false);
      await qc.invalidateQueries({ queryKey: ["shadow-ai"] });
    },
  });
  return (
    <Panel role="region" aria-label="Каталог ИИ-сервисов" className="flex flex-col gap-2">
      <h2 className="text-lg font-semibold">Каталог ИИ-сервисов</h2>
      {!catalog ? (
        <p className="text-sm text-muted">Загрузка каталога…</p>
      ) : !catalog.loaded ? (
        <Banner kind="warning">Каталог не загружен: обращения не с чем сопоставить. Загрузите подписанный файл каталога из выпуска (.aisecdb).</Banner>
      ) : (
        <>
          {!catalog.valid && <Banner kind="error">Подпись сохранённого каталога не прошла проверку. Импорт невозможен: загрузите подписанный каталог заново.</Banner>}
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
            <dt className="text-muted">Версия</dt>
            <dd>
              {catalog.version} от {catalog.date}
            </dd>
            <dt className="text-muted">Сервисов</dt>
            <dd>{formatNumber(catalog.services.length)}</dd>
            <dt className="text-muted">Загружен</dt>
            <dd>{catalog.uploaded_at ? formatAbsolute(catalog.uploaded_at) : "—"}</dd>
            <dt className="text-muted">Рабочий ключ заверен до</dt>
            <dd>{catalog.subkey_not_after ? formatAbsolute(catalog.subkey_not_after) : "—"}</dd>
          </dl>
        </>
      )}
      {canManage && (
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Файл каталога" hint="Подписанный файл из выпуска, до 4 МиБ. Версия должна быть новее загруженной.">
            {({ id, describedBy }) => (
              <input id={id} aria-describedby={describedBy} ref={file} type="file" accept=".aisecdb" className="text-sm" onChange={(e) => setPicked(Boolean(e.target.files?.length))} />
            )}
          </Field>
          <Button disabled={!picked || load.isPending} onClick={() => load.mutate()}>
            Загрузить каталог
          </Button>
        </div>
      )}
      <ErrorBanner error={load.error} />
      {load.data && <Banner kind="info">Каталог версии {load.data.version} загружен.</Banner>}
    </Panel>
  );
}

// Вкладка «Импорт и каталог»: журнал прокси файлом, история импорта, каталог.
export function ImportTab({ canManage, catalog }: { canManage: boolean; catalog: ShadowCatalog | undefined }) {
  const qc = useQueryClient();
  const file = useRef<HTMLInputElement>(null);
  const [format, setFormat] = useState<LogFormat>("squid");
  const [gzip, setGzip] = useState(false);
  const [picked, setPicked] = useState(false);
  const imports = useQuery({ queryKey: ["shadow-ai", "imports"], queryFn: ({ signal }) => shadowApi.imports(signal) });
  const run = useMutation({
    mutationFn: () => shadowApi.importLog(file.current!.files![0]!, format, gzip),
    onSuccess: async () => {
      if (file.current) file.current.value = "";
      setPicked(false);
      await qc.invalidateQueries({ queryKey: ["shadow-ai"] });
    },
  });
  const ready = catalog?.loaded === true && catalog.valid;
  const items = imports.data?.items ?? [];
  return (
    <div className="flex flex-col gap-4">
      <Panel role="region" aria-label="Импорт журнала прокси" className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Импорт журнала прокси</h2>
        <p className="text-sm text-muted">
          Файл разбирается на сервере потоком, до 256 МиБ (сжатый gzip — до 1 ГиБ после распаковки). В базе остаются только сводки по сервису,
          псевдониму пользователя и часу; строки журнала и адреса страниц не хранятся.
        </p>
        {canManage ? (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Формат журнала">
                {({ id }) => (
                  <Select id={id} value={format} onChange={(e) => setFormat(e.target.value as LogFormat)}>
                    {formats.map((f) => (
                      <option key={f} value={f}>
                        {formatTitle.get(f)}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label="Файл журнала">
                {({ id }) => (
                  <input
                    id={id}
                    ref={file}
                    type="file"
                    className="text-sm"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      setPicked(Boolean(f));
                      if (f) setGzip(f.name.toLowerCase().endsWith(".gz"));
                    }}
                  />
                )}
              </Field>
              <Check checked={gzip} onCheckedChange={setGzip} label="Файл сжат gzip" />
              <Button variant="primary" disabled={!picked || !ready || run.isPending} onClick={() => run.mutate()}>
                {run.isPending ? "Идёт импорт…" : "Импортировать журнал"}
              </Button>
            </div>
            {catalog && !ready && <p className="text-sm text-muted">Импорт станет доступен после загрузки подписанного каталога ниже.</p>}
            <ErrorBanner error={run.error} />
            {run.data && <ImportResult r={run.data} />}
          </>
        ) : (
          <p className="text-sm text-muted">Импортировать журналы и загружать каталог может администратор безопасности.</p>
        )}
      </Panel>

      <Panel role="region" aria-label="История импорта" className="flex flex-col gap-2">
        <h2 className="text-lg font-semibold">История импорта</h2>
        <ErrorBanner error={imports.error} />
        {imports.data && items.length === 0 && <EmptyState title="Журналов ещё не импортировали" action={<p className="text-sm text-muted">Последние 100 импортов появятся здесь.</p>} />}
        {items.length > 0 && (
          <div className="overflow-auto">
            <Table aria-label="Импорты">
              <thead>
                <tr>
                  <Th>Когда</Th>
                  <Th>Формат</Th>
                  <Th className="text-right">Строк</Th>
                  <Th className="text-right">Сервисы каталога</Th>
                  <Th className="text-right">Ошибок</Th>
                  <Th className="text-right">Исключено</Th>
                  <Th>Период журнала</Th>
                  <Th>Кто</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id}>
                    <Td>{formatAbsolute(i.created_at)}</Td>
                    <Td>{formatTitle.get(i.format) ?? i.format}</Td>
                    <Td className="text-right">{formatNumber(i.lines)}</Td>
                    <Td className="text-right">{formatNumber(i.matched)}</Td>
                    <Td className="text-right" title={i.error_lines.length ? `Строки: ${i.error_lines.join(", ")}` : undefined}>
                      {formatNumber(i.errors)}
                    </Td>
                    <Td className="text-right">{formatNumber(i.excluded ?? 0)}</Td>
                    <Td>{i.from && i.to ? `${formatAbsolute(i.from)} — ${formatAbsolute(i.to)}` : "—"}</Td>
                    <Td className="text-sm">{i.created_by}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>

      <CatalogPanel catalog={catalog} canManage={canManage} />
    </div>
  );
}
