import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Banner, Panel, Table, Td, Th } from "../ui/Layout";
import { ServiceDBVersions } from "../ui/ServiceDBVersions";
import { inventoryApi } from "./api";

// Вкладка «Шаблоны чата» (задача 5.23): служебная база эталонов шаблонов чата по семействам моделей (DM-28, ADR-0028).
// Загрузка и возврат предыдущей версии — право models.templates.load; возврат сервер принимает только из сессии консоли.
export function TemplatesTab({ canLoad }: { canLoad: boolean }) {
  const qc = useQueryClient();
  const file = useRef<HTMLInputElement>(null);
  const [picked, setPicked] = useState(false);
  const q = useQuery({ queryKey: ["inventory", "chat-templates"], queryFn: ({ signal }) => inventoryApi.chatTemplates(signal) });
  const load = useMutation({
    mutationFn: () => inventoryApi.uploadChatTemplates(file.current!.files![0]!),
    onSuccess: async () => {
      if (file.current) file.current.value = "";
      setPicked(false);
      rollback.reset();
      await qc.invalidateQueries({ queryKey: ["inventory", "chat-templates"] });
    },
  });
  const rollback = useMutation({
    mutationFn: () => inventoryApi.rollbackChatTemplates(),
    onSuccess: async () => {
      load.reset();
      await qc.invalidateQueries({ queryKey: ["inventory", "chat-templates"] });
    },
  });
  const t = q.data;
  const stored = t !== undefined && (t.current !== undefined || t.previous !== undefined);

  return (
    <div className="flex flex-col gap-4">
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка базы эталонов…</p>}
      {t && (
        <Panel role="region" aria-label="База эталонов шаблонов чата" className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">База эталонов шаблонов чата</h2>
          <p className="text-sm text-muted">
            Эталоны нужны, чтобы заметить подмену встроенного шаблона чата в файлах модели. Без базы шаблоны проверяются только детекторами инъекций, а итог
            сверки — «эталона нет».
          </p>
          {!stored ? (
            <Banner kind="warning">База эталонов не загружена. Загрузите подписанный файл базы из выпуска (.aisecdb).</Banner>
          ) : (
            <>
              {t.active === "previous" && (
                <Banner kind="warning">
                  Текущая версия базы не прошла проверку подписи и не используется: действует предыдущая. Загрузите подписанную базу из выпуска заново.
                </Banner>
              )}
              {t.active === "none" && <Banner kind="error">Ни одна из сохранённых версий не прошла проверку подписи: эталоны не действуют. Загрузите подписанную базу заново.</Banner>}
              <ServiceDBVersions
                title="базу эталонов шаблонов чата"
                recordsTitle="Записей"
                current={t.current}
                previous={t.previous}
                active={t.active}
                canManage={canLoad}
                pending={rollback.isPending}
                onRollback={() => rollback.mutate()}
              />
            </>
          )}
          {canLoad ? (
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Файл базы эталонов" hint="Подписанный файл из выпуска, до 4 МиБ. Версия должна быть новее загруженной.">
                {({ id, describedBy }) => (
                  <input id={id} aria-describedby={describedBy} ref={file} type="file" accept=".aisecdb" className="text-sm" onChange={(e) => setPicked(Boolean(e.target.files?.length))} />
                )}
              </Field>
              <Button variant="primary" disabled={!picked || load.isPending} onClick={() => load.mutate()}>
                Загрузить базу эталонов
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted">Загружать базу и возвращать предыдущую версию может администратор безопасности.</p>
          )}
          <ErrorBanner error={load.error ?? rollback.error} />
          {load.data?.current && (
            <Banner kind="info">
              База эталонов версии {load.data.current.version} загружена{load.data.current.uploaded_at ? ` ${formatAbsolute(load.data.current.uploaded_at)}` : ""}.
            </Banner>
          )}
          {rollback.data?.current && <Banner kind="info">Возвращена предыдущая версия базы эталонов: {rollback.data.current.version}.</Banner>}
        </Panel>
      )}

      {t && t.families.length > 0 && (
        <Panel role="region" aria-label="Семейства моделей в базе эталонов" className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">Семейства моделей</h2>
          <p className="text-sm text-muted">Действующая версия базы: {formatNumber(t.families.length)}. Тексты и хеши шаблонов сервер не показывает.</p>
          <div className="overflow-auto">
            <Table aria-label="Семейства эталонов">
              <thead>
                <tr>
                  <Th>Семейство</Th>
                  <Th>Подстроки имени модели</Th>
                  <Th>Варианты шаблона</Th>
                </tr>
              </thead>
              <tbody>
                {t.families.map((f) => (
                  <tr key={f.id}>
                    <Td>
                      {f.title}
                      <div className="text-xs text-muted">{f.id}</div>
                    </Td>
                    <Td className="break-words">{f.match.join(", ")}</Td>
                    <Td className="break-words">{f.variants.join(", ")}</Td>
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
