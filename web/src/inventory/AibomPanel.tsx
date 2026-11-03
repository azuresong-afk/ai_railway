import { useMutation } from "@tanstack/react-query";
import { ErrorBanner } from "../admin/common";
import { Button } from "../ui/Button";
import { Banner, Panel } from "../ui/Layout";
import { inventoryApi } from "./api";

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Вкладка «AI-BOM» (задача 5.23): выгрузка реестра ИИ в CycloneDX 1.6 (ML-BOM, ADR-0029, п. 3). Право inventory.export.
// Файл собирает сервер и сам пишет выгрузку в журнал аудита до выдачи; консоль только сохраняет полученное.
export function AibomPanel() {
  const exp = useMutation({
    mutationFn: async () => {
      const blob = await inventoryApi.aibom();
      const stamp = new Date().toISOString().slice(0, 10);
      save(blob, `aisec-aibom-${stamp}.cdx.json`);
      return blob.size;
    },
  });
  return (
    <Panel role="region" aria-label="Выгрузка AI-BOM" className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Выгрузка AI-BOM</h2>
      <p className="text-base">
        Перечень ИИ-компонентов установки одним файлом в формате CycloneDX 1.6 (ML-BOM): приложения, модели с хешами файлов и провайдеры со связями между
        ними. Файл можно передать аудитору или загрузить в систему учёта.
      </p>
      <ul className="list-disc pl-5 text-sm text-muted">
        <li>Ключи приложений, секреты и учётные данные провайдеров в файл не попадают; у провайдеров только схема, хост и порт адреса.</li>
        <li>Архивные приложения не выгружаются.</li>
        <li>Каждая выгрузка записывается в журнал аудита.</li>
      </ul>
      <div>
        <Button variant="primary" disabled={exp.isPending} onClick={() => exp.mutate()}>
          {exp.isPending ? "Готовим файл…" : "Выгрузить AI-BOM"}
        </Button>
      </div>
      <ErrorBanner error={exp.error} />
      {exp.isSuccess && <Banner kind="info">Файл выгружен. Выгрузка записана в журнал аудита.</Banner>}
    </Panel>
  );
}
