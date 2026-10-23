import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Panel } from "../ui/Layout";
import { type IncidentCategory, incidentsApi } from "./api";

const maxBody = 8000;

// Инструкции реагирования по категориям (право incident_categories.manage, только администратор безопасности).
// Каждое сохранение — новая версия; устаревшая версия отклоняется сервером (409).
export function CategoriesPanel() {
  const q = useQuery({ queryKey: ["incidents", "categories"], queryFn: ({ signal }) => incidentsApi.categories(signal) });
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">Текст показывается в карточке инцидента своей категории. Прежние версии хранятся.</p>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка категорий…</p>}
      {q.data?.items.map((c) => <CategoryEditor key={`${c.id}-${c.instruction.version}`} c={c} />)}
    </div>
  );
}

function CategoryEditor({ c }: { c: IncidentCategory }) {
  const qc = useQueryClient();
  const [body, setBody] = useState(c.instruction.body);
  const m = useMutation({
    mutationFn: () => incidentsApi.setInstruction(c.id, body, c.instruction.version),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incidents"] }),
  });
  const changed = body !== c.instruction.body;
  return (
    <Panel aria-label={`Категория ${c.title}`} className="flex flex-col gap-2">
      <h2 className="text-md font-semibold">{c.title}</h2>
      <p className="text-xs text-muted">
        {c.instruction.default
          ? "Сейчас действует текст по умолчанию."
          : `Версия ${c.instruction.version}${c.instruction.updated_at ? `, изменена ${formatAbsolute(c.instruction.updated_at)}` : ""}${c.instruction.updated_by ? `, ${c.instruction.updated_by}` : ""}.`}
        {c.rows.length > 0 && ` Строки матрицы обнаружения: ${c.rows.join(", ")}.`}
      </p>
      <Field label="Инструкция реагирования" hint={`До ${maxBody} знаков, только текст.`}>
        {({ id, describedBy }) => (
          <textarea
            id={id}
            aria-describedby={describedBy}
            rows={6}
            maxLength={maxBody}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 text-base"
          />
        )}
      </Field>
      <ErrorBanner error={m.error} />
      <div>
        <Button variant="primary" disabled={!changed || body.trim() === "" || m.isPending} onClick={() => m.mutate()} aria-label={`Сохранить инструкцию: ${c.title}`}>
          Сохранить инструкцию
        </Button>
      </div>
    </Panel>
  );
}
