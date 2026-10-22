import { formatAbsolute } from "../events/format";
import { Banner, Table, Td, Th } from "../ui/Layout";
import { actionText, type PolicyDiff, type PolicyException, type PolicyRule, weakeningText } from "./api";

const fieldText: Record<PolicyDiff["fields"][number]["field"], string> = {
  name: "Название",
  mode: "Режим",
  non_text: "Нетекстовые данные",
  response_check: "Проверка ответа",
  block_message: "Сообщение при блокировке",
};

const ruleLine = (r: PolicyRule) => `${r.id}: ${r.detector}, ${actionText[r.action]}, серьёзность ${r.severity}`;

const exceptionLine = (e: PolicyException) =>
  `${e.id}: ${[e.detector, e.category, e.pattern, e.app && `приложение ${e.app}`, e.fragment && "по фрагменту"].filter(Boolean).join(", ")}${e.expires_at ? `, до ${formatAbsolute(e.expires_at)}` : ""}`;

// Сравнение двух версий политики (ТЗ 5.3); признаки ослабления защиты (DM-40) выводятся текстом, не только цветом.
export function DiffView({ diff, preview }: { diff: PolicyDiff; preview?: boolean }) {
  const empty =
    diff.fields.length + diff.rules_added.length + diff.rules_removed.length + diff.rules_changed.length +
      diff.exceptions_added.length + diff.exceptions_removed.length + diff.exceptions_changed.length === 0 && !diff.reordered;
  return (
    <section aria-label={preview ? "Различия с текущей версией" : `Различия версий ${diff.from} и ${diff.to}`} className="flex flex-col gap-3">
      <h3 className="text-sm font-medium">{preview ? "Что изменится по сравнению с текущей версией" : `Версия ${diff.from} → версия ${diff.to}`}</h3>
      {diff.weakening && (
        <Banner kind="warning">
          Изменение ослабляет защиту: {diff.weakening_reasons.map((r) => `${weakeningText[r.kind]}${r.rule ? ` (${r.rule})` : ""}${r.exception ? ` (${r.exception})` : ""}`).join("; ")}.
          {preview ? " Для сохранения понадобится пароль или код. " : " "}Изменение будет отмечено в журнале аудита как ослабление защиты.
        </Banner>
      )}
      {empty && <p className="text-sm text-muted">Содержимое версий совпадает.</p>}
      {diff.fields.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Поле</Th>
              <Th>Было</Th>
              <Th>Стало</Th>
            </tr>
          </thead>
          <tbody>
            {diff.fields.map((f) => (
              <tr key={f.field}>
                <Td>{fieldText[f.field]}</Td>
                <Td>{f.before || "—"}</Td>
                <Td>{f.after || "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {diff.rules_added.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Добавлены правила</h4>
          <ul className="list-disc pl-5 text-sm">{diff.rules_added.map((r) => <li key={r.id}>{ruleLine(r)}</li>)}</ul>
        </div>
      )}
      {diff.rules_removed.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Удалены правила</h4>
          <ul className="list-disc pl-5 text-sm">{diff.rules_removed.map((r) => <li key={r.id}>{ruleLine(r)}</li>)}</ul>
        </div>
      )}
      {diff.rules_changed.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Изменены правила</h4>
          <ul className="list-disc pl-5 text-sm">
            {diff.rules_changed.map((r) => (
              <li key={r.id}>
                {r.id} (изменено: {r.fields.join(", ")}): {ruleLine(r.before)} → {ruleLine(r.after)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {diff.reordered && <p className="text-sm">Изменён порядок правил.</p>}
      {diff.exceptions_added.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Добавлены исключения</h4>
          <ul className="list-disc pl-5 text-sm">{diff.exceptions_added.map((e) => <li key={e.id}>{exceptionLine(e)}</li>)}</ul>
        </div>
      )}
      {diff.exceptions_removed.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Удалены исключения</h4>
          <ul className="list-disc pl-5 text-sm">{diff.exceptions_removed.map((e) => <li key={e.id}>{exceptionLine(e)}</li>)}</ul>
        </div>
      )}
      {diff.exceptions_changed.length > 0 && (
        <div>
          <h4 className="text-sm font-medium">Изменены исключения</h4>
          <ul className="list-disc pl-5 text-sm">
            {diff.exceptions_changed.map((e) => (
              <li key={e.id}>
                {e.id} (изменено: {e.fields.join(", ")}): {exceptionLine(e.before)} → {exceptionLine(e.after)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
