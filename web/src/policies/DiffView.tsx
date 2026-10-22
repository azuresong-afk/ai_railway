import { Banner, Table, Td, Th } from "../ui/Layout";
import { actionText, type PolicyDiff, type PolicyRule, weakeningText } from "./api";

const fieldText: Record<PolicyDiff["fields"][number]["field"], string> = {
  name: "Название",
  mode: "Режим",
  non_text: "Нетекстовые данные",
  response_check: "Проверка ответа",
  block_message: "Сообщение при блокировке",
};

const ruleLine = (r: PolicyRule) => `${r.id}: ${r.detector}, ${actionText[r.action]}, серьёзность ${r.severity}`;

// Сравнение двух версий политики (ТЗ 5.3); признаки ослабления защиты (DM-40) выводятся текстом, не только цветом.
export function DiffView({ diff }: { diff: PolicyDiff }) {
  const empty =
    diff.fields.length + diff.rules_added.length + diff.rules_removed.length + diff.rules_changed.length === 0 && !diff.reordered;
  return (
    <section aria-label={`Различия версий ${diff.from} и ${diff.to}`} className="flex flex-col gap-3">
      <h3 className="text-sm font-medium">
        Версия {diff.from} → версия {diff.to}
      </h3>
      {diff.weakening && (
        <Banner kind="warning">
          Изменение ослабляет защиту: {diff.weakening_reasons.map((r) => `${weakeningText[r.kind]}${r.rule ? ` (${r.rule})` : ""}`).join("; ")}.
          Изменение будет отмечено в журнале аудита как ослабление защиты.
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
    </section>
  );
}
