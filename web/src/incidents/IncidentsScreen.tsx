import type { Me } from "../api/client";
import { TabBar } from "../ui/Layout";
import { CategoriesPanel } from "./CategoriesPanel";
import { IncidentList } from "./IncidentList";
import { RetentionPanel } from "./RetentionPanel";

// Экран «Инциденты» (ТЗ 5.7, 6.3, п. 5): список и доска, карточка; инструкции категорий и срок хранения — отдельные вкладки по праву.
// Вкладки показываются по правам из сессии, а решение о доступе всегда принимает сервер.
export function IncidentsScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const tabs = [
    ...(has("incidents.read") ? [{ value: "list", title: "Инциденты", content: <IncidentList me={me} /> }] : []),
    ...(has("incident_categories.manage") ? [{ value: "instructions", title: "Инструкции по категориям", content: <CategoriesPanel /> }] : []),
    ...(has("incidents.read") ? [{ value: "retention", title: "Срок хранения", content: <RetentionPanel me={me} /> }] : []),
  ];
  return (
    <section aria-label="Инциденты" className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Инциденты</h1>
      {tabs.length > 0 ? (
        <TabBar label="Разделы инцидентов" tabs={tabs} defaultValue={tabs[0]!.value} />
      ) : (
        <p className="text-sm text-muted">Нет доступа к инцидентам. Обратитесь к администратору.</p>
      )}
    </section>
  );
}
