import { useSearchParams } from "react-router";
import type { Me } from "../api/client";
import { TabBar } from "../ui/Layout";
import { AibomPanel } from "./AibomPanel";
import { ModelsTab } from "./ModelsTab";
import { OverviewTab } from "./OverviewTab";
import { TemplatesTab } from "./TemplatesTab";

// Экран «Реестр ИИ» (ТЗ 5.11, задача 5.23): приложения, провайдеры, ключи и модели, отчёты сканера, база эталонов шаблонов чата,
// выгрузка AI-BOM. Права проверяет сервер; консоль скрывает кнопки без inventory.manage, inventory.unblock,
// models.templates.load и вкладку AI-BOM без inventory.export.
export function InventoryScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const [params] = useSearchParams();
  const tabs = [
    { value: "overview", title: "Приложения и провайдеры", content: <OverviewTab /> },
    {
      value: "models",
      title: "Модели",
      content: <ModelsTab canManage={has("inventory.manage")} canUnblock={has("inventory.unblock")} mfa={me.mfa?.enabled === true} />,
    },
    { value: "templates", title: "Шаблоны чата", content: <TemplatesTab canLoad={has("models.templates.load")} /> },
    ...(has("inventory.export") ? [{ value: "aibom", title: "AI-BOM", content: <AibomPanel /> }] : []),
  ];
  return (
    <section aria-label="Реестр ИИ" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Реестр ИИ</h1>
        <p className="text-sm text-muted">
          Какие приложения, модели и провайдеры используются, откуда они взялись и можно ли им доверять. Реестр пополняется по трафику шлюза и вручную.
        </p>
      </div>
      <TabBar label="Разделы реестра ИИ" defaultValue={params.get("model") ? "models" : "overview"} tabs={tabs} />
    </section>
  );
}
