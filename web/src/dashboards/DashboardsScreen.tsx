import type { Me } from "../api/client";
import { TabBar } from "../ui/Layout";
import { AppScreen, OverviewScreen, PiiScreen, ThreatsScreen } from "./screens";

// Экран «Обзор» (ТЗ 6.4, 5.8): общая картина, угрозы, ПДн и мини-дашборд приложения.
// Права и область (всё или своё приложение) проверяет сервер; без полного доступа остаётся «Приложение».
export function DashboardsScreen({ me }: { me: Me }) {
  const full = me.permissions.includes("events.read") || me.permissions.includes("system.read");
  const tabs = [
    ...(full
      ? [
          { value: "overview", title: "Обзор", content: <OverviewScreen me={me} /> },
          { value: "threats", title: "Угрозы", content: <ThreatsScreen /> },
          { value: "pii", title: "ПДн", content: <PiiScreen /> },
        ]
      : []),
    { value: "app", title: "Приложение", content: <AppScreen /> },
  ];
  return (
    <div className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Обзор</h1>
      <TabBar label="Дашборды" tabs={tabs} defaultValue={tabs[0]!.value} />
    </div>
  );
}
