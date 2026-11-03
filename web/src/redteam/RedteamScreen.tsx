import type { Me } from "../api/client";
import { TabBar } from "../ui/Layout";
import { CoverageTab } from "./CoverageTab";
import { RunsTab } from "./RunsTab";
import { ScenariosTab } from "./ScenariosTab";
import { SchedulesTab } from "./SchedulesTab";
import { TargetsTab } from "./TargetsTab";

// Экран «Тестирование устойчивости» (ТЗ 5.13, задача 5.34): продукт сам атакует ваши приложения набором сценариев и показывает, что удалось.
// Права проверяет сервер; консоль скрывает кнопки без redteam.run, redteam.targets.manage, redteam.scenarios.load,
// redteam.schedules.manage и выгрузку отчёта без redteam.export. Выдержки ответов в отчёте — ещё и с events.content.read.
export function RedteamScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const tabs = [
    { value: "runs", title: "Запуски", content: <RunsTab canRun={has("redteam.run")} canExport={has("redteam.export")} canReadContent={has("events.content.read")} /> },
    { value: "coverage", title: "Покрытие матрицы", content: <CoverageTab /> },
    { value: "targets", title: "Цели", content: <TargetsTab canManage={has("redteam.targets.manage")} mfa={me.mfa?.enabled === true} /> },
    { value: "schedules", title: "Расписания", content: <SchedulesTab canManage={has("redteam.schedules.manage")} /> },
    { value: "scenarios", title: "Сценарии", content: <ScenariosTab canLoad={has("redteam.scenarios.load")} /> },
  ];
  return (
    <section aria-label="Тестирование устойчивости" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Тестирование устойчивости</h1>
        <p className="text-sm text-muted">
          Проверка защиты ваших приложений набором атак на языковые модели. Запускайте вручную, по расписанию или из CI. Атаки идут только на ваши цели из списка.
        </p>
      </div>
      <TabBar label="Разделы тестирования устойчивости" defaultValue="runs" tabs={tabs} />
    </section>
  );
}
