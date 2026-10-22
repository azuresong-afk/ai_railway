import type { Me } from "../api/client";
import { TabBar } from "../ui/Layout";
import { AlertList } from "./AlertList";
import { ChannelsPanel } from "./ChannelsPanel";
import { RetentionPanel } from "./RetentionPanel";
import { RulesPanel } from "./RulesPanel";

// Экран «Оповещения» (ТЗ 6.3, п. 2): список и карточки, правила, каналы, срок хранения. Вкладки показываются по правам
// из сессии, а решение о доступе всегда принимает сервер.
export function AlertsScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const tabs = [
    ...(has("alerts.read") ? [{ value: "list", title: "Оповещения", content: <AlertList me={me} /> }] : []),
    ...(has("alert_rules.read") ? [{ value: "rules", title: "Правила", content: <RulesPanel me={me} /> }] : []),
    ...(has("notify_channels.read") ? [{ value: "channels", title: "Каналы", content: <ChannelsPanel me={me} /> }] : []),
    ...(has("alert_rules.read") ? [{ value: "retention", title: "Срок хранения", content: <RetentionPanel me={me} /> }] : []),
  ];
  return (
    <section aria-label="Оповещения" className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Оповещения</h1>
      {tabs.length > 0 ? <TabBar label="Разделы оповещений" tabs={tabs} defaultValue={tabs[0]!.value} /> : <p className="text-sm text-muted">Нет доступа к оповещениям. Обратитесь к администратору.</p>}
    </section>
  );
}
