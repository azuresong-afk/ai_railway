import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { type AlertRule, alertsApi } from "./api";
import { kindText } from "./format";
import { RuleDialog } from "./RuleDialog";

function conditionText(r: AlertRule): string {
  const c = r.condition;
  const parts: string[] = [];
  if (c.field) parts.push(`новое значение: ${c.field}`);
  if (c.filter) parts.push(c.filter);
  if (c.min_severity) parts.push(`серьёзность не ниже ${c.min_severity}`);
  if (c.count) parts.push(`${c.count} событий за ${c.window_minutes ?? "?"} мин`);
  if (c.metric) parts.push(`метрика ${c.metric}, ×${c.factor ?? 3}`);
  if (c.warn_percent) parts.push(`бюджет ${c.warn_percent} % и 100 %`);
  return parts.join("; ") || "—";
}

// Правила оповещений: встроенные и системные только просматриваются (меняются получатели), свои — создаются и правятся.
export function RulesPanel({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const canManage = has("alert_rules.manage");
  const q = useQuery({ queryKey: ["alerts", "rules"], queryFn: ({ signal }) => alertsApi.rules(signal) });
  const [dialog, setDialog] = useState<{ rule: AlertRule | null }>();
  const mfa = me.mfa?.enabled === true;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted">Системные правила и правила безопасности не отключаются: у них меняются только получатели.</p>
        {canManage && (
          <Button variant="primary" onClick={() => setDialog({ rule: null })}>
            Создать правило
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка правил…</p>}
      {q.data && q.data.items.length === 0 && <EmptyState title="Правил нет" action={<p className="text-sm text-muted">Встроенные правила создаются при запуске сервера.</p>} />}
      {q.data && q.data.items.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>Вид</Th>
                <Th>Условие</Th>
                <Th>Серьёзность</Th>
                <Th>Состояние</Th>
                <Th>Изменено</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((r) => (
                <tr key={r.id}>
                  <Td>{r.name}</Td>
                  <Td>{kindText.get(r.kind) ?? r.kind}</Td>
                  <Td className="max-w-80 truncate font-mono text-sm" title={conditionText(r)}>
                    {conditionText(r)}
                  </Td>
                  <Td>
                    <SeverityBadge level={r.severity} />
                  </Td>
                  <Td>
                    {r.locked ? "Не отключается" : r.enabled ? "Включено" : "Выключено"}
                  </Td>
                  <Td>{formatAbsolute(r.updated_at)}</Td>
                  <Td>
                    {canManage ? (
                      <Button onClick={() => setDialog({ rule: r })} aria-label={`${r.locked ? "Получатели правила" : "Изменить правило"} ${r.name}`}>
                        {r.locked ? "Получатели" : "Изменить"}
                      </Button>
                    ) : (
                      <span className="text-sm text-muted">Только просмотр</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {dialog && (
        <RuleDialog
          key={dialog.rule?.id ?? "new"}
          rule={dialog.rule}
          mfa={mfa}
          canUsers={has("users.read")}
          canRoles={has("roles.read")}
          onClose={() => setDialog(undefined)}
        />
      )}
    </div>
  );
}
