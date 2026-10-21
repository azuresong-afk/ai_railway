import type { Me } from "../api/client";
import { EmptyState, TabBar } from "../ui/Layout";
import { AuditTab } from "./AuditTab";
import { PolicyTab } from "./PolicyTab";
import { RetentionTab } from "./RetentionTab";
import { RolesTab } from "./RolesTab";
import { TokensTab } from "./TokensTab";
import { UsersTab } from "./UsersTab";

// Экран «Администрирование» (ТЗ 6.3, п. 12): вкладки видны по правам из сессии, решение всегда за сервером.
export function AdminScreen({ me }: { me: Me }) {
  const has = (...p: string[]) => p.some((x) => me.permissions.includes(x));
  const tabs = [
    has("users.read") && { value: "users", title: "Пользователи", content: <UsersTab me={me} /> },
    has("roles.read") && { value: "roles", title: "Роли и разрешения", content: <RolesTab me={me} /> },
    has("auth_policy.read") && { value: "policy", title: "Вход и сессии", content: <PolicyTab me={me} /> },
    has("api_tokens.read") && { value: "tokens", title: "Токены API", content: <TokensTab me={me} /> },
    has("events.read") && { value: "retention", title: "Время и хранение", content: <RetentionTab me={me} /> },
    has("audit.read") && { value: "audit", title: "Журнал аудита", content: <AuditTab me={me} /> },
  ].filter((t): t is { value: string; title: string; content: React.JSX.Element } => t !== false);

  if (tabs.length === 0) {
    return <EmptyState title="Нет доступа к администрированию" action={<p className="text-sm text-muted">Обратитесь к администратору.</p>} />;
  }
  return (
    <section aria-label="Администрирование" className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Администрирование</h1>
      <TabBar label="Разделы администрирования" tabs={tabs} defaultValue={tabs[0]!.value} />
    </section>
  );
}
