import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useMemo, useState } from "react";
import { Link } from "react-router";
import { ErrorBanner, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { buildFilter } from "../events/filter";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { type Agent, agentsApi, type AgentTool, type McpServer, type ToolStatus } from "./api";
import { RiskBadge, StatusBadge, statusLabel } from "./labels";
import { ToolDialog } from "./ToolDialog";

const dash = "—";

// Ссылка на события по условию: фильтр собирает та же функция, что и экран событий.
function eventsLink(field: string, value: string): string {
  return `/events?f=${encodeURIComponent(buildFilter([{ field, negate: false, values: [value] }]))}`;
}

function AgentsTab({ servers }: { servers: Map<string, McpServer> }) {
  const q = useQuery({ queryKey: ["agents", "list"], queryFn: ({ signal }) => agentsApi.agents(signal) });
  if (q.isError) return <ErrorBanner error={q.error} />;
  if (!q.data) return <p className="text-sm text-muted">Загрузка агентов…</p>;
  if (q.data.items.length === 0) return <EmptyState title="Агентов пока нет" action={<p className="text-sm text-muted">Агента создаёт администратор в карточке приложения.</p>} />;
  return (
    <Panel className="overflow-auto p-0">
      <Table>
        <thead>
          <tr>
            <Th>Название</Th>
            <Th>ID</Th>
            <Th>Ответственный</Th>
            <Th>MCP-серверы</Th>
            <Th>Состояние</Th>
            <Th>События</Th>
          </tr>
        </thead>
        <tbody>
          {q.data.items.map((a: Agent) => (
            <tr key={a.id}>
              <Td>
                {a.name}
                {a.description && <span className="block text-xs text-muted">{a.description}</span>}
              </Td>
              <Td className="font-mono">{a.slug}</Td>
              <Td>{a.owner || dash}</Td>
              <Td>{a.mcp_servers.length > 0 ? a.mcp_servers.map((s) => servers.get(s)?.slug ?? s).join(", ") : dash}</Td>
              <Td>{a.status === "active" ? "Работает" : "Отключён"}</Td>
              <Td>
                <Link className="underline" to={eventsLink("agent", a.slug)} aria-label={`События агента ${a.name}`}>
                  Открыть
                </Link>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Panel>
  );
}

// Учётные данные MCP-сервера: только ввод. Значение живёт в состоянии формы и стирается при закрытии и после успеха.
function CredentialDialog({ server, onClose }: { server: McpServer; onClose: () => void }) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const m = useMutation({
    mutationFn: () => agentsApi.setCredential(server.id, value),
    onSuccess: async () => {
      setValue("");
      await qc.invalidateQueries({ queryKey: ["mcp-servers"] });
      onClose();
    },
  });
  const close = () => {
    setValue("");
    m.reset();
    onClose();
  };
  const bad = value === "" ? "Введите значение заголовка." : /^[\x20-\x7e]+$/.test(value) ? undefined : "Только видимые символы ASCII и пробел.";
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!bad) m.mutate();
  };
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && close()}
      title={`Учётные данные: ${server.name}`}
      description="Значение шифруется и больше нигде не показывается. Новое значение заменяет прежнее."
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label={`Значение заголовка ${server.auth_header || "Authorization"}`} error={value === "" ? undefined : bad}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} name="mcp-credential" aria-describedby={describedBy} aria-invalid={invalid} type="password" autoComplete="new-password" maxLength={16384} value={value} onChange={(e) => setValue(e.target.value)} />
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || Boolean(bad)}>
            Сохранить учётные данные
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function ServersTab({ canManage }: { canManage: boolean }) {
  const q = useQuery({ queryKey: ["mcp-servers", "list"], queryFn: ({ signal }) => agentsApi.servers(signal) });
  const [cred, setCred] = useState<McpServer>();
  if (q.isError) return <ErrorBanner error={q.error} />;
  if (!q.data) return <p className="text-sm text-muted">Загрузка MCP-серверов…</p>;
  if (q.data.items.length === 0) return <EmptyState title="MCP-серверов пока нет" action={<p className="text-sm text-muted">Сервер регистрирует администратор.</p>} />;
  return (
    <>
      <Panel className="overflow-auto p-0">
        <Table>
          <thead>
            <tr>
              <Th>Название</Th>
              <Th>ID</Th>
              <Th>Адрес</Th>
              <Th>Контур</Th>
              <Th>Учётные данные</Th>
              <Th>Действия</Th>
            </tr>
          </thead>
          <tbody>
            {q.data.items.map((s) => (
              <tr key={s.id}>
                <Td>{s.name}</Td>
                <Td className="font-mono">{s.slug}</Td>
                <Td className="font-mono text-sm break-all">{s.url}</Td>
                <Td>
                  {s.external ? "Внешний" : "Внутренний"}
                  {s.insecure_http && <span className="block text-xs text-muted">Разрешён http:// без шифрования</span>}
                </Td>
                <Td>{s.credential_set ? `Заданы (${s.credential_set_at ? formatAbsolute(s.credential_set_at) : "время неизвестно"})` : "Не заданы"}</Td>
                <Td>
                  <span className="flex flex-wrap gap-2">
                    {canManage && (
                      <Button onClick={() => setCred(s)} aria-label={`Учётные данные ${s.name}`}>
                        Учётные данные
                      </Button>
                    )}
                    <Link className="underline" to={eventsLink("mcp_server", s.slug)} aria-label={`События сервера ${s.name}`}>
                      События
                    </Link>
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Panel>
      {cred && <CredentialDialog key={cred.id} server={cred} onClose={() => setCred(undefined)} />}
    </>
  );
}

const statuses: ToolStatus[] = ["new", "approved", "changed", "suspicious", "revoked"];

function ToolsTab({ me, servers }: { me: Me; servers: Map<string, McpServer> }) {
  const [status, setStatus] = useState<ToolStatus | "">("");
  const [server, setServer] = useState("");
  const [open, setOpen] = useState<AgentTool>();
  const q = useQuery({
    queryKey: ["agent-tools", "list", status, server],
    queryFn: ({ signal }) => agentsApi.tools({ ...(status ? { status } : {}), ...(server ? { mcp_server_id: server } : {}) }, signal),
  });
  const bad = useQuery({
    queryKey: ["agent-tools", "list", "suspicious", ""],
    queryFn: ({ signal }) => agentsApi.tools({ status: "suspicious" }, signal),
  });
  const origin = (t: AgentTool) => (t.mcp_server_id ? (servers.get(t.mcp_server_id)?.slug ?? t.mcp_server_id) : "функция агента");
  const canApprove = me.permissions.includes("agents.tools.approve");
  return (
    <div className="flex flex-col gap-3">
      {bad.data && bad.data.items.length > 0 && (
        <Banner kind="error">
          В описаниях {bad.data.items.length} инструментов найдены внедрённые инструкции для модели (DM-24).{" "}
          <Button variant="ghost" onClick={() => setStatus("suspicious")}>
            Показать подозрительные
          </Button>
        </Banner>
      )}
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Состояние
          <Select value={status} onChange={(e) => setStatus(e.target.value as ToolStatus | "")} className="w-56">
            <option value="">Любое</option>
            {statuses.map((s) => (
              <option key={s} value={s}>
                {statusLabel.get(s)}
              </option>
            ))}
          </Select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          MCP-сервер
          <Select value={server} onChange={(e) => setServer(e.target.value)} className="w-56">
            <option value="">Любой</option>
            {[...servers.values()].map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        </label>
      </div>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка инструментов…</p>}
      {q.data && q.data.items.length === 0 && <EmptyState title="Инструментов нет" action={<p className="text-sm text-muted">Они появятся после первого запроса списка инструментов через шлюз.</p>} />}
      {q.data && q.data.items.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Инструмент</Th>
                <Th>Источник</Th>
                <Th>Состояние</Th>
                <Th>Риск</Th>
                <Th>Виден</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((t) => (
                <tr key={t.id}>
                  <Td className="font-mono">{t.name}</Td>
                  <Td>{origin(t)}</Td>
                  <Td>
                    <StatusBadge status={t.status} />
                  </Td>
                  <Td>
                    <RiskBadge risk={t.risk} />
                  </Td>
                  <Td>{formatAbsolute(t.last_seen)}</Td>
                  <Td>
                    <span className="flex flex-wrap gap-2">
                      <Button onClick={() => setOpen(t)} aria-label={`Открыть инструмент ${t.name}`}>
                        {canApprove && t.status !== "approved" ? "Проверить и одобрить" : "Открыть"}
                      </Button>
                      {t.status === "suspicious" && (
                        <Link className="underline" to={eventsLink("tool", t.name)} aria-label={`События инструмента ${t.name}`}>
                          События
                        </Link>
                      )}
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {open && <ToolDialog key={open.id} tool={open} canApprove={canApprove} mfa={me.mfa?.enabled === true} onClose={() => setOpen(undefined)} />}
    </div>
  );
}

// Экран «Агенты» (ТЗ 5.10, 6.3): реестр агентов, MCP-серверов и инструментов. Кнопки показываются по правам из сессии,
// решение о доступе принимает сервер.
export function AgentsScreen({ me }: { me: Me }) {
  const serversQ = useQuery({ queryKey: ["mcp-servers", "list"], queryFn: ({ signal }) => agentsApi.servers(signal) });
  const servers = useMemo(() => new Map((serversQ.data?.items ?? []).map((s) => [s.id, s])), [serversQ.data]);
  const tabs = [
    { value: "agents", title: "Агенты", content: <AgentsTab servers={servers} /> },
    { value: "servers", title: "MCP-серверы", content: <ServersTab canManage={me.permissions.includes("agents.manage")} /> },
    { value: "tools", title: "Инструменты", content: <ToolsTab me={me} servers={servers} /> },
  ];
  return (
    <section aria-label="Агенты" className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Агенты</h1>
      <TabBar label="Разделы реестра агентов" tabs={tabs} defaultValue="agents" />
    </section>
  );
}
