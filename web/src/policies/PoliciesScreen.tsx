import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { actionText, type PolicySummary, policiesApi } from "./api";
import { DiffView } from "./DiffView";
import { CreateDialog, ImportDialog, RollbackDialog } from "./PolicyDialogs";
import { Sandbox } from "./Sandbox";

const modeText = { monitor: "Мониторинг", enforce: "Защита" } as const;
const nonTextText = { allow_unchecked: "Пропускать без проверки", allow_inline: "Пропускать, проверяя текст рядом", block: "Блокировать" } as const;
const responseText = { buffered: "С буферизацией", incremental: "Поточная", monitor: "Только наблюдение" } as const;

// Экран «Политики» (ТЗ 6.3, п. 6): версии, сравнение, откат, импорт и экспорт YAML, песочница.
// Кнопки показываются по правам из сессии, решение всегда за сервером.
export function PoliciesScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const list = useQuery({ queryKey: ["policies", "list"], queryFn: ({ signal }) => policiesApi.list(signal) });
  const [sel, setSel] = useState<string>();
  const [create, setCreate] = useState(false);
  const [imp, setImp] = useState(false);
  const selected = list.data?.items.find((p) => p.id === sel);

  return (
    <section aria-label="Политики" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Политики</h1>
        {has("policies.manage") && (
          <div className="flex gap-2">
            <Button onClick={() => setImp(true)}>Загрузить YAML</Button>
            <Button variant="primary" onClick={() => setCreate(true)}>
              Создать политику
            </Button>
          </div>
        )}
      </div>
      <ErrorBanner error={list.error} />
      {!list.data && !list.isError && <p className="text-sm text-muted">Загрузка политик…</p>}
      {list.data && list.data.items.length === 0 && <EmptyState title="Политик пока нет" action={<p className="text-sm text-muted">Создайте политику из шаблона.</p>} />}
      {list.data && list.data.items.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>ID</Th>
                <Th>Режим</Th>
                <Th>Версия</Th>
                <Th>Изменена</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((p) => (
                <tr key={p.id} aria-selected={p.id === sel}>
                  <Td>
                    {p.name}
                    {p.template && <span className="ml-2 text-xs text-muted">(шаблон)</span>}
                  </Td>
                  <Td className="font-mono">{p.id}</Td>
                  <Td>{modeText[p.mode]}</Td>
                  <Td>{p.current_version ?? "—"}</Td>
                  <Td>{p.updated_at ? formatAbsolute(p.updated_at) : "—"}</Td>
                  <Td>
                    <Button onClick={() => setSel(p.id === sel ? undefined : p.id)} aria-label={`Открыть политику ${p.name}`}>
                      {p.id === sel ? "Закрыть" : "Открыть"}
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {selected && <PolicyDetail key={selected.id} summary={selected} me={me} onSelect={setSel} onImport={() => setImp(true)} />}
      <CreateDialog
        open={create}
        onClose={() => setCreate(false)}
        onDone={(p) => {
          setCreate(false);
          setSel(p.id);
        }}
      />
      <ImportDialog
        open={imp}
        onClose={() => setImp(false)}
        current={selected}
        mfa={me.mfa?.enabled === true}
        onDone={(p) => {
          setImp(false);
          setSel(p.id);
        }}
      />
    </section>
  );
}

function PolicyDetail({ summary, me, onSelect, onImport }: { summary: PolicySummary; me: Me; onSelect: (id: string) => void; onImport: () => void }) {
  const has = (p: string) => me.permissions.includes(p);
  const pid = summary.id;
  const policy = useQuery({ queryKey: ["policies", pid, "get"], queryFn: ({ signal }) => policiesApi.get(pid, signal) });
  const versions = useQuery({ queryKey: ["policies", pid, "versions"], queryFn: ({ signal }) => policiesApi.versions(pid, signal), enabled: !summary.template });
  const [rollback, setRollback] = useState<number>();
  const [pair, setPair] = useState<{ from: number; to: number }>();
  const diff = useQuery({
    queryKey: ["policies", pid, "diff", pair?.from, pair?.to],
    queryFn: ({ signal }) => policiesApi.diff(pid, pair!.from, pair!.to, signal),
    enabled: pair !== undefined,
  });
  const [exportErr, setExportErr] = useState<string>();
  const current = summary.current_version;
  const items = versions.data?.items ?? [];

  const doExport = async () => {
    setExportErr(undefined);
    try {
      const text = await policiesApi.exportYaml(pid, undefined);
      const url = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `${pid}.yaml`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setExportErr("Не удалось выгрузить политику. Повторите или обратитесь к администратору.");
    }
  };

  const spec = policy.data?.spec;
  const tabs = [
    {
      value: "content",
      title: "Содержимое",
      content: (
        <div className="flex flex-col gap-3">
          <ErrorBanner error={policy.error} />
          {spec && (
            <>
              <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-muted">Режим</dt>
                <dd>{modeText[spec.mode]}</dd>
                <dt className="text-muted">Нетекстовые данные</dt>
                <dd>{spec.non_text ? nonTextText[spec.non_text] : "—"}</dd>
                <dt className="text-muted">Проверка ответа</dt>
                <dd>{spec.response_check ? responseText[spec.response_check] : "—"}</dd>
                {spec.block_message && (
                  <>
                    <dt className="text-muted">Сообщение при блокировке</dt>
                    <dd>{spec.block_message}</dd>
                  </>
                )}
              </dl>
              <Table>
                <thead>
                  <tr>
                    <Th>Правило</Th>
                    <Th>Детектор</Th>
                    <Th>Действие</Th>
                    <Th>Серьёзность</Th>
                    <Th>Порог</Th>
                  </tr>
                </thead>
                <tbody>
                  {spec.rules.map((r) => (
                    <tr key={r.id}>
                      <Td className="font-mono">{r.id}</Td>
                      <Td className="font-mono">{r.detector}</Td>
                      <Td>{actionText[r.action]}</Td>
                      <Td>{r.severity}</Td>
                      <Td>{r.threshold === undefined ? "—" : String(r.threshold).replace(".", ",")}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </>
          )}
        </div>
      ),
    },
    ...(summary.template
      ? []
      : [
          {
            value: "versions",
            title: "Версии",
            content: (
              <div className="flex flex-col gap-3">
                <ErrorBanner error={versions.error} />
                <Table>
                  <thead>
                    <tr>
                      <Th>Версия</Th>
                      <Th>Создана</Th>
                      <Th>Автор</Th>
                      <Th>Источник</Th>
                      <Th>Комментарий</Th>
                      <Th>Действия</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((v, i) => (
                      <tr key={v.version}>
                        <Td>
                          {v.version}
                          {v.version === current && <span className="ml-2 text-xs text-muted">(текущая)</span>}
                        </Td>
                        <Td>{formatAbsolute(v.created_at)}</Td>
                        <Td>{v.created_by}</Td>
                        <Td>{{ api: "Консоль", import: "Загрузка YAML", rollback: `Откат к версии ${v.rolled_back_from ?? ""}`, template: "Шаблон" }[v.source]}</Td>
                        <Td>{v.comment || "—"}</Td>
                        <Td>
                          <span className="flex gap-2">
                            {items[i + 1] && (
                              <Button onClick={() => setPair({ from: items[i + 1]!.version, to: v.version })} aria-label={`Сравнить версию ${v.version} с предыдущей`}>
                                Сравнить с предыдущей
                              </Button>
                            )}
                            {has("policies.manage") && v.version !== current && (
                              <Button variant="danger" onClick={() => setRollback(v.version)} aria-label={`Откатить к версии ${v.version}`}>
                                Откатить
                              </Button>
                            )}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                {pair && (
                  <>
                    <ErrorBanner error={diff.error} />
                    {diff.data && <DiffView diff={diff.data} />}
                  </>
                )}
              </div>
            ),
          },
        ]),
    ...(has("policies.test")
      ? [{ value: "sandbox", title: "Песочница", content: <Sandbox policyId={pid} versions={items} canReadApps={has("applications.read")} /> }]
      : []),
  ];

  return (
    <Panel aria-label={`Политика ${summary.name}`} className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-md font-semibold">
          {summary.name}
          {current !== undefined && <span className="ml-2 text-sm font-normal text-muted">версия {current}</span>}
        </h2>
        <Button onClick={doExport}>Выгрузить YAML</Button>
      </div>
      {summary.template && <p className="text-sm text-muted">Шаблон меняться не может. Создайте на его основе свою политику.</p>}
      {exportErr && <p role="alert" className="text-sm">{exportErr}</p>}
      {!summary.template && has("policies.manage") && (
        <div>
          <Button onClick={onImport}>Загрузить новую версию из YAML</Button>
        </div>
      )}
      <TabBar label="Разделы политики" tabs={tabs} defaultValue="content" />
      {current !== undefined && (
        <RollbackDialog
          policyId={pid}
          current={current}
          target={rollback}
          mfa={me.mfa?.enabled === true}
          onClose={() => setRollback(undefined)}
          onDone={(p) => {
            setRollback(undefined);
            onSelect(p.id);
          }}
        />
      )}
    </Panel>
  );
}
