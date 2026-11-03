import { useQuery } from "@tanstack/react-query";
import { ErrorBanner } from "../admin/common";
import { formatAbsolute, formatNumber } from "../events/format";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { inventoryApi } from "./api";
import { envTitle, keyStateTitle, providerTypeTitle } from "./format";

// Вкладка «Приложения и провайдеры» (задача 5.23): приложения, их провайдеры и ключи, провайдеры, состояние пополнения реестра.
// Секретов и хешей ключей в ответе нет: показываются префикс, название и срок.
export function OverviewTab() {
  const q = useQuery({ queryKey: ["inventory", "overview"], queryFn: ({ signal }) => inventoryApi.overview(signal) });
  const o = q.data;
  const providerName = (slug: string) => o?.providers.find((p) => p.slug === slug)?.name ?? slug;
  const keys = (o?.applications ?? []).flatMap((a) => a.keys.map((k) => ({ app: a, key: k })));

  return (
    <div className="flex flex-col gap-4">
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка реестра…</p>}
      {o && (
        <>
          <Panel role="region" aria-label="Сводка реестра" className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">Сводка</h2>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
              <dt className="text-muted">Приложений</dt>
              <dd>{formatNumber(o.applications.length)}</dd>
              <dt className="text-muted">Провайдеров</dt>
              <dd>{formatNumber(o.providers.length)}</dd>
              <dt className="text-muted">Моделей в реестре</dt>
              <dd>
                {formatNumber(o.models)} из {formatNumber(o.limits.models)}
              </dd>
              <dt className="text-muted">Записей использования</dt>
              <dd>
                {formatNumber(o.usage)} из {formatNumber(o.limits.usage)}
              </dd>
              <dt className="text-muted">Пополнение по трафику</dt>
              <dd>
                {o.sync.synced_upto ? `прочитано до ${formatAbsolute(o.sync.synced_upto)}` : "ещё не запускалось"}
                {o.sync.run_at ? `, запуск ${formatAbsolute(o.sync.run_at)}` : ""}
              </dd>
            </dl>
            {o.sync.limit_reached && (
              <Banner kind="warning">
                В последнем запуске в реестр поместилось не всё: пропущено {formatNumber(o.sync.skipped)}. Удалите ненужные модели или добавьте нужные вручную.
              </Banner>
            )}
          </Panel>

          <Panel role="region" aria-label="Приложения" className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">Приложения</h2>
            {o.applications.length === 0 ? (
              <EmptyState title="Приложений пока нет" action={<p className="text-sm text-muted">Подключите первое приложение в разделе «Приложения».</p>} />
            ) : (
              <div className="overflow-auto">
                <Table aria-label="Приложения реестра">
                  <thead>
                    <tr>
                      <Th>Приложение</Th>
                      <Th>Среда</Th>
                      <Th>Подразделение</Th>
                      <Th>Провайдер</Th>
                      <Th>Разрешённые модели</Th>
                      <Th className="text-right">Ключей</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {o.applications.map((a) => (
                      <tr key={a.id}>
                        <Td>
                          {a.name}
                          <div className="text-xs text-muted">{a.slug}</div>
                          {a.archived && <div className="text-xs text-muted">В архиве</div>}
                        </Td>
                        <Td>{envTitle.get(a.env) ?? a.env}</Td>
                        <Td>{a.department || "—"}</Td>
                        <Td>{providerName(a.provider)}</Td>
                        <Td className="break-words">{a.models.length ? a.models.join(", ") : "не ограничены"}</Td>
                        <Td className="text-right">{formatNumber(a.keys.length)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </Panel>

          <Panel role="region" aria-label="Ключи приложений" className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">Ключи приложений</h2>
            <p className="text-sm text-muted">Только префикс, название и срок: сам ключ нигде не показывается. Для каждого приложения — до 20 последних ключей.</p>
            {keys.length === 0 ? (
              <p className="text-sm text-muted">Ключей нет.</p>
            ) : (
              <div className="overflow-auto">
                <Table aria-label="Ключи">
                  <thead>
                    <tr>
                      <Th>Приложение</Th>
                      <Th>Название ключа</Th>
                      <Th>Префикс</Th>
                      <Th>Состояние</Th>
                      <Th>Срок действия</Th>
                      <Th>Создан</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {keys.map(({ app, key }) => (
                      <tr key={key.id}>
                        <Td>{app.name}</Td>
                        <Td>{key.name}</Td>
                        <Td className="font-mono text-sm">{key.prefix}</Td>
                        <Td>{keyStateTitle.get(key.state)}</Td>
                        <Td>{formatAbsolute(key.expires_at)}</Td>
                        <Td>{formatAbsolute(key.created_at)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </Panel>

          <Panel role="region" aria-label="Провайдеры" className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">Провайдеры</h2>
            {o.providers.length === 0 ? (
              <p className="text-sm text-muted">Провайдеров нет.</p>
            ) : (
              <div className="overflow-auto">
                <Table aria-label="Провайдеры реестра">
                  <thead>
                    <tr>
                      <Th>Провайдер</Th>
                      <Th>Тип</Th>
                      <Th>Расположение</Th>
                      <Th>Учётные данные</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {o.providers.map((p) => (
                      <tr key={p.id}>
                        <Td>
                          {p.name}
                          <div className="text-xs text-muted">{p.slug}</div>
                        </Td>
                        <Td>{providerTypeTitle.get(p.type) ?? p.type}</Td>
                        <Td>{p.external ? "внешний" : "в контуре заказчика"}</Td>
                        <Td>{p.credential_set ? `заданы${p.credential_set_at ? `, ${formatAbsolute(p.credential_set_at)}` : ""}` : "не заданы"}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
