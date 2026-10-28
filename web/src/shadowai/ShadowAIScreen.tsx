import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { ChartCard } from "../dashboards/charts";
import { token } from "../dashboards/Chart";
import { bucketLabel } from "../dashboards/format";
import { formatAbsolute, formatNumber } from "../events/format";
import { formatBytes } from "../system/format";
import { Button } from "../ui/Button";
import { Field, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { type Range, type ShadowCatalog, type ShadowTimeline, shadowApi } from "./api";
import { type ExclusionDraft, ExclusionDialog, ExclusionsTab } from "./ExclusionsTab";
import { categoryTitle, type PeriodId, periods, serviceName, userFilter, userKindTitle } from "./format";
import { ImportTab } from "./ImportTab";
import { SyslogPanel } from "./SyslogPanel";

const axisText = () => ({ color: token("--c-text-muted") });

// Динамика: обращения столбцами, пользователи линией по второй оси.
function timelineOption(t: ShadowTimeline) {
  const labels = t.items.map((p) => bucketLabel(p.bucket, t.step));
  return {
    tooltip: { trigger: "axis" },
    legend: { data: ["Обращения", "Пользователи"], textStyle: axisText() },
    grid: { left: 56, right: 48, top: 32, bottom: 28 },
    xAxis: { type: "category", data: labels, axisLabel: axisText() },
    yAxis: [
      { type: "value", axisLabel: axisText(), splitLine: { lineStyle: { color: token("--c-border") } } },
      { type: "value", minInterval: 1, axisLabel: axisText(), splitLine: { show: false } },
    ],
    series: [
      { name: "Обращения", type: "bar", data: t.items.map((p) => p.requests) },
      { name: "Пользователи", type: "line", yAxisIndex: 1, showSymbol: false, data: t.items.map((p) => p.users) },
    ],
  };
}

function rangeOf(id: PeriodId, now: number): Range {
  const days = periods.find((p) => p.id === id)!.days;
  return { from: new Date(now - days * 86_400_000).toISOString(), to: new Date(now).toISOString() };
}

// Вкладка «Сервисы и пользователи»: сервисы каталога за период, их пользователи (псевдонимами) и динамика.
function OverviewTab({
  me,
  catalog,
  canManage,
  onExclude,
}: {
  me: Me;
  catalog: ShadowCatalog | undefined;
  canManage: boolean;
  onExclude: (d: ExclusionDraft) => void;
}) {
  const [period, setPeriod] = useState<PeriodId>("30d");
  const [anchor, setAnchor] = useState(() => Date.now());
  const [service, setService] = useState("");
  const range = useMemo(() => rangeOf(period, anchor), [period, anchor]);
  const step = periods.find((p) => p.id === period)!.step;
  const services = useQuery({ queryKey: ["shadow-ai", "services", range], queryFn: ({ signal }) => shadowApi.services(range, signal) });
  const users = useQuery({ queryKey: ["shadow-ai", "users", range, service], queryFn: ({ signal }) => shadowApi.users(range, service, signal) });
  const timeline = useQuery({ queryKey: ["shadow-ai", "timeline", range, step], queryFn: ({ signal }) => shadowApi.timeline(range, step, signal) });
  const canEvents = me.permissions.includes("events.read");
  const list = services.data?.items ?? [];
  const people = users.data?.items ?? [];
  const t = timeline.data;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Период">
          {({ id }) => (
            <Select
              id={id}
              value={period}
              onChange={(e) => {
                setPeriod(e.target.value as PeriodId);
                setAnchor(Date.now());
              }}
            >
              {periods.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button onClick={() => setAnchor(Date.now())}>Обновить</Button>
      </div>
      <ErrorBanner error={services.error ?? timeline.error} />
      {t && (
        <ChartCard
          title="Динамика обращений"
          label={`Обращения к ИИ-сервисам и число пользователей, ${periods.find((p) => p.id === period)!.title.toLowerCase()}`}
          option={timelineOption(t)}
          head={["Время", "Обращения", "Пользователи", "Сервисы"]}
          rows={t.items.map((p) => [bucketLabel(p.bucket, t.step), p.requests, p.users, p.services])}
          empty={t.items.length === 0}
        />
      )}

      <Panel role="region" aria-label="Сервисы" className="flex flex-col gap-2">
        <h2 className="text-lg font-semibold">Сервисы</h2>
        {services.isPending && <p className="text-sm text-muted">Загрузка сервисов…</p>}
        {services.data && list.length === 0 && (
          <EmptyState
            title="За период обращений к ИИ-сервисам не найдено"
            action={<p className="text-sm text-muted">Импортируйте журнал прокси или включите приём по syslog.</p>}
          />
        )}
        {list.length > 0 && (
          <div className="overflow-auto">
            <Table aria-label="Сервисы за период">
              <thead>
                <tr>
                  <Th>Сервис</Th>
                  <Th>Категория</Th>
                  <Th className="text-right">Пользователей</Th>
                  <Th className="text-right">Обращений</Th>
                  <Th className="text-right">Объём</Th>
                  <Th>Впервые</Th>
                  <Th>Последний раз</Th>
                  <Th>Действия</Th>
                </tr>
              </thead>
              <tbody>
                {list.map((s) => (
                  <tr key={s.id}>
                    <Td>
                      {s.name}
                      {s.vendor && <div className="text-xs text-muted">{s.vendor}</div>}
                    </Td>
                    <Td>{categoryTitle.get(s.category) ?? "нет в каталоге"}</Td>
                    <Td className="text-right">{formatNumber(s.users)}</Td>
                    <Td className="text-right">{formatNumber(s.requests)}</Td>
                    <Td className="text-right">{formatBytes(s.bytes)}</Td>
                    <Td>{formatAbsolute(s.first_seen)}</Td>
                    <Td>{formatAbsolute(s.last_seen)}</Td>
                    <Td>
                      <div className="flex flex-wrap gap-1">
                        <Button variant="ghost" aria-pressed={s.id === service} onClick={() => setService(s.id === service ? "" : s.id)}>
                          {s.id === service ? "Все пользователи" : "Пользователи сервиса"}
                        </Button>
                        {canManage && (
                          <Button variant="ghost" aria-label={`Исключить сервис ${s.name}`} onClick={() => onExclude({ kind: "service", value: s.id, by: "login" })}>
                            Исключить
                          </Button>
                        )}
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>

      <Panel role="region" aria-label="Пользователи" className="flex flex-col gap-2">
        <h2 className="text-lg font-semibold">{service ? `Пользователи сервиса ${serviceName(catalog, service)}` : "Пользователи"}</h2>
        <p className="text-sm text-muted">
          Пользователи показаны псевдонимами, как в событиях шлюза: логины и адреса из журналов не хранятся.
          {canEvents ? " По псевдониму можно открыть события этого пользователя в шлюзе." : ""}
        </p>
        <ErrorBanner error={users.error} />
        {users.data && people.length === 0 && <p className="text-sm text-muted">Пользователей за период нет.</p>}
        {people.length > 0 && (
          <div className="max-h-96 overflow-auto">
            <Table aria-label="Пользователи за период">
              <thead>
                <tr>
                  <Th>Псевдоним</Th>
                  <Th>По чему</Th>
                  <Th className="text-right">Обращений</Th>
                  <Th className="text-right">Объём</Th>
                  <Th>Сервисы</Th>
                  <Th>Последний раз</Th>
                  {(canEvents || canManage) && <Th>Действия</Th>}
                </tr>
              </thead>
              <tbody>
                {people.map((u) => (
                  <tr key={u.alias}>
                    <Td className="font-mono text-sm">{u.alias}</Td>
                    <Td>{userKindTitle.get(u.kind)}</Td>
                    <Td className="text-right">{formatNumber(u.requests)}</Td>
                    <Td className="text-right">{formatBytes(u.bytes)}</Td>
                    <Td>{u.services.map((id) => serviceName(catalog, id)).join(", ")}</Td>
                    <Td>{formatAbsolute(u.last_seen)}</Td>
                    {(canEvents || canManage) && (
                      <Td>
                        <div className="flex flex-wrap items-center gap-2">
                          {canEvents && (
                            <Link
                              className="underline"
                              to={`/events?${new URLSearchParams({ r: "30d", f: userFilter(u.alias) })}`}
                              aria-label={`События пользователя ${u.alias}`}
                            >
                              События
                            </Link>
                          )}
                          {canManage && (
                            <Button variant="ghost" aria-label={`Исключить пользователя ${u.alias}`} onClick={() => onExclude({ kind: "user", value: u.alias, by: "alias" })}>
                              Исключить
                            </Button>
                          )}
                        </div>
                      </Td>
                    )}
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>
    </div>
  );
}

// Экран «Теневой ИИ» (ТЗ 5.12, DM-37; задачи 4.22–4.23): обращения к публичным ИИ-сервисам по журналам прокси и NGFW.
// Права проверяет сервер; консоль только скрывает кнопки управления без shadow_ai.manage.
export function ShadowAIScreen({ me }: { me: Me }) {
  const canManage = me.permissions.includes("shadow_ai.manage");
  const mfa = me.mfa?.enabled === true;
  const catalog = useQuery({ queryKey: ["shadow-ai", "catalog"], queryFn: ({ signal }) => shadowApi.catalog(signal) });
  const settings = useQuery({ queryKey: ["shadow-ai", "settings"], queryFn: ({ signal }) => shadowApi.settings(signal) });
  const syslog = useQuery({ queryKey: ["shadow-ai", "syslog"], queryFn: ({ signal }) => shadowApi.syslog(signal), refetchInterval: 30_000 });
  const [draft, setDraft] = useState<ExclusionDraft | null>(null);
  const c = catalog.data;
  const pseudonymized = settings.data?.users_pseudonymized ?? true;

  return (
    <section aria-label="Теневой ИИ" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">Теневой ИИ</h1>
        <p className="text-sm text-muted">
          Обращения сотрудников к публичным ИИ-сервисам в обход шлюза — по журналам прокси и NGFW.
          {settings.data ? ` Сводки хранятся ${formatNumber(settings.data.retention_days)} суток.` : ""}
        </p>
      </div>
      <ErrorBanner error={catalog.error ?? settings.error} />
      {c && !c.loaded && <Banner kind="warning">Каталог ИИ-сервисов не загружен: обращения не с чем сопоставить. Загрузите его на вкладке «Импорт и каталог».</Banner>}
      {settings.data && !pseudonymized && (
        <Banner kind="info">Серверу не задан ключ псевдонимов пользователей: учитываются только сервисы, без пользователей.</Banner>
      )}
      <TabBar
        label="Разделы теневого ИИ"
        defaultValue="overview"
        tabs={[
          { value: "overview", title: "Сервисы и пользователи", content: <OverviewTab me={me} catalog={c} canManage={canManage} onExclude={setDraft} /> },
          { value: "import", title: "Импорт и каталог", content: <ImportTab canManage={canManage} catalog={c} /> },
          {
            value: "exclusions",
            title: "Исключения",
            content: <ExclusionsTab canManage={canManage} catalog={c} mfa={mfa} usersPseudonymized={pseudonymized} />,
          },
          {
            value: "syslog",
            title: "Приём по syslog",
            content: (
              <Panel role="region" aria-label="Приём по syslog" className="flex flex-col gap-2">
                <ErrorBanner error={syslog.error} />
                {syslog.data ? <SyslogPanel s={syslog.data} /> : !syslog.isError && <p className="text-sm text-muted">Загрузка состояния…</p>}
              </Panel>
            ),
          },
        ]}
      />
      {draft && <ExclusionDialog key={`${draft.kind}:${draft.value}`} draft={draft} onClose={() => setDraft(null)} catalog={c} mfa={mfa} usersPseudonymized={pseudonymized} />}
    </section>
  );
}
