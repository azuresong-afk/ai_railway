import { useState } from "react";
import { Link } from "react-router";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { SeverityBadge } from "../ui/Badge";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import type { Severity } from "../ui/icons";
import { Field, Select } from "../ui/Field";
import { type AppDashboard, type DashFeedItem, type DashPeriodInfo, type Overview, type Period, type Pii, type Threats, useAttention, useDashboard } from "./api";
import { barsOption, ChartCard, decisionsOption, decisionsRows, heatmapOption, linesOption, linesRows } from "./charts";
import { actionTitle, decisionFilter, eventsUrl, num, percent, rub, weekdays } from "./format";
import { PeriodBar } from "./PeriodBar";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { appsApi } from "../apps/api";

const sevOf = (s: string): Severity => (["critical", "high", "medium", "low", "info"].includes(s) ? (s as Severity) : "info");

// Показатель-плитка: подпись и крупное значение.
export function Stat({ title, value, hint }: { title: string; value: string; hint?: string }) {
  return (
    <Panel className="flex min-w-0 flex-col gap-1">
      <span className="text-sm text-muted">{title}</span>
      <span className="text-2xl font-semibold">{value}</span>
      {hint && <span className="text-xs text-muted">{hint}</span>}
    </Panel>
  );
}

export function PeriodNote({ period }: { period: DashPeriodInfo }) {
  return (
    <>
      {!period.aggregates_ready && (
        <Banner kind="info">Идёт досчёт показателей за прошлые периоды: цифры за давние сроки могут быть неполными.</Banner>
      )}
      <p className="text-xs text-muted">
        {formatAbsolute(period.from)} — {formatAbsolute(period.to)}, шаг: {period.unit === "minute" ? "минута" : period.unit === "hour" ? "час" : "сутки"}.
      </p>
    </>
  );
}

// Общая обвязка экрана: период, режим реального времени, ошибка и ожидание.
export function useScreen<T>(name: Parameters<typeof useDashboard>[0], appId?: string) {
  const [period, setPeriod] = useState<Period>({ name: "24h" });
  const [live, setLive] = useState(false);
  const q = useDashboard<T>(name, appId, period, { live });
  return { period, setPeriod, live, setLive, q };
}

export function Bar({ s }: { s: ReturnType<typeof useScreen> }) {
  return <PeriodBar period={s.period} onPeriod={s.setPeriod} live={s.live} onLive={s.setLive} liveState={s.q.live} />;
}

// «Лента решений» (ТЗ 6.4): метаданные без содержимого; карточка события открывается по ссылке.
export function Feed({ items, period }: { items: DashFeedItem[]; period: string }) {
  if (items.length === 0) return <p className="py-4 text-sm text-muted">Решений за период нет.</p>;
  return (
    <Table aria-label="Лента решений">
      <thead>
        <tr>
          <Th>Время</Th>
          <Th>Приложение</Th>
          <Th>Модель</Th>
          <Th>Решение</Th>
          <Th>Серьёзность</Th>
          <Th>Правило</Th>
        </tr>
      </thead>
      <tbody>
        {items.map((f) => (
          <tr key={f.id}>
            <Td>
              <Link className="text-accent underline" to={`/events?${new URLSearchParams({ r: period === "30d" || period === "7d" ? period : "24h", event: f.id })}`}>
                {formatAbsolute(f.time)}
              </Link>
            </Td>
            <Td>{f.app}</Td>
            <Td>{f.model || "—"}</Td>
            <Td>
              {actionTitle.get(f.action) ?? f.action}
              {f.policy_mode === "monitor" && f.action === "block" ? " (мониторинг)" : ""}
            </Td>
            <Td>
              <SeverityBadge level={sevOf(f.severity)} />
            </Td>
            <Td>{f.rule || "—"}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function Attention({ me }: { me: Me }) {
  const a = useAttention(me.permissions);
  const offline = a.gateways.data?.gateways.filter((g) => g.state === "offline") ?? [];
  const alerts = a.alerts.data?.items ?? [];
  const incidents = a.incidents.data?.items ?? [];
  if (alerts.length + incidents.length + offline.length === 0) return null;
  return (
    <Panel className="flex flex-col gap-2" aria-label="Требует внимания">
      <h3 className="text-md font-semibold">Требует внимания</h3>
      <ul className="flex flex-col gap-1 text-base">
        {alerts.map((x) => (
          <li key={x.id}>
            <Link className="text-accent underline" to="/alerts">
              Критическое оповещение: {x.title}
            </Link>
          </li>
        ))}
        {incidents.map((x) => (
          <li key={x.id}>
            <Link className="text-accent underline" to="/incidents">
              Инцидент №{x.number}: {x.title}
              {x.overdue ? " — срок реакции истёк" : ""}
            </Link>
          </li>
        ))}
        {offline.map((g) => (
          <li key={g.id}>
            <Link className="text-accent underline" to="/system">
              Шлюз «{g.name}» не в сети
            </Link>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Totals({ t, latency }: { t: Overview["totals"]; latency?: Overview["latency"] }) {
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(11rem,1fr))] gap-3">
      <Stat title="Запросов" value={num(t.requests)} />
      <Stat title="С находками" value={num(t.with_findings)} hint={t.requests ? percent(t.with_findings / t.requests) : undefined} />
      <Stat title="Заблокировано" value={num(t.blocked)} />
      <Stat title="Заблокировало бы" value={num(t.would_block)} hint="режим мониторинга" />
      <Stat title="Замаскировано" value={num(t.masked)} />
      <Stat title="Токенов" value={num(t.tokens_prompt + t.tokens_completion)} />
      <Stat title="Стоимость" value={rub(t.cost)} hint={t.unpriced_requests ? `без цены: ${num(t.unpriced_requests)} запр.` : undefined} />
      {latency && (
        <Stat
          title="Задержка шлюза, p95"
          value={latency.p95_ms === 0 ? "нет данных" : latency.overflow ? "больше 5 с" : `до ${num(latency.p95_ms)} мс`}
        />
      )}
    </div>
  );
}

export function OverviewScreen({ me }: { me: Me }) {
  const s = useScreen<Overview>("overview");
  const nav = useNavigate();
  const d = s.q.data;
  return (
    <div className="flex flex-col gap-4">
      <Bar s={s} />
      <ErrorBanner error={s.q.error} />
      {d && (
        <>
          <PeriodNote period={d.period} />
          <Attention me={me} />
          <Totals t={d.totals} latency={d.latency} />
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <ChartCard
              title="Запросы по решениям"
              label="Столбцы: запросы по решениям политики во времени"
              option={decisionsOption(d.decisions, d.period)}
              head={decisionsRows(d.decisions, d.period)[0]}
              rows={decisionsRows(d.decisions, d.period)[1]}
              empty={d.decisions.length === 0}
              onPick={(p) => {
                const key = [...decisionFilter.keys()].find((k) => p.seriesName === (k === "allowed" ? "Пропущено" : k === "masked" ? "Замаскировано" : k === "blocked" ? "Заблокировано" : "Заблокировало бы"));
                if (key) nav(eventsUrl(s.period.name, {}, decisionFilter.get(key)!));
              }}
            />
            <ChartCard
              title="Топ детекторов"
              label="Столбцы: детекторы по числу срабатываний"
              option={barsOption(d.top_detectors)}
              head={["Детектор", "Срабатываний"]}
              rows={d.top_detectors.map((x) => [x.key, x.value])}
              empty={d.top_detectors.length === 0}
              onPick={(p) => p.name && nav(eventsUrl(s.period.name, { detector: p.name }))}
            />
          </div>
          <Panel className="flex flex-col gap-2">
            <h3 className="text-md font-semibold">Приложения по риску</h3>
            {d.apps.length === 0 ? (
              <p className="text-sm text-muted">Нет данных за выбранный период.</p>
            ) : (
              <Table aria-label="Приложения по риску">
                <thead>
                  <tr>
                    <Th>Приложение</Th>
                    <Th className="text-right">Запросов</Th>
                    <Th className="text-right">С находками</Th>
                    <Th className="text-right">Заблокировано</Th>
                    <Th className="text-right">Замаскировано</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.apps.map((a) => (
                    <tr key={a.key}>
                      <Td>
                        <Link className="text-accent underline" to={eventsUrl(s.period.name, { app: a.key })}>
                          {a.key || "не указано"}
                        </Link>
                      </Td>
                      <Td className="text-right">{num(a.requests)}</Td>
                      <Td className="text-right">{num(a.with_findings)}</Td>
                      <Td className="text-right">{num(a.blocked)}</Td>
                      <Td className="text-right">{num(a.masked)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Panel>
          <Panel className="flex flex-col gap-2">
            <h3 className="text-md font-semibold">Лента решений</h3>
            <Feed items={d.feed} period={s.period.name} />
          </Panel>
        </>
      )}
    </div>
  );
}

export function ThreatsScreen() {
  const s = useScreen<Threats>("threats");
  const nav = useNavigate();
  const d = s.q.data;
  return (
    <div className="flex flex-col gap-4">
      <Bar s={s} />
      <ErrorBanner error={s.q.error} />
      {d && (
        <>
          <PeriodNote period={d.period} />
          <div className="grid grid-cols-[repeat(auto-fit,minmax(11rem,1fr))] gap-3">
            <Stat title="Запросов с находками" value={num(d.totals.with_findings)} />
            <Stat
              title="Нетекстовое не проверено"
              value={percent(d.non_text_unchecked_share)}
              hint={`${num(d.totals.non_text_unchecked)} запр. — изображения и аудио этап 3 не разбирает`}
            />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <ChartCard
              title="Угрозы по строкам матрицы"
              label="Линии: срабатывания по строкам матрицы обнаружения во времени"
              option={linesOption(d.by_threat, d.period)}
              head={linesRows(d.by_threat, d.period)[0]}
              rows={linesRows(d.by_threat, d.period)[1]}
              empty={d.by_threat.length === 0}
              onPick={(p) => p.seriesName && nav(eventsUrl(s.period.name, { threat: p.seriesName }))}
            />
            <ChartCard
              title="Категории находок"
              label="Линии: находки по категориям во времени"
              option={linesOption(d.by_category, d.period)}
              head={linesRows(d.by_category, d.period)[0]}
              rows={linesRows(d.by_category, d.period)[1]}
              empty={d.by_category.length === 0}
            />
            <ChartCard
              title="Детекторы"
              label="Линии: срабатывания детекторов во времени"
              option={linesOption(d.by_detector, d.period)}
              head={linesRows(d.by_detector, d.period)[0]}
              rows={linesRows(d.by_detector, d.period)[1]}
              empty={d.by_detector.length === 0}
              onPick={(p) => p.seriesName && nav(eventsUrl(s.period.name, { detector: p.seriesName }))}
            />
            <ChartCard
              title="Тепловая карта: день недели и час"
              label="Тепловая карта: число находок по дням недели и часам суток"
              option={heatmapOption(d.heatmap)}
              head={["День", "Час", "Находок"]}
              rows={d.heatmap.map((c) => [weekdays[c.weekday - 1] ?? String(c.weekday), c.hour, c.findings])}
              empty={d.heatmap.length === 0}
              height={280}
            />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <ChartCard
              title="Топ угроз"
              label="Столбцы: угрозы по числу срабатываний"
              option={barsOption(d.top_threats)}
              head={["Угроза", "Срабатываний"]}
              rows={d.top_threats.map((x) => [x.key, x.value])}
              empty={d.top_threats.length === 0}
              onPick={(p) => p.name && nav(eventsUrl(s.period.name, { threat: p.name }))}
            />
            <ChartCard
              title="Топ категорий"
              label="Столбцы: категории находок"
              option={barsOption(d.top_categories)}
              head={["Категория", "Находок"]}
              rows={d.top_categories.map((x) => [x.key, x.value])}
              empty={d.top_categories.length === 0}
            />
            <ChartCard
              title="Топ детекторов"
              label="Столбцы: детекторы по числу срабатываний"
              option={barsOption(d.top_detectors)}
              head={["Детектор", "Срабатываний"]}
              rows={d.top_detectors.map((x) => [x.key, x.value])}
              empty={d.top_detectors.length === 0}
              onPick={(p) => p.name && nav(eventsUrl(s.period.name, { detector: p.name }))}
            />
          </div>
        </>
      )}
    </div>
  );
}

export function PiiScreen() {
  const s = useScreen<Pii>("pii");
  const d = s.q.data;
  return (
    <div className="flex flex-col gap-4">
      <Bar s={s} />
      <ErrorBanner error={s.q.error} />
      {d && (
        <>
          <PeriodNote period={d.period} />
          <Stat title="Находок ПДн" value={num(d.findings)} />
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <ChartCard
              title="Типы ПДн"
              label="Столбцы: находки по типам персональных данных"
              option={barsOption(d.types)}
              head={["Тип", "Находок"]}
              rows={d.types.map((x) => [x.key, x.value])}
              empty={d.types.length === 0}
            />
            <ChartCard
              title="Находки ПДн во времени"
              label="Линии: находки по типам персональных данных во времени"
              option={linesOption(d.series, d.period)}
              head={linesRows(d.series, d.period)[0]}
              rows={linesRows(d.series, d.period)[1]}
              empty={d.series.length === 0}
            />
          </div>
          <Panel className="flex flex-col gap-2">
            <h3 className="text-md font-semibold">Тип, приложение и действие</h3>
            {d.rows.length === 0 ? (
              <p className="text-sm text-muted">Нет данных за выбранный период.</p>
            ) : (
              <Table aria-label="ПДн по приложениям и действиям">
                <thead>
                  <tr>
                    <Th>Тип</Th>
                    <Th>Приложение</Th>
                    <Th>Действие</Th>
                    <Th className="text-right">Находок</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.rows.map((r, i) => (
                    <tr key={i}>
                      <Td>{r.category}</Td>
                      <Td>{r.app || "не указано"}</Td>
                      <Td>{actionTitle.get(r.action) ?? r.action}</Td>
                      <Td className="text-right">{num(r.findings)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}

// Мини-дашборд приложения. Список приложений — из API приложений (только доступные пользователю).
export function AppScreen() {
  const apps = useQuery({
    queryKey: ["dash", "apps"],
    queryFn: ({ signal }) => appsApi.applications(signal),
  });
  const [appId, setAppId] = useState("");
  const s = useScreen<AppDashboard>("app", appId || undefined);
  const nav = useNavigate();
  const d = s.q.data;
  const list = apps.data?.filter((a) => a.status !== "archived") ?? [];
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Приложение">
          {({ id }) => (
            <Select id={id} value={appId} onChange={(e) => setAppId(e.target.value)}>
              <option value="">Выберите приложение</option>
              {list.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <ErrorBanner error={apps.error} />
      {!appId ? (
        <EmptyState title="Выберите приложение" action={<p className="text-sm text-muted">Покажем его запросы, решения политики, модели и ленту решений.</p>} />
      ) : (
        <>
          <Bar s={s} />
          <ErrorBanner error={s.q.error} />
          {d && (
            <>
              <PeriodNote period={d.period} />
              <Totals t={d.totals} latency={d.latency} />
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                <ChartCard
                  title="Запросы по решениям"
                  label="Столбцы: запросы приложения по решениям политики во времени"
                  option={decisionsOption(d.decisions, d.period)}
                  head={decisionsRows(d.decisions, d.period)[0]}
                  rows={decisionsRows(d.decisions, d.period)[1]}
                  empty={d.decisions.length === 0}
                />
                <ChartCard
                  title="Топ детекторов"
                  label="Столбцы: детекторы по числу срабатываний"
                  option={barsOption(d.top_detectors)}
                  head={["Детектор", "Срабатываний"]}
                  rows={d.top_detectors.map((x) => [x.key, x.value])}
                  empty={d.top_detectors.length === 0}
                  onPick={(p) => p.name && nav(eventsUrl(s.period.name, { app: d.application.slug, detector: p.name }))}
                />
              </div>
              <Panel className="flex flex-col gap-2">
                <h3 className="text-md font-semibold">Модели</h3>
                {d.models.length === 0 ? (
                  <p className="text-sm text-muted">Нет данных за выбранный период.</p>
                ) : (
                  <Table aria-label="Модели приложения">
                    <thead>
                      <tr>
                        <Th>Модель</Th>
                        <Th className="text-right">Запросов</Th>
                        <Th className="text-right">Токенов</Th>
                        <Th className="text-right">Стоимость</Th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.models.map((m) => (
                        <tr key={m.key}>
                          <Td>{m.key || "не указано"}</Td>
                          <Td className="text-right">{num(m.requests)}</Td>
                          <Td className="text-right">{num(m.tokens_prompt + m.tokens_completion)}</Td>
                          <Td className="text-right">{m.unpriced_requests > 0 && m.cost === "0.0000000" ? "не определена" : rub(m.cost)}</Td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                )}
              </Panel>
              <Panel className="flex flex-col gap-2">
                <h3 className="text-md font-semibold">Лента решений</h3>
                <Feed items={d.feed} period={s.period.name} />
              </Panel>
            </>
          )}
        </>
      )}
    </div>
  );
}
