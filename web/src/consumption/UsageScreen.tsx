import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ConfirmDialog, ErrorBanner, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { appsApi } from "../apps/api";
import { Bar, PeriodNote, Stat, useScreen } from "../dashboards/screens";
import { ChartCard } from "../dashboards/charts";
import { token } from "../dashboards/Chart";
import { bucketLabel, num, rub } from "../dashboards/format";
import type { Consumption, DashRequestRow } from "../dashboards/api";
import { providersApi } from "../providers/api";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { type BudgetStatus, validBudget, type ModelPrice, validPrice, usageApi } from "./api";

const costText = (r: { cost: string; unpriced_requests: number }): string =>
  r.unpriced_requests > 0 && Number(r.cost) === 0 ? "не определена" : rub(r.cost) + (r.unpriced_requests > 0 ? " *" : "");

function RowsTable({ title, keyTitle, rows }: { title: string; keyTitle: string; rows: DashRequestRow[] }) {
  if (rows.length === 0) return <p className="py-4 text-sm text-muted">Нет данных за выбранный период.</p>;
  return (
    <Table aria-label={title}>
      <thead>
        <tr>
          <Th>{keyTitle}</Th>
          <Th className="text-right">Запросов</Th>
          <Th className="text-right">Токенов входа</Th>
          <Th className="text-right">Токенов выхода</Th>
          <Th className="text-right">Стоимость</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <Td>{r.key || "не указано"}</Td>
            <Td className="text-right">{num(r.requests)}</Td>
            <Td className="text-right">{num(r.tokens_prompt)}</Td>
            <Td className="text-right">{num(r.tokens_completion)}</Td>
            <Td className="text-right">{costText(r)}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function BudgetBar({ b }: { b: BudgetStatus }) {
  if (!b.budget) return <span className="text-muted">Бюджет не задан</span>;
  const p = Math.min(100, b.percent);
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-32 rounded-control bg-surface-hover" role="img" aria-label={`Расход ${b.percent} % бюджета`}>
        <div className={`h-2 rounded-control ${b.exhausted ? "bg-sev-critical" : b.percent >= 80 ? "bg-sev-medium" : "bg-accent"}`} style={{ width: `${p}%` }} />
      </div>
      <span>
        {b.percent} %{b.exhausted ? " — исчерпан" : ""}
      </span>
    </div>
  );
}

function ConsumptionTab({ canBudgets }: { canBudgets: boolean }) {
  const s = useScreen<Consumption>("consumption");
  const [dim, setDim] = useState("app");
  const d = s.q.data;
  const dims: [string, string, string, DashRequestRow[] | undefined][] = [
    ["app", "Приложения", "Приложение", d?.by_app],
    ["model", "Модели", "Модель", d?.by_model],
    ["user", "Пользователи", "Пользователь (псевдоним)", d?.by_user],
    ["department", "Подразделения", "Подразделение", d?.by_department],
  ];
  const cur = dims.find((x) => x[0] === dim)!;
  const series = d?.series ?? [];
  const seriesOption = {
    tooltip: { trigger: "axis" },
    legend: { data: ["Запросы", "Токены"], textStyle: { color: token("--c-text-muted") } },
    grid: { left: 56, right: 56, top: 32, bottom: 28 },
    xAxis: { type: "category", data: series.map((x) => bucketLabel(x.bucket, d?.period.unit ?? "hour")) },
    yAxis: [{ type: "value", name: "запросы" }, { type: "value", name: "токены" }],
    series: [
      { name: "Запросы", type: "bar", data: series.map((x) => x.requests) },
      { name: "Токены", type: "line", yAxisIndex: 1, showSymbol: false, data: series.map((x) => x.tokens) },
    ],
  };
  return (
    <div className="flex flex-col gap-4">
      <Bar s={s} />
      <ErrorBanner error={s.q.error} />
      {d && (
        <>
          <PeriodNote period={d.period} />
          <div className="grid grid-cols-[repeat(auto-fit,minmax(11rem,1fr))] gap-3">
            <Stat title="Запросов" value={num(d.totals.requests)} />
            <Stat title="Токенов входа" value={num(d.totals.tokens_prompt)} />
            <Stat title="Токенов выхода" value={num(d.totals.tokens_completion)} />
            <Stat
              title="Стоимость"
              value={rub(d.totals.cost)}
              hint={d.totals.unpriced_requests ? `без цены: ${num(d.totals.unpriced_requests)} запр. — стоимость не определена` : undefined}
            />
            <Stat
              title={`Прогноз на ${d.forecast.month}`}
              value={d.forecast.enough ? rub(d.forecast.projected) : "мало данных"}
              hint={`Расход с начала месяца: ${rub(d.forecast.spent)}. Линейный прогноз, нужны сутки месяца и расход.`}
            />
          </div>
          <ChartCard
            title="Запросы и токены во времени"
            label="Столбцы и линия: запросы и токены во времени"
            option={seriesOption}
            head={["Время", "Запросов", "Токенов", "Стоимость"]}
            rows={series.map((x) => [bucketLabel(x.bucket, d.period.unit), x.requests, x.tokens, rub(x.cost)])}
            empty={series.length === 0}
          />
          <Panel className="flex flex-col gap-2">
            <div className="flex items-end justify-between gap-3">
              <h3 className="text-md font-semibold">Потребление по срезам</h3>
              <Field label="Срез">
                {({ id }) => (
                  <Select id={id} value={dim} onChange={(e) => setDim(e.target.value)}>
                    {dims.map(([v, t]) => (
                      <option key={v} value={v}>
                        {t}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            <RowsTable title={`Потребление: ${cur[1]}`} keyTitle={cur[2]} rows={cur[3] ?? []} />
            {d.totals.unpriced_requests > 0 && <p className="text-xs text-muted">* Часть запросов к моделям без цены: их стоимость не определена и в сумму не входит.</p>}
          </Panel>
          {canBudgets && (
            <Panel className="flex flex-col gap-2">
              <h3 className="text-md font-semibold">Исполнение бюджетов за текущий месяц</h3>
              {d.budgets.length === 0 ? (
                <p className="text-sm text-muted">Бюджеты не заданы.</p>
              ) : (
                <Table aria-label="Исполнение бюджетов">
                  <thead>
                    <tr>
                      <Th>Приложение</Th>
                      <Th>Режим</Th>
                      <Th className="text-right">Бюджет</Th>
                      <Th className="text-right">Расход</Th>
                      <Th>Исполнение</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.budgets.map((b) => (
                      <tr key={b.application_id}>
                        <Td>{b.name}</Td>
                        <Td>{b.budget ? (b.budget.mode === "hard" ? "Жёсткий" : "Учёт и оповещения") : "—"}</Td>
                        <Td className="text-right">{b.budget ? rub(b.budget.monthly_limit) : "—"}</Td>
                        <Td className="text-right">{rub(b.spent)}</Td>
                        <Td>
                          <BudgetBar b={b} />
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Panel>
          )}
        </>
      )}
    </div>
  );
}

// Цена модели: провайдер и имя модели неизменны, меняются цены входа и выхода.
function PriceDialog({ price, onClose }: { price: ModelPrice | null; onClose: () => void }) {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers", "list"], queryFn: ({ signal }) => providersApi.list(signal) });
  const [f, setF] = useState({ provider_id: price?.provider_id ?? "", model: price?.model ?? "", input: price?.input_price ?? "", output: price?.output_price ?? "" });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  const errs = {
    provider: !price && f.provider_id === "" ? "Выберите провайдера." : undefined,
    model: !price && (f.model.trim() === "" || f.model.length > 200) ? "Укажите имя модели у провайдера, до 200 знаков." : undefined,
    input: validPrice(f.input) ? undefined : "Рубли за 1 000 токенов, до четырёх знаков после точки, например 0.1500.",
    output: validPrice(f.output) ? undefined : "Рубли за 1 000 токенов, до четырёх знаков после точки, например 0.3000.",
  };
  const bad = Object.values(errs).some(Boolean);
  const m = useMutation({
    mutationFn: () =>
      price
        ? usageApi.updatePrice(price.id, { input_price: f.input, output_price: f.output })
        : usageApi.createPrice({ provider_id: f.provider_id, model: f.model.trim(), input_price: f.input, output_price: f.output }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["usage", "prices"] });
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!bad) m.mutate();
  };
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={price ? `Цена модели ${price.model}` : "Новая цена модели"}
      description="Цена в рублях за 1 000 токенов. Модель без цены не блокируется, но её стоимость считается неопределённой."
    >
      <form onSubmit={submit} className="flex flex-col gap-3">
        {!price && (
          <>
            <Field label="Провайдер" {...(errs.provider && f.provider_id !== "" ? { error: errs.provider } : {})}>
              {({ id }) => (
                <Select id={id} value={f.provider_id} onChange={set("provider_id")}>
                  <option value="">Выберите провайдера</option>
                  {providers.data?.items.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Модель" hint="Имя у провайдера, после псевдонимов приложения.">
              {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={200} value={f.model} onChange={set("model")} />}
            </Field>
          </>
        )}
        <Field label="Цена входа, ₽ за 1 000 токенов" {...(f.input !== "" && errs.input ? { error: errs.input } : {})}>
          {({ id, invalid }) => <Input id={id} aria-invalid={invalid} inputMode="decimal" value={f.input} onChange={set("input")} />}
        </Field>
        <Field label="Цена выхода, ₽ за 1 000 токенов" {...(f.output !== "" && errs.output ? { error: errs.output } : {})}>
          {({ id, invalid }) => <Input id={id} aria-invalid={invalid} inputMode="decimal" value={f.output} onChange={set("output")} />}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || bad}>
            {price ? "Сохранить цену" : "Задать цену"}
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function PricesTab({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["usage", "prices"], queryFn: ({ signal }) => usageApi.prices(signal) });
  const providers = useQuery({ queryKey: ["providers", "list"], queryFn: ({ signal }) => providersApi.list(signal), retry: false });
  const name = new Map(providers.data?.items.map((p) => [p.id, p.name]));
  const [edit, setEdit] = useState<{ price: ModelPrice | null }>();
  const [del, setDel] = useState<ModelPrice>();
  const delM = useMutation({
    mutationFn: (p: ModelPrice) => usageApi.removePrice(p.id),
    onSuccess: async () => {
      setDel(undefined);
      await qc.invalidateQueries({ queryKey: ["usage", "prices"] });
    },
  });
  const items = q.data?.items ?? [];
  return (
    <section aria-label="Цены моделей" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted">Цены в рублях за 1 000 токенов; по ним считаются стоимость и бюджеты.</p>
        {canManage && (
          <Button variant="primary" onClick={() => setEdit({ price: null })}>
            Задать цену модели
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.isSuccess && items.length === 0 ? (
        <EmptyState title="Цены моделей не заданы" action={<p className="text-sm text-muted">Без цен стоимость запросов не определена, бюджеты не считаются.</p>} />
      ) : (
        items.length > 0 && (
          <Table aria-label="Цены моделей">
            <thead>
              <tr>
                <Th>Провайдер</Th>
                <Th>Модель</Th>
                <Th className="text-right">Вход, ₽/1 000</Th>
                <Th className="text-right">Выход, ₽/1 000</Th>
                {canManage && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.id}>
                  <Td>{name.get(p.provider_id) ?? p.provider_id}</Td>
                  <Td>{p.model}</Td>
                  <Td className="text-right">{p.input_price}</Td>
                  <Td className="text-right">{p.output_price}</Td>
                  {canManage && (
                    <Td>
                      <div className="flex gap-1">
                        <Button variant="ghost" aria-label={`Изменить цену ${p.model}`} onClick={() => setEdit({ price: p })}>
                          Изменить
                        </Button>
                        <Button variant="ghost" aria-label={`Удалить цену ${p.model}`} onClick={() => setDel(p)}>
                          Удалить
                        </Button>
                      </div>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )
      )}
      {edit && <PriceDialog price={edit.price} onClose={() => setEdit(undefined)} />}
      {del && (
        <ConfirmDialog
          open
          onOpenChange={(v) => !v && setDel(undefined)}
          title={`Удалить цену ${del.model}?`}
          description="Стоимость запросов к этой модели станет неопределённой, расход по ней перестанет входить в бюджеты."
          actionLabel="Удалить цену"
          busy={delM.isPending}
          error={delM.error}
          onConfirm={() => delM.mutate(del)}
        />
      )}
    </section>
  );
}

// Бюджет приложения: месячный лимит в рублях и режим. Жёсткий бюджет отклоняет запросы после исчерпания.
function BudgetDialog({ target, onClose }: { target: { id: string; name: string; budget: BudgetStatus["budget"] }; onClose: () => void }) {
  const qc = useQueryClient();
  const [limit, setLimit] = useState(target.budget?.monthly_limit.replace(/\.?0+$/, "") ?? "");
  const [mode, setMode] = useState<"soft" | "hard">(target.budget?.mode ?? "soft");
  const ok = validBudget(limit) && Number(limit) >= 0.01 && Number(limit) <= 1_000_000_000;
  const m = useMutation({
    mutationFn: () => usageApi.setBudget(target.id, { mode, monthly_limit: limit }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["usage", "budgets"] });
      onClose();
    },
  });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Бюджет: ${target.name}`} description="Расход считается по ценам моделей за календарный месяц в часовом поясе установки.">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) m.mutate();
        }}
        className="flex flex-col gap-3"
      >
        <Field label="Бюджет в месяц, ₽" {...(limit !== "" && !ok ? { error: "От 0.01 до 1 000 000 000 ₽, до двух знаков после точки." } : {})}>
          {({ id, invalid }) => <Input id={id} aria-invalid={invalid} inputMode="decimal" value={limit} onChange={(e) => setLimit(e.target.value)} />}
        </Field>
        <Field label="Режим">
          {({ id }) => (
            <Select id={id} value={mode} onChange={(e) => setMode(e.target.value as "soft" | "hard")}>
              <option value="soft">Учёт и оповещения (80 % и 100 %)</option>
              <option value="hard">Жёсткий: запросы отклоняются после исчерпания</option>
            </Select>
          )}
        </Field>
        {mode === "hard" && <Banner kind="warning">Когда расход достигнет бюджета, шлюз начнёт отвечать приложению отказом 429 до начала следующего месяца.</Banner>}
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || !ok}>
            Сохранить бюджет
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function BudgetsTab({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["usage", "budgets"], queryFn: ({ signal }) => usageApi.budgets(signal) });
  const apps = useQuery({ queryKey: ["usage", "apps"], queryFn: ({ signal }) => appsApi.applications(signal), enabled: canManage });
  const [edit, setEdit] = useState<{ id: string; name: string; budget: BudgetStatus["budget"] }>();
  const [del, setDel] = useState<BudgetStatus>();
  const [pick, setPick] = useState("");
  const delM = useMutation({
    mutationFn: (b: BudgetStatus) => usageApi.removeBudget(b.application_id),
    onSuccess: async () => {
      setDel(undefined);
      await qc.invalidateQueries({ queryKey: ["usage", "budgets"] });
    },
  });
  const items = q.data?.items ?? [];
  const withBudget = new Set(items.filter((b) => b.budget).map((b) => b.application_id));
  const free = (apps.data ?? []).filter((a) => a.status !== "archived" && !withBudget.has(a.id));
  return (
    <section aria-label="Бюджеты приложений" className="flex flex-col gap-3">
      <p className="text-sm text-muted">Месяц: {q.data?.month ?? "—"}. Расход обновляется с задержкой до периода heartbeat шлюзов.</p>
      {canManage && free.length > 0 && (
        <div className="flex items-end gap-3">
          <Field label="Приложение без бюджета">
            {({ id }) => (
              <Select id={id} value={pick} onChange={(e) => setPick(e.target.value)}>
                <option value="">Выберите приложение</option>
                {free.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Button
            variant="primary"
            disabled={pick === ""}
            onClick={() => {
              const a = free.find((x) => x.id === pick);
              if (a) setEdit({ id: a.id, name: a.name, budget: null });
            }}
          >
            Задать бюджет
          </Button>
        </div>
      )}
      <ErrorBanner error={q.error} />
      {q.isSuccess && items.length === 0 ? (
        <EmptyState title="Бюджеты не заданы" action={<p className="text-sm text-muted">Задайте месячный бюджет приложению, чтобы получать оповещения о расходе.</p>} />
      ) : (
        items.length > 0 && (
          <Table aria-label="Бюджеты приложений">
            <thead>
              <tr>
                <Th>Приложение</Th>
                <Th>Режим</Th>
                <Th className="text-right">Бюджет</Th>
                <Th className="text-right">Расход</Th>
                <Th>Исполнение</Th>
                {canManage && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {items.map((b) => (
                <tr key={b.application_id}>
                  <Td>{b.name}</Td>
                  <Td>{b.budget ? (b.budget.mode === "hard" ? "Жёсткий" : "Учёт и оповещения") : "—"}</Td>
                  <Td className="text-right">{b.budget ? rub(b.budget.monthly_limit) : "—"}</Td>
                  <Td className="text-right">
                    {rub(b.spent)}
                    {b.unpriced_requests > 0 ? ` (без цены: ${num(b.unpriced_requests)} запр.)` : ""}
                  </Td>
                  <Td>
                    <BudgetBar b={b} />
                  </Td>
                  {canManage && (
                    <Td>
                      <div className="flex gap-1">
                        <Button variant="ghost" aria-label={`Изменить бюджет ${b.name}`} onClick={() => setEdit({ id: b.application_id, name: b.name, budget: b.budget })}>
                          Изменить
                        </Button>
                        {b.budget && (
                          <Button variant="ghost" aria-label={`Снять бюджет ${b.name}`} onClick={() => setDel(b)}>
                            Снять
                          </Button>
                        )}
                      </div>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )
      )}
      {edit && <BudgetDialog target={edit} onClose={() => { setEdit(undefined); setPick(""); }} />}
      {del && (
        <ConfirmDialog
          open
          onOpenChange={(v) => !v && setDel(undefined)}
          title={`Снять бюджет ${del.name}?`}
          description="Расход продолжит учитываться, но оповещения и ограничение по бюджету перестанут действовать."
          actionLabel="Снять бюджет"
          busy={delM.isPending}
          error={delM.error}
          onConfirm={() => delM.mutate(del)}
        />
      )}
    </section>
  );
}

// Экран «Потребление» (ТЗ 5.8, 6.4): расход, цены моделей и бюджеты. Вкладки и кнопки видны по правам из сессии,
// решение о доступе принимает сервер.
export function UsageScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const tabs = [
    { value: "usage", title: "Потребление", content: <ConsumptionTab canBudgets={has("budgets.read")} /> },
    ...(has("model_prices.read") ? [{ value: "prices", title: "Цены моделей", content: <PricesTab canManage={has("model_prices.manage")} /> }] : []),
    ...(has("budgets.read") ? [{ value: "budgets", title: "Бюджеты", content: <BudgetsTab canManage={has("budgets.manage")} /> }] : []),
  ];
  return (
    <div className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Потребление</h1>
      <TabBar label="Потребление" tabs={tabs} defaultValue="usage" />
    </div>
  );
}
