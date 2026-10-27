import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, type Me } from "../api/client";
import { appsApi } from "../apps/api";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, TabBar, Table, Td, Th } from "../ui/Layout";
import { frequencyTitles, type ReportKind, type ReportSchedule, type ReportScheduleInput, reportKinds, reportsApi, reportUrl, weekdayTitles } from "./api";

const errText = (e: unknown) => (e instanceof ApiError ? e.detail : "Не удалось выполнить действие. Повторите позже.");
const reportTitle = new Map<string, string>(reportKinds);
const runStatus = new Map<string, string>([
  ["pending", "ждёт отправки"],
  ["sent", "отправлено"],
  ["failed", "не доставлено"],
]);

function fmt(iso: string | undefined, tz: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("ru-RU", { timeZone: tz });
}

// Ссылка-скачивание в виде кнопки; недоступная показывается неактивной кнопкой.
function DownloadLink({ href, disabled, children }: { href: string; disabled: boolean; children: string }) {
  if (disabled) return <Button disabled>{children}</Button>;
  return (
    <a
      href={href}
      download
      className="inline-flex h-[var(--control-h)] items-center justify-center rounded-control border border-line-strong bg-surface px-3 text-base font-medium text-fg hover:bg-surface-hover"
    >
      {children}
    </a>
  );
}

// Отчёты за период: предпросмотр страницы для печати, выгрузка CSV и XLSX (ТЗ 5.8, S10).
function ReportsTab({ me }: { me: Me }) {
  const [kind, setKind] = useState<ReportKind>("summary");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [app, setApp] = useState("");
  const [delimiter, setDelimiter] = useState<"semicolon" | "comma">("semicolon");
  const [preview, setPreview] = useState("");
  // Владелец приложения (reports.read только на свои объекты) получает только сводный отчёт по своему приложению.
  const full = !(me.own_scope ?? []).includes("reports.read");
  const apps = useQuery({ queryKey: ["reports-apps"], queryFn: ({ signal }) => appsApi.applications(signal), enabled: me.permissions.includes("applications.read") });
  const bad =
    (from === "") !== (to === "")
      ? "Укажите обе даты или оставьте обе пустыми."
      : from !== "" && from > to
        ? "Начало периода не может быть позже конца."
        : undefined;
  const blocked = Boolean(bad) || (!full && app === "");
  const appArg = kind === "summary" ? app : "";
  const kinds = full ? reportKinds : reportKinds.filter(([k]) => k === "summary");
  return (
    <div className="flex flex-col gap-3">
      <Panel className="flex flex-wrap items-end gap-3">
        <Field label="Отчёт">
          {({ id }) => (
            <Select id={id} value={kind} onChange={(e) => setKind(e.target.value as ReportKind)}>
              {kinds.map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="С даты" hint="Пусто — последние 30 суток" error={bad}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} type="date" value={from} aria-describedby={describedBy} aria-invalid={invalid} onChange={(e) => setFrom(e.target.value)} />
          )}
        </Field>
        <Field label="По дату">
          {({ id }) => <Input id={id} type="date" value={to} onChange={(e) => setTo(e.target.value)} />}
        </Field>
        <Field label="Разделитель CSV" hint="Для Excel с русской локалью — точка с запятой">
          {({ id }) => (
            <Select id={id} value={delimiter} onChange={(e) => setDelimiter(e.target.value as "semicolon" | "comma")}>
              <option value="semicolon">Точка с запятой</option>
              <option value="comma">Запятая</option>
            </Select>
          )}
        </Field>
        <Field label="Приложение" hint={kind === "summary" ? undefined : "Только для сводного отчёта"}>
          {({ id }) => (
            <Select id={id} value={app} disabled={kind !== "summary"} onChange={(e) => setApp(e.target.value)}>
              <option value="">Все приложения</option>
              {(apps.data ?? []).map((a) => (
                <option key={a.id} value={a.slug}>
                  {a.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </Panel>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" disabled={blocked} onClick={() => setPreview(reportUrl(kind, "html", from, to, appArg))}>
          Показать отчёт
        </Button>
        <DownloadLink disabled={blocked} href={reportUrl(kind, "csv", from, to, appArg, delimiter)}>
          Скачать CSV
        </DownloadLink>
        <DownloadLink disabled={blocked} href={reportUrl(kind, "xlsx", from, to, appArg)}>
          Скачать XLSX
        </DownloadLink>
        {preview && (
          <a className="inline-flex h-[var(--control-h)] items-center text-base underline" href={preview} target="_blank" rel="noopener noreferrer">
            Открыть для печати в новой вкладке
          </a>
        )}
      </div>
      {!full && app === "" && <p className="text-sm text-muted">Выберите своё приложение: отчёты по остальным вам недоступны.</p>}
      <p className="text-sm text-muted">Каждая выгрузка записывается в журнал аудита. В отчёте нет содержимого запросов и ответов.</p>
      {preview ? (
        // Страница отчёта без скриптов; sandbox без разрешений не даёт ей ничего, кроме показа.
        <iframe title="Предпросмотр отчёта" src={preview} sandbox="" className="h-[70vh] w-full rounded-panel border border-line bg-white" />
      ) : (
        <EmptyState title="Отчёт ещё не открыт" action={<p className="text-sm text-muted">Выберите период и нажмите «Показать отчёт».</p>} />
      )}
    </div>
  );
}

function toInput(s: ReportSchedule): ReportScheduleInput {
  return { name: s.name, report: s.report, frequency: s.frequency, weekday: s.weekday ?? 1, day: s.day ?? 1, at: s.at, format: s.format, channel_id: s.channel_id, enabled: s.enabled, recipient_user_ids: s.recipient_user_ids };
}

const emptyForm: ReportScheduleInput = { name: "", report: "summary", frequency: "weekly", weekday: 1, at: "09:00", format: "xlsx", channel_id: "", enabled: true, recipient_user_ids: [] };

function ScheduleForm({ initial, onDone, onCancel }: { initial?: ReportSchedule; onDone: () => void; onCancel: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState<ReportScheduleInput>(initial ? toInput(initial) : emptyForm);
  const [err, setErr] = useState("");
  const channels = useQuery({ queryKey: ["reports-channels"], queryFn: ({ signal }) => reportsApi.channels(signal) });
  const email = channels.data?.items ?? [];
  const recipients = useQuery({ queryKey: ["reports-recipients"], queryFn: ({ signal }) => reportsApi.recipients(signal) });
  const users = recipients.data?.items ?? [];
  const chosen = f.recipient_user_ids ?? [];
  // Выбранные получатели без адреса, а также те, кого в списке уже нет (деактивированы, потеряли право).
  const noEmail = chosen.filter((uid) => users.find((u) => u.id === uid)?.has_email !== true);
  const toggle = (uid: string, on: boolean) => setF({ ...f, recipient_user_ids: on ? [...chosen, uid] : chosen.filter((x) => x !== uid) });
  const save = useMutation({
    mutationFn: () => {
      // Лишние для периодичности поля не отправляются.
      const body: ReportScheduleInput = { ...f };
      if (f.frequency !== "weekly") delete body.weekday;
      if (f.frequency !== "monthly") delete body.day;
      return initial ? reportsApi.update(initial.id, { ...body, version: initial.version }) : reportsApi.create(body);
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["report-schedules"] });
      onDone();
    },
    onError: (e) => setErr(errText(e)),
  });
  const set = (p: Partial<ReportScheduleInput>) => setF({ ...f, ...p });
  const ready = f.name.trim() !== "" && f.channel_id !== "" && /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(f.at);
  return (
    <Panel className="flex flex-col gap-3">
      <h3 className="text-lg font-semibold">{initial ? "Изменение расписания" : "Новое расписание рассылки"}</h3>
      {err && <Banner kind="error">{err}</Banner>}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Название">{({ id }) => <Input id={id} maxLength={200} value={f.name} onChange={(e) => set({ name: e.target.value })} />}</Field>
        <Field label="Отчёт">
          {({ id }) => (
            <Select id={id} value={f.report} onChange={(e) => set({ report: e.target.value as ReportScheduleInput["report"] })}>
              {reportKinds.map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Периодичность">
          {({ id }) => (
            <Select id={id} value={f.frequency} onChange={(e) => set({ frequency: e.target.value as ReportScheduleInput["frequency"] })}>
              {[...frequencyTitles].map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {f.frequency === "weekly" && (
          <Field label="День недели">
            {({ id }) => (
              <Select id={id} value={f.weekday ?? 1} onChange={(e) => set({ weekday: Number(e.target.value) })}>
                {weekdayTitles.map((t, i) => (
                  <option key={t} value={i + 1}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {f.frequency === "monthly" && (
          <Field label="Число месяца" hint="От 1 до 28">
            {({ id }) => <Input id={id} type="number" min={1} max={28} value={f.day ?? 1} onChange={(e) => set({ day: Number(e.target.value) })} />}
          </Field>
        )}
        <Field label="Время отправки" hint="По часовому поясу установки">
          {({ id }) => <Input id={id} type="time" value={f.at} onChange={(e) => set({ at: e.target.value })} />}
        </Field>
        <Field label="Формат вложения">
          {({ id }) => (
            <Select id={id} value={f.format} onChange={(e) => set({ format: e.target.value as ReportScheduleInput["format"] })}>
              <option value="xlsx">XLSX (таблица)</option>
              <option value="html">HTML (для печати)</option>
            </Select>
          )}
        </Field>
        <Field label="Почтовый канал" hint="Получатели берутся из настроек канала в разделе «Оповещения»">
          {({ id }) => (
            <Select id={id} value={f.channel_id} onChange={(e) => set({ channel_id: e.target.value })}>
              <option value="">Выберите канал</option>
              {email.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <fieldset className="flex flex-col gap-1">
        <legend className="text-sm font-medium">Получатели — пользователи консоли</legend>
        <p className="text-sm text-muted">
          Адрес берётся из учётной записи (карточка пользователя или «Профиль») и добавляется к адресам почтового канала. Пользователь без адреса
          пропускается.
        </p>
        {recipients.isError && <Banner kind="error">{errText(recipients.error)}</Banner>}
        {recipients.isSuccess && users.length === 0 && <p className="text-sm text-muted">Нет пользователей, которым можно слать отчёты.</p>}
        {users.map((u) => (
          <label key={u.id} className="flex items-center gap-2 text-base">
            <input type="checkbox" checked={chosen.includes(u.id)} onChange={(e) => toggle(u.id, e.target.checked)} />
            {u.display_name} ({u.login}){u.has_email ? "" : " — нет e-mail"}
          </label>
        ))}
        {noEmail.length > 0 && recipients.isSuccess && (
          <Banner kind="warning">
            У выбранных получателей без адреса ({noEmail.length}) отчёт не уйдёт. Задайте e-mail в карточке пользователя или попросите сделать это в профиле.
          </Banner>
        )}
      </fieldset>
      {channels.isError && <Banner kind="error">{errText(channels.error)}</Banner>}
      {channels.isSuccess && email.length === 0 && <Banner kind="warning">Нет включённых почтовых каналов с получателями: добавьте канал в разделе «Оповещения».</Banner>}
      <label className="flex items-center gap-2 text-base">
        <input type="checkbox" checked={f.enabled ?? true} onChange={(e) => set({ enabled: e.target.checked })} />
        Рассылка включена
      </label>
      <div className="flex gap-2">
        <Button variant="primary" disabled={!ready || save.isPending} onClick={() => save.mutate()}>
          {initial ? "Сохранить расписание" : "Создать расписание"}
        </Button>
        <Button onClick={onCancel}>Отмена</Button>
      </div>
    </Panel>
  );
}

function SchedulesTab({ me }: { me: Me }) {
  const qc = useQueryClient();
  const manage = me.permissions.includes("reports.schedules.manage");
  const [editing, setEditing] = useState<string>(""); // "" — нет формы, "new" — новое, иначе id
  const [runsFor, setRunsFor] = useState("");
  const [err, setErr] = useState("");
  const list = useQuery({ queryKey: ["report-schedules"], queryFn: ({ signal }) => reportsApi.schedules(signal) });
  const runs = useQuery({ queryKey: ["report-runs", runsFor], queryFn: ({ signal }) => reportsApi.runs(runsFor, signal), enabled: runsFor !== "" });
  const del = useMutation({
    mutationFn: (sid: string) => reportsApi.remove(sid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["report-schedules"] }),
    onError: (e) => setErr(errText(e)),
  });
  const items = list.data?.items ?? [];
  const cur = items.find((s) => s.id === editing);
  return (
    <div className="flex flex-col gap-3">
      {err && <Banner kind="error">{err}</Banner>}
      {list.isError && <Banner kind="error">{errText(list.error)}</Banner>}
      {manage && editing === "" && (
        <div>
          <Button variant="primary" onClick={() => setEditing("new")}>
            Добавить расписание
          </Button>
        </div>
      )}
      {editing === "new" && <ScheduleForm onDone={() => setEditing("")} onCancel={() => setEditing("")} />}
      {cur && <ScheduleForm initial={cur} onDone={() => setEditing("")} onCancel={() => setEditing("")} />}
      {list.isSuccess && items.length === 0 ? (
        <EmptyState title="Расписаний пока нет" action={<p className="text-sm text-muted">Отчёт можно получать на почту: добавьте расписание.</p>} />
      ) : (
        <Table aria-label="Расписания рассылки">
          <thead>
            <tr>
              <Th>Название</Th>
              <Th>Отчёт</Th>
              <Th>Периодичность</Th>
              <Th>Следующая отправка</Th>
              <Th>Состояние</Th>
              <Th>Действия</Th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.id}>
                <Td>{s.name}</Td>
                <Td>{reportTitle.get(s.report) ?? s.report}</Td>
                <Td>
                  {frequencyTitles.get(s.frequency)}, {s.at}
                </Td>
                <Td>{fmt(s.next_run_at, me.timezone)}</Td>
                <Td>{s.enabled ? "включена" : "выключена"}</Td>
                <Td>
                  <div className="flex gap-1">
                    <Button variant="ghost" onClick={() => setRunsFor(runsFor === s.id ? "" : s.id)}>
                      Журнал отправок
                    </Button>
                    {manage && (
                      <>
                        <Button variant="ghost" aria-label={`Изменить расписание ${s.name}`} onClick={() => setEditing(s.id)}>
                          Изменить
                        </Button>
                        <Button variant="danger" aria-label={`Удалить расписание ${s.name}`} disabled={del.isPending} onClick={() => del.mutate(s.id)}>
                          Удалить
                        </Button>
                      </>
                    )}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {runsFor !== "" && runs.isSuccess && (
        <Table aria-label="Журнал отправок">
          <thead>
            <tr>
              <Th>Срок</Th>
              <Th>Период отчёта</Th>
              <Th>Результат</Th>
              <Th>Попыток</Th>
              <Th>Без e-mail</Th>
              <Th>Ошибка</Th>
            </tr>
          </thead>
          <tbody>
            {runs.data.items.map((r) => (
              <tr key={r.id}>
                <Td>{fmt(r.due_at, me.timezone)}</Td>
                <Td>
                  {r.period_first} — {r.period_last}
                </Td>
                <Td>{runStatus.get(r.status) ?? r.status}</Td>
                <Td>{r.attempts}</Td>
                <Td>{r.skipped_no_email > 0 ? `пропущено ${r.skipped_no_email}: задайте e-mail пользователям` : "—"}</Td>
                <Td>{r.error ?? "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

export function ReportsScreen({ me }: { me: Me }) {
  const tabs = [{ value: "reports", title: "Отчёты", content: <ReportsTab me={me} /> }];
  if (me.permissions.includes("reports.schedules.read")) tabs.push({ value: "schedules", title: "Рассылка", content: <SchedulesTab me={me} /> });
  return (
    <div className="flex flex-col gap-3">
      <h1 className="text-xl font-semibold">Отчёты</h1>
      <TabBar label="Разделы отчётов" tabs={tabs} defaultValue="reports" />
    </div>
  );
}
