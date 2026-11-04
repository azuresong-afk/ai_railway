import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ConfirmDialog, ErrorBanner, fieldError, FormDialog } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Table, Td, Th } from "../ui/Layout";
import { redteamApi, type Schedule, type ScheduleInput, type Target } from "./api";
import { frequencyTitle, langTitle, scheduleStatusTitle, scheduleWhen, weekdayTitle } from "./format";

const schedKey = ["redteam", "schedules"] as const;

// Вкладка «Расписания»: продукт сам запускает тестирование по расписанию. Секретные заголовки цели в расписание не попадают,
// поэтому цели с секретным заголовком по расписанию не запускаются — для них есть запуск из CI (aisec-cli redteam run).
export function SchedulesTab({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [removing, setRemoving] = useState<Schedule | null>(null);
  const q = useQuery({ queryKey: schedKey, queryFn: ({ signal }) => redteamApi.schedules(signal) });
  const targets = useQuery({ queryKey: ["redteam", "targets"], queryFn: ({ signal }) => redteamApi.targets(signal) });
  const remove = useMutation({
    mutationFn: (id: string) => redteamApi.deleteSchedule(id),
    onSuccess: async () => {
      setRemoving(null);
      await qc.invalidateQueries({ queryKey: schedKey });
    },
  });
  const tname = (id: string) => targets.data?.items.find((t) => t.id === id)?.name ?? "цель удалена";
  const items = q.data?.items ?? [];
  const usable = (targets.data?.items ?? []).filter((t) => !t.auth_header);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          Расписание запускает тестирование на сервере в заданное время (часовой пояс установки). Если сервер был выключен, пропущенный запуск
          не догоняется: он записывается как пропущенный.
        </p>
        {canManage && (
          <Button variant="primary" disabled={usable.length === 0} onClick={() => setEditing("new")}>
            Добавить расписание
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка расписаний…</p>}
      {targets.data && usable.length === 0 && (
        <Banner kind="info">Для расписания нужна цель без секретного заголовка. Добавьте её на вкладке «Цели» или запускайте тестирование из CI.</Banner>
      )}
      {q.data && items.length === 0 && <EmptyState title="Расписаний ещё нет." action={null} />}
      {items.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Расписания запусков">
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>Цель</Th>
                <Th>Когда</Th>
                <Th>Следующий запуск</Th>
                <Th>Последняя попытка</Th>
                {canManage && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <Td className="break-words">
                    {s.name}
                    {!s.enabled && <div className="text-xs text-muted">выключено</div>}
                  </Td>
                  <Td className="break-words">{tname(s.target_id)}</Td>
                  <Td>
                    {scheduleWhen(s)}
                    <div className="text-xs text-muted">
                      {s.threats.length > 0 ? `строки: ${s.threats.join(", ")}` : "все строки матрицы"}
                      {s.lang ? `, ${langTitle.get(s.lang) ?? s.lang}` : ""}
                    </div>
                  </Td>
                  <Td>{s.enabled ? formatAbsolute(s.next_run_at) : "—"}</Td>
                  <Td>
                    {s.last_status ? (scheduleStatusTitle.get(s.last_status) ?? s.last_status) : "ещё не было"}
                    {s.last_run_at && <div className="text-xs text-muted">{formatAbsolute(s.last_run_at)}</div>}
                    {s.last_run_id && (
                      <a className="text-xs underline" href={`#/redteam?run=${encodeURIComponent(s.last_run_id)}`}>
                        Открыть запуск
                      </a>
                    )}
                  </Td>
                  {canManage && (
                    <Td>
                      <div className="flex gap-2">
                        <Button onClick={() => setEditing(s)}>Изменить</Button>
                        <Button onClick={() => setRemoving(s)}>Удалить</Button>
                      </div>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {editing && targets.data && <ScheduleDialog schedule={editing === "new" ? undefined : editing} targets={usable} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => {
          if (!v) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Удалить расписание"
        description={<>Расписание «{removing?.name}» будет удалено, запуски по нему прекратятся. Прошлые запуски останутся.</>}
        actionLabel="Удалить расписание"
        busy={remove.isPending}
        error={remove.error}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </div>
  );
}

function ScheduleDialog({ schedule, targets, onClose }: { schedule: Schedule | undefined; targets: Target[]; onClose: () => void }) {
  const qc = useQueryClient();
  const scen = useQuery({ queryKey: ["redteam", "scenarios"], queryFn: ({ signal }) => redteamApi.scenarios(signal) });
  const [name, setName] = useState(schedule?.name ?? "");
  const [target, setTarget] = useState(schedule?.target_id ?? targets[0]?.id ?? "");
  const [frequency, setFrequency] = useState<Schedule["frequency"]>(schedule?.frequency ?? "weekly");
  const [weekday, setWeekday] = useState(schedule?.weekday || 1);
  const [day, setDay] = useState(schedule?.day || 1);
  const [at, setAt] = useState(schedule?.at ?? "03:00");
  const [lang, setLang] = useState<string>(schedule?.lang ?? "");
  const [threats, setThreats] = useState<string[]>(schedule?.threats ?? []);
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
  const rows = [...new Set((scen.data?.scenarios ?? []).map((s) => s.threat))].sort();

  const save = useMutation({
    mutationFn: () => {
      const body: ScheduleInput = {
        name: name.trim(),
        target_id: target,
        frequency,
        at,
        enabled,
        ...(frequency === "weekly" ? { weekday } : {}),
        ...(frequency === "monthly" ? { day } : {}),
        ...(threats.length ? { threats } : {}),
        ...(lang ? { lang: lang as "ru" | "en" } : {}),
        ...(schedule ? { version: schedule.version } : {}),
      };
      return schedule ? redteamApi.updateSchedule(schedule.id, body) : redteamApi.createSchedule(body);
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: schedKey });
      onClose();
    },
  });
  const err = (f: string) => {
    const e = fieldError(save.error, f);
    return e ? { error: e } : {};
  };
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={schedule ? "Изменение расписания" : "Новое расписание"}
      description="Не чаще одного запуска в сутки по одному расписанию: тестирование отправляет много запросов."
    >
      <Field label="Название" {...err("name")}>
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}
      </Field>
      <Field label="Цель" {...err("target_id")}>
        {({ id, describedBy }) => (
          <Select id={id} aria-describedby={describedBy} value={target} onChange={(e) => setTarget(e.target.value)}>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Как часто">
          {({ id }) => (
            <Select id={id} value={frequency} onChange={(e) => setFrequency(e.target.value as Schedule["frequency"])}>
              {[...frequencyTitle].map(([v, title]) => (
                <option key={v} value={v}>
                  {title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Время (ЧЧ:ММ)" {...err("at")}>
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={at} maxLength={5} onChange={(e) => setAt(e.target.value)} />}
        </Field>
        {frequency === "weekly" && (
          <Field label="День недели">
            {({ id }) => (
              <Select id={id} value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
                {weekdayTitle.slice(1).map((t, i) => (
                  <option key={t} value={i + 1}>
                    {t}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {frequency === "monthly" && (
          <Field label="День месяца (1–28)" {...err("day")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} type="number" min={1} max={28} value={day} onChange={(e) => setDay(Number(e.target.value))} />}
          </Field>
        )}
      </div>
      <Field label="Язык сценариев">
        {({ id }) => (
          <Select id={id} value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">Все</option>
            {[...langTitle].map(([v, title]) => (
              <option key={v} value={v}>
                {title}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {rows.length > 0 && (
        <fieldset className="flex flex-col gap-1">
          <legend className="text-sm font-medium">Строки матрицы обнаружения</legend>
          <p className="text-xs text-muted">Без отметок — все строки, по которым есть сценарии.</p>
          <div className="grid grid-cols-3 gap-1">
            {rows.map((r) => (
              <Check key={r} label={r} checked={threats.includes(r)} onCheckedChange={(v) => setThreats(v ? [...threats, r] : threats.filter((x) => x !== r))} />
            ))}
          </div>
        </fieldset>
      )}
      <Check label="Расписание включено" checked={enabled} onCheckedChange={setEnabled} />
      <ErrorBanner error={save.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={name.trim() === "" || target === "" || save.isPending} onClick={() => save.mutate()}>
          {schedule ? "Сохранить расписание" : "Добавить расписание"}
        </Button>
      </div>
    </FormDialog>
  );
}
