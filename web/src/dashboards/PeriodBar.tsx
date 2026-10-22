import { useState } from "react";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { type LiveState, type Period, periodTitles } from "./api";

// Значение поля datetime-local («2026-10-22T10:30») → RFC 3339 в UTC; пусто или не дата — undefined.
function toIso(v: string): string | undefined {
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

const liveText = new Map<LiveState, string>([
  ["connecting", "Подключение к потоку…"],
  ["on", "Данные обновляются в реальном времени."],
  ["lost", "Связь потеряна: поток отклонён или оборван. Данные обновятся при смене периода или перезагрузке экрана."],
]);

// Панель периода дашбордов (ТЗ 5.8): именованные периоды, произвольный интервал и режим реального времени.
export function PeriodBar({
  period,
  onPeriod,
  live,
  onLive,
  liveState,
}: {
  period: Period;
  onPeriod: (p: Period) => void;
  live: boolean;
  onLive: (v: boolean) => void;
  liveState: LiveState;
}) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const f = toIso(from);
  const t = toIso(to);
  const bad = from !== "" && to !== "" && f !== undefined && t !== undefined && f >= t ? "Начало должно быть раньше конца." : undefined;
  const custom = period.name === "custom";
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Период">
          {({ id }) => (
            <Select
              id={id}
              value={period.name}
              onChange={(e) => {
                const name = e.target.value as Period["name"];
                if (name !== "custom") onPeriod({ name });
                else onPeriod({ name, ...(f ? { from: f } : {}), ...(t ? { to: t } : {}) });
              }}
            >
              {periodTitles.map(([v, title]) => (
                <option key={v} value={v}>
                  {title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {custom && (
          <>
            <Field label="С" {...(bad ? { error: bad } : {})}>
              {({ id }) => <Input id={id} type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />}
            </Field>
            <Field label="По">{({ id }) => <Input id={id} type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />}</Field>
            <Button
              variant="primary"
              disabled={Boolean(bad) || f === undefined || t === undefined}
              onClick={() => f && t && onPeriod({ name: "custom", from: f, to: t })}
            >
              Применить период
            </Button>
          </>
        )}
        <Check checked={live} onCheckedChange={onLive} label="Обновлять в реальном времени" />
      </div>
      {live && liveText.get(liveState) && <Banner kind={liveState === "lost" ? "warning" : "info"}>{liveText.get(liveState)!}</Banner>}
    </div>
  );
}
