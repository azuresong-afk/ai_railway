import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Save, Trash2, X } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { Confirm } from "../ui/Overlay";
import { describeError, eventsApi } from "./api";
import { buildFilter, type Chip, chipKey, fields, fieldTitle, parseFilter, valueTitle } from "./filter";

export const periods = [
  { id: "1h", title: "Последний час", ms: 3_600_000 },
  { id: "24h", title: "Последние 24 часа", ms: 86_400_000 },
  { id: "7d", title: "Последние 7 суток", ms: 7 * 86_400_000 },
  { id: "30d", title: "Последние 30 суток", ms: 30 * 86_400_000 },
];

// Условие добавляется к уже существующему по тому же полю и знаку: так получается `in (…)`.
export function addChip(chips: Chip[], add: Chip): Chip[] {
  const i = chips.findIndex((c) => c.field === add.field && c.negate === add.negate);
  if (i < 0) return [...chips, add];
  return chips.map((c, j) => (j === i ? { ...c, values: [...new Set([...c.values, ...add.values])] } : c));
}

export function chipLabel(c: Chip): string {
  if (c.values.length > 1) return `${fieldTitle(c.field)} ${c.negate ? "не из" : "из"}: ${c.values.map((v) => valueTitle(c.field, v)).join(", ")}`;
  return `${fieldTitle(c.field)} ${c.negate ? "≠" : "="} ${valueTitle(c.field, c.values[0] ?? "")}`;
}

function AddCondition({ onAdd }: { onAdd: (c: Chip) => void }) {
  const [field, setField] = useState(fields[0]!.id);
  const [negate, setNegate] = useState(false);
  const [value, setValue] = useState("");
  const listId = useId();
  const info = fields.find((f) => f.id === field)!;
  const options = info.options;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const v = (info.bool ? value || "true" : value).trim();
    if (v === "") return;
    onAdd({ field, negate: info.bool ? false : negate, values: [v] });
    setValue("");
  };
  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Добавить условие">
      <label className="flex flex-col gap-1 text-sm font-medium">
        Поле
        <Select
          value={field}
          onChange={(e) => {
            setField(e.target.value);
            setValue("");
          }}
          className="w-44"
        >
          {fields.map((f) => (
            <option key={f.id} value={f.id}>
              {f.title}
            </option>
          ))}
        </Select>
      </label>
      {!info.bool && (
        <label className="flex flex-col gap-1 text-sm font-medium">
          Условие
          <Select value={negate ? "ne" : "eq"} onChange={(e) => setNegate(e.target.value === "ne")} className="w-28">
            <option value="eq">равно</option>
            <option value="ne">не равно</option>
          </Select>
        </label>
      )}
      <label className="flex flex-col gap-1 text-sm font-medium">
        Значение
        {info.bool ? (
          <Select value={value || "true"} onChange={(e) => setValue(e.target.value)} className="w-28">
            <option value="true">да</option>
            <option value="false">нет</option>
          </Select>
        ) : (
          <>
            <Input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              maxLength={256}
              className="w-44"
              autoComplete="off"
              {...(options ? { list: listId } : {})}
            />
            {options && (
              <datalist id={listId}>
                {options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.title}
                  </option>
                ))}
              </datalist>
            )}
          </>
        )}
      </label>
      <Button type="submit">
        <Plus size={16} aria-hidden="true" />
        Добавить условие
      </Button>
    </form>
  );
}

function SavedFilters({ filter, onApply }: { filter: string; onApply: (f: string) => void }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["event-filters"], queryFn: ({ signal }) => eventsApi.filters(signal) });
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [picked, setPicked] = useState("");
  const save = useMutation({
    mutationFn: () => eventsApi.saveFilter(name.trim(), filter),
    onSuccess: () => {
      setSaving(false);
      setName("");
      void qc.invalidateQueries({ queryKey: ["event-filters"] });
    },
  });
  const del = useMutation({
    mutationFn: (id: string) => eventsApi.deleteFilter(id),
    onSuccess: () => {
      setPicked("");
      void qc.invalidateQueries({ queryKey: ["event-filters"] });
    },
  });
  const items = list.data?.items ?? [];
  const current = items.find((i) => i.id === picked);
  return (
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex flex-col gap-1 text-sm font-medium">
        Сохранённые фильтры
        <Select
          value={picked}
          onChange={(e) => {
            setPicked(e.target.value);
            const it = items.find((i) => i.id === e.target.value);
            if (it) onApply(it.filter);
          }}
          className="w-44"
        >
          <option value="">{items.length === 0 ? "Пока нет" : "Выберите фильтр"}</option>
          {items.map((i) => (
            <option key={i.id} value={i.id}>
              {i.name}
            </option>
          ))}
        </Select>
      </label>
      {current && (
        <Confirm
          trigger={
            <Button variant="danger">
              <Trash2 size={16} aria-hidden="true" />
              Удалить фильтр
            </Button>
          }
          title="Удалить сохранённый фильтр?"
          description={`Фильтр «${current.name}» исчезнет из вашего списка. События не изменятся.`}
          actionLabel="Удалить фильтр"
          onConfirm={() => del.mutate(current.id)}
        />
      )}
      {saving ? (
        <form
          className="flex items-end gap-2"
          aria-label="Сохранить фильтр"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim() !== "") save.mutate();
          }}
        >
          <label className="flex flex-col gap-1 text-sm font-medium">
            Название фильтра
            <Input value={name} maxLength={100} onChange={(e) => setName(e.target.value)} className="w-44" autoComplete="off" />
          </label>
          <Button type="submit" variant="primary" disabled={save.isPending || name.trim() === ""}>
            Сохранить фильтр
          </Button>
          <Button
            onClick={() => {
              setSaving(false);
              save.reset();
            }}
          >
            Отменить
          </Button>
        </form>
      ) : (
        <Button onClick={() => setSaving(true)} disabled={filter === ""}>
          <Save size={16} aria-hidden="true" />
          Сохранить фильтр…
        </Button>
      )}
      {save.isError && <Banner kind="error">{describeError(save.error, "filters")}</Banner>}
      {del.isError && <Banner kind="error">{describeError(del.error, "filters")}</Banner>}
      {list.isError && <Banner kind="error">{describeError(list.error, "filters")}</Banner>}
    </div>
  );
}

// Чипы над таблицей: каждый снимается одним кликом (ТЗ 6.5).
export function FilterBar({
  filter,
  onFilter,
  period,
  onPeriod,
}: {
  filter: string;
  onFilter: (f: string) => void;
  period: string;
  onPeriod: (p: string) => void;
}) {
  const chips = parseFilter(filter);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm font-medium">
          Период
          <Select value={period} onChange={(e) => onPeriod(e.target.value)} className="w-44">
            {periods.map((p) => (
              <option key={p.id} value={p.id}>
                {p.title}
              </option>
            ))}
          </Select>
        </label>
        <AddCondition onAdd={(c) => onFilter(buildFilter(addChip(chips ?? [], c)))} />
      </div>
      <SavedFilters filter={filter} onApply={onFilter} />
      <ul aria-label="Условия фильтра" className="flex flex-wrap gap-2">
        {chips === null ? (
          <li className="flex items-center gap-1 rounded-control border border-line-strong bg-surface py-0.5 pr-1 pl-2 text-sm">
            <span className="font-mono">{filter}</span>
            <Button variant="ghost" aria-label="Снять фильтр" className="!h-6 !px-1" onClick={() => onFilter("")}>
              <X size={14} aria-hidden="true" />
            </Button>
          </li>
        ) : (
          chips.map((c) => (
            <li key={chipKey(c)} className="flex items-center gap-1 rounded-control border border-line-strong bg-surface py-0.5 pr-1 pl-2 text-sm">
              <span>{chipLabel(c)}</span>
              <Button
                variant="ghost"
                aria-label={`Снять условие: ${chipLabel(c)}`}
                className="!h-6 !px-1"
                onClick={() => onFilter(buildFilter(chips.filter((x) => chipKey(x) !== chipKey(c))))}
              >
                <X size={14} aria-hidden="true" />
              </Button>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
