import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, Fragment, useMemo, useState } from "react";
import type { Me } from "../api/client";
import { formatAbsolute, formatNumber } from "../events/format";
import { chainReasonText } from "../system/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, RawText, Table, Td, Th } from "../ui/Layout";
import { adminApi, type AuditFilter, type AuditRecord, type AuditVerification } from "./api";
import { ErrorBanner } from "./common";

// Журнал аудита (ТЗ 6.3 п. 11, задача 2.4a): только просмотр, записи через консоль не меняются (УПД.2).
// Проверка цепочки по кнопке — та же проверка, что фоновая на сервере (РСБ.4, DM-43).

const periods = [
  { value: "1", title: "24 часа", days: 1 },
  { value: "7", title: "7 суток", days: 7 },
  { value: "31", title: "31 сутки", days: 31 },
];

const resultText = new Map([
  ["success", "Успех"],
  ["failure", "Неудача"],
  ["denied", "Отказ"],
]);

const actorText = new Map([
  ["user", "пользователь"],
  ["api_token", "токен API"],
  ["system", "система"],
  ["gateway", "шлюз"],
  ["cli", "aisec-cli"],
]);

const partRe = /^[a-z][a-z0-9_]*$/;

// Код события «группа.действие» или группа «группа.*»; разбор по частям, без вложенных повторов в регулярном выражении.
function validCode(s: string): boolean {
  const parts = s.split(".");
  if (parts.length < 2 || s.length > 66) return false;
  return parts.every((p, i) => partRe.test(p) || (p === "*" && i === parts.length - 1));
}

// Коды через запятую или пробел: «auth.*, user.create». Пустая строка — все события.
export function parseActions(s: string): { actions: string[]; error?: string } {
  const actions = s.split(/[\s,]+/).filter(Boolean);
  if (actions.length > 20) return { actions, error: "Не больше 20 кодов событий." };
  const bad = actions.find((a) => !validCode(a));
  if (bad) return { actions, error: `«${bad}» — не код события. Пример: auth.login или группа auth.*.` };
  return { actions };
}

function buildFilter(days: number, actions: string[], actor: string, result: string): AuditFilter {
  const to = Date.now();
  return { from: new Date(to - days * 86_400_000).toISOString(), to: new Date(to).toISOString(), actions, actor: actor.trim(), result };
}

export function AuditTab({ me }: { me: Me }) {
  const canVerify = me.permissions.includes("audit.verify");
  const [period, setPeriod] = useState("7");
  const [codes, setCodes] = useState("");
  const [actor, setActor] = useState("");
  const [result, setResult] = useState("");
  const [filter, setFilter] = useState<AuditFilter>(() => buildFilter(7, [], "", ""));
  const [open, setOpen] = useState<number | null>(null);
  // rev меняет ключ запроса и при совпавшем до миллисекунды конце периода.
  const [rev, setRev] = useState(0);
  const parsed = parseActions(codes);

  const list = useInfiniteQuery({
    queryKey: ["admin", "audit", filter, rev],
    queryFn: ({ pageParam, signal }) => adminApi.audit(filter, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor || undefined,
  });
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (parsed.error) return;
    const days = periods.find((p) => p.value === period)?.days ?? 7;
    setOpen(null);
    setFilter(buildFilter(days, parsed.actions, actor, result));
  };
  // После проверки период сдвигается к текущему времени: так в списке появится запись её итога.
  const refresh = () => {
    setRev((n) => n + 1);
    setFilter((f) => {
      const span = Date.parse(f.to) - Date.parse(f.from);
      const to = Date.now();
      return { ...f, from: new Date(to - span).toISOString(), to: new Date(to).toISOString() };
    });
  };

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">
        Журнал только для чтения: изменить или удалить запись через консоль нельзя. Секреты в подробностях скрыты при записи.
      </p>
      {canVerify && <VerifyPanel onDone={refresh} />}
      <form onSubmit={submit} aria-label="Фильтр журнала аудита" className="flex flex-wrap items-end gap-3">
        <Field label="Период">
          {({ id }) => (
            <Select id={id} value={period} onChange={(e) => setPeriod(e.target.value)}>
              {periods.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.title}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Коды событий" hint="Например, auth.* или user.create, до 20." error={parsed.error}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} value={codes} onChange={(e) => setCodes(e.target.value)} />
          )}
        </Field>
        <Field label="Субъект" hint="Логин или ID, точное совпадение.">
          {({ id, describedBy }) => (
            <Input id={id} aria-describedby={describedBy} maxLength={256} value={actor} onChange={(e) => setActor(e.target.value)} />
          )}
        </Field>
        <Field label="Результат">
          {({ id }) => (
            <Select id={id} value={result} onChange={(e) => setResult(e.target.value)}>
              <option value="">Любой</option>
              {[...resultText].map(([v, t]) => (
                <option key={v} value={v}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button type="submit" variant="primary" disabled={Boolean(parsed.error)}>
          Показать
        </Button>
      </form>
      {list.isError && <ErrorBanner error={list.error} />}
      {list.isPending && <p className="text-sm text-muted">Загрузка журнала…</p>}
      {list.isSuccess && rows.length === 0 && (
        <EmptyState title="Записей не найдено" action={<p className="text-sm text-muted">Расширьте период или снимите фильтр.</p>} />
      )}
      {rows.length > 0 && (
        <Table aria-label="Журнал аудита">
          <thead>
            <tr>
              <Th className="text-right">№</Th>
              <Th>Время</Th>
              <Th>Событие</Th>
              <Th>Субъект</Th>
              <Th>Адрес</Th>
              <Th>Объект</Th>
              <Th>Результат</Th>
              <Th>
                <span className="sr-only">Подробности</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <Fragment key={r.seq}>
                <Row r={r} open={open === r.seq} onToggle={() => setOpen(open === r.seq ? null : r.seq)} />
                {open === r.seq && (
                  <tr>
                    <Td colSpan={8} className="py-2">
                      <RawText>{JSON.stringify(r.details, null, 2)}</RawText>
                      <p className="mt-1 text-xs text-muted">Хеш записи: {r.hash}</p>
                    </Td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </Table>
      )}
      {list.hasNextPage && (
        <div>
          <Button onClick={() => void list.fetchNextPage()} disabled={list.isFetchingNextPage}>
            {list.isFetchingNextPage ? "Загрузка…" : "Показать ещё"}
          </Button>
        </div>
      )}
    </div>
  );
}

function Row({ r, open, onToggle }: { r: AuditRecord; open: boolean; onToggle: () => void }) {
  return (
    <tr>
      <Td className="text-right">{r.seq}</Td>
      <Td>{r.ts ? formatAbsolute(r.ts) : "время не читается"}</Td>
      <Td>
        {r.action_title || r.action}
        <span className="block text-xs text-muted">{r.action}</span>
      </Td>
      <Td>
        {r.actor.name || r.actor.id}
        <span className="block text-xs text-muted">{actorText.get(r.actor.type) ?? r.actor.type}</span>
      </Td>
      <Td>{r.source_ip ?? "—"}</Td>
      <Td>{r.object.type ? `${r.object.type}${r.object.id ? `: ${r.object.id}` : ""}` : "—"}</Td>
      <Td>{resultText.get(r.result) ?? r.result}</Td>
      <Td>
        <Button variant="ghost" aria-expanded={open} onClick={onToggle}>
          {open ? "Скрыть" : "Подробности"}
        </Button>
      </Td>
    </tr>
  );
}

function verifyText(v: AuditVerification): string {
  if (v.ok) return `Цепочка цела: проверено ${formatNumber(v.checked)} записей, последняя — № ${v.last_seq}. Проверено ${formatAbsolute(v.checked_at)}.`;
  const reason = chainReasonText.get(v.reason) ?? v.reason;
  return `Цепочка нарушена на записи № ${v.broken_seq ?? "?"}: ${reason}. Итог записан в журнал и показан в «Состоянии системы».`;
}

function VerifyPanel({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => adminApi.verifyAudit(),
    onSuccess: () => {
      onDone();
      void qc.invalidateQueries({ queryKey: ["system", "status"] });
    },
  });
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <Button onClick={() => m.mutate()} disabled={m.isPending}>
          {m.isPending ? "Проверка…" : "Проверить цепочку"}
        </Button>
        <span className="text-sm text-muted">Проверяется весь хранимый журнал; на большом журнале — до нескольких минут.</span>
      </div>
      <ErrorBanner error={m.error} />
      {m.data && <Banner kind={m.data.ok ? "info" : "error"}>{verifyText(m.data)}</Banner>}
    </div>
  );
}
