import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, X } from "lucide-react";
import { useState } from "react";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner, Panel, RawText } from "../ui/Layout";
import { Table, Td, Th } from "../ui/Layout";
import { describeError, type Event, type EventContent, eventsApi } from "./api";
import { formatAbsolute, formatNumber } from "./format";
import { fieldTitle, valueTitle } from "./filter";

// Состав details не закреплён схемой: читаем только известные поля и только как текст и числа.
interface TraceStep {
  rule: string;
  detector: string;
  matched: boolean;
  action: string;
  note: string;
}
interface FindingRow {
  detector: string;
  category: string;
  score: number | null;
  location: string;
  threat: string;
}
interface Details {
  action: string;
  applied: string[];
  rule: string;
  severity: string;
  policy: string;
  policyVersion: number | null;
  failMode: string;
  trace: TraceStep[];
  failures: { detector: string; location: string; reason: string }[];
  findings: FindingRow[];
  latency: [string, number][];
  tokens: { prompt: number; completion: number } | null;
}

const rec = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function readDetails(raw: unknown): Details {
  const d = rec(raw);
  const dec = rec(d.decision);
  const tokens = rec(d.tokens);
  return {
    action: str(dec.action),
    applied: arr(dec.applied).map(str).filter(Boolean),
    rule: str(dec.rule),
    severity: str(dec.severity),
    policy: str(dec.policy),
    policyVersion: numOrNull(dec.policy_version),
    failMode: str(dec.fail_mode),
    trace: arr(dec.trace).map((t) => {
      const r = rec(t);
      return { rule: str(r.rule), detector: str(r.detector), matched: r.matched === true, action: str(r.action), note: str(r.note) };
    }),
    failures: arr(dec.failures).map((f) => {
      const r = rec(f);
      return { detector: str(r.detector), location: str(r.location), reason: str(r.reason) };
    }),
    findings: arr(d.findings).map((f) => {
      const r = rec(f);
      return { detector: str(r.detector), category: str(r.category), score: numOrNull(r.score), location: str(r.location), threat: str(r.threat) };
    }),
    latency: Object.entries(rec(d.latency_ms)).flatMap(([k, v]) => (typeof v === "number" ? [[k, v] as [string, number]] : [])),
    tokens:
      typeof tokens.prompt === "number" && typeof tokens.completion === "number"
        ? { prompt: tokens.prompt, completion: tokens.completion }
        : null,
  };
}

const yn = (b: boolean) => (b ? "да" : "нет");

function Meta({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
      {rows
        .filter(([, v]) => v !== "")
        .map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="font-mono text-sm break-all">{v}</dd>
          </div>
        ))}
    </dl>
  );
}

function Why({ ev, d }: { ev: Event; d: Details }) {
  return (
    <section aria-labelledby="why" className="flex flex-col gap-2">
      <h3 id="why" className="text-md font-semibold">
        Почему принято решение
      </h3>
      <Meta
        rows={[
          ["Итоговое действие", d.action || ev.action || "—"],
          ["Применено", d.applied.join(", ")],
          ["Правило", d.rule || ev.rule || ""],
          ["Режим политики", ev.policy_mode ? valueTitle("policy_mode", ev.policy_mode) : ""],
          ["Политика", d.policy ? `${d.policy}${d.policyVersion !== null ? `, версия ${d.policyVersion}` : ""}` : ""],
          ["Серьёзность", d.severity || ev.severity || ""],
          ["При сбое проверки", d.failMode],
        ]}
      />
      {ev.policy_mode === "monitor" && (
        <p className="text-sm text-muted">
          Политика работает в режиме наблюдения: итоговое действие записано, но запрос не блокировался.
        </p>
      )}
      {d.trace.length > 0 ? (
        <Table aria-label="Трассировка правил">
          <thead>
            <tr>
              <Th>Правило</Th>
              <Th>Детектор</Th>
              <Th>Сработало</Th>
              <Th>Действие</Th>
            </tr>
          </thead>
          <tbody>
            {d.trace.map((t, i) => (
              <tr key={i}>
                <Td>
                  {t.rule}
                  {t.note && <div className="text-xs text-muted">{t.note}</div>}
                </Td>
                <Td className="font-mono text-sm">{t.detector}</Td>
                <Td>{yn(t.matched)}</Td>
                <Td>{t.action}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <p className="text-sm text-muted">Трассировка правил для этого события не записана.</p>
      )}
      {d.failures.length > 0 && (
        <Banner kind="warning">
          Не отработали детекторы: {d.failures.map((f) => `${f.detector} (${f.location}, ${f.reason === "timeout" ? "не уложился в срок" : "ошибка"})`).join("; ")}.
        </Banner>
      )}
    </section>
  );
}

function Findings({ d, threats }: { d: Details; threats: string[] }) {
  return (
    <section aria-labelledby="found" className="flex flex-col gap-2">
      <h3 id="found" className="text-md font-semibold">
        Находки и категория угрозы
      </h3>
      <p className="text-sm text-muted">
        Строки матрицы обнаружения: {threats.length > 0 ? threats.join(", ") : "нет"}.
      </p>
      {d.findings.length > 0 ? (
        <Table aria-label="Находки">
          <thead>
            <tr>
              <Th>Детектор</Th>
              <Th>Угроза</Th>
              <Th>Где найдено</Th>
              <Th className="text-right">Оценка</Th>
            </tr>
          </thead>
          <tbody>
            {d.findings.map((f, i) => (
              <tr key={i}>
                <Td className="font-mono text-sm">{f.detector}</Td>
                <Td className="font-mono text-sm">{f.threat}</Td>
                <Td className="font-mono text-sm">{f.location}</Td>
                <Td className="text-right">{f.score === null ? "—" : f.score.toLocaleString("ru-RU", { maximumFractionDigits: 2 })}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <p className="text-sm text-muted">Находок нет.</p>
      )}
    </section>
  );
}

// Окно ввода причины (УПД.7): причину вводят до запроса, сервер пишет её в журнал аудита.
function ReasonDialog({
  open,
  onOpenChange,
  onSubmit,
  pending,
  error,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSubmit: (reason: string) => void;
  pending: boolean;
  error: string | null;
}) {
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);
  const trimmed = reason.trim();
  const len = [...trimmed].length;
  const invalid = len < 3 || len > 500;
  const local = touched && invalid ? "Опишите причину: от 3 до 500 символов." : undefined;
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(v) => {
        onOpenChange(v);
        if (!v) {
          setReason("");
          setTouched(false);
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-[var(--c-overlay)]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 w-[28rem] max-w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 rounded-panel border border-line bg-surface p-5 text-fg shadow-popup">
          <Dialog.Title className="text-lg font-semibold">Показать содержимое</Dialog.Title>
          <Dialog.Description className="mt-1 text-base text-muted">
            Просмотр запишется в журнал аудита вместе с вашей причиной.
          </Dialog.Description>
          <form
            className="mt-4 flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              setTouched(true);
              if (!invalid) onSubmit(trimmed);
            }}
          >
            <Field label="Причина просмотра" hint="Например: разбор инцидента 1234." {...(local ? { error: local } : {})}>
              {({ id, describedBy, invalid: inv }) => (
                <Input
                  id={id}
                  value={reason}
                  maxLength={500}
                  autoComplete="off"
                  aria-invalid={inv}
                  {...(describedBy ? { "aria-describedby": describedBy } : {})}
                  onChange={(e) => setReason(e.target.value)}
                />
              )}
            </Field>
            {error && <Banner kind="error">{error}</Banner>}
            <div className="flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button>Отменить</Button>
              </Dialog.Close>
              <Button type="submit" variant="primary" disabled={pending}>
                Показать содержимое
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function ContentBlock({ ev, canRead }: { ev: Event; canRead: boolean }) {
  const [open, setOpen] = useState(false);
  // Содержимое живёт только в состоянии этого блока: закрытие карточки или смена события его сбрасывает.
  const [content, setContent] = useState<EventContent | null>(null);
  const read = useMutation({
    mutationFn: (reason: string) => eventsApi.content(ev.id, reason),
    onSuccess: (c) => {
      setContent(c);
      setOpen(false);
    },
  });
  return (
    <section aria-labelledby="content" className="flex flex-col gap-2">
      <h3 id="content" className="text-md font-semibold">
        Запрос и ответ
      </h3>
      {content ? (
        <>
          <p className="text-sm text-muted">
            {content.storage === "masked"
              ? "Показано замаскированное содержимое: персональные данные и секреты заменены."
              : "Показано полное содержимое."}
          </p>
          <h4 className="text-sm font-medium">Запрос</h4>
          <RawText>{content.request ?? "Запрос не сохранён."}</RawText>
          <h4 className="text-sm font-medium">Ответ</h4>
          <RawText>{content.response ?? "Ответ не сохранён."}</RawText>
          <Button
            onClick={() => {
              setContent(null);
              read.reset();
            }}
          >
            <EyeOff size={16} aria-hidden="true" />
            Скрыть содержимое
          </Button>
        </>
      ) : !ev.has_content ? (
        <p className="text-sm text-muted">Содержимое не сохранено: режим хранения «{valueTitle("storage", ev.storage)}».</p>
      ) : canRead ? (
        <>
          <p className="text-sm text-muted">Содержимое не загружается вместе со списком. Для просмотра укажите причину.</p>
          <div>
            <Button onClick={() => setOpen(true)}>
              <Eye size={16} aria-hidden="true" />
              Показать содержимое
            </Button>
          </div>
        </>
      ) : (
        <p className="text-sm text-muted">Просмотр содержимого доступен администратору безопасности.</p>
      )}
      {/* Монтируется только пока открыто: введённая причина не переживает закрытие окна. */}
      {open && (
        <ReasonDialog
          open
          onOpenChange={(v) => {
            setOpen(v);
            if (!v) read.reset();
          }}
          onSubmit={(r) => read.mutate(r)}
          pending={read.isPending}
          error={read.isError ? describeError(read.error, "content") : null}
        />
      )}
    </section>
  );
}

export function EventCard({ id, canReadContent, onClose }: { id: string; canReadContent: boolean; onClose: () => void }) {
  const q = useQuery({ queryKey: ["event", id], queryFn: ({ signal }) => eventsApi.get(id, signal) });
  return (
    <aside aria-label="Карточка события" className="flex w-[34rem] max-w-[50vw] shrink-0 flex-col gap-4 overflow-auto border-l border-line bg-surface p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Событие</h2>
        <Button variant="ghost" aria-label="Закрыть карточку" onClick={onClose}>
          <X size={16} aria-hidden="true" />
        </Button>
      </div>
      {q.isPending && <p className="text-sm text-muted">Загрузка…</p>}
      {q.isError && <Banner kind="error">{describeError(q.error, "list")}</Banner>}
      {q.data && <Body key={q.data.id} ev={q.data} canReadContent={canReadContent} />}
    </aside>
  );
}

function Body({ ev, canReadContent }: { ev: Event; canReadContent: boolean }) {
  const d = readDetails(ev.details);
  return (
    <>
      <Panel>
        <Meta
          rows={[
            ["ID", ev.id],
            ["Время", formatAbsolute(ev.time)],
            ["Принято сервером", formatAbsolute(ev.received_at)],
            ["Шлюз", ev.gateway_id],
            ["Тип", valueTitle("type", ev.type)],
            [fieldTitle("app"), ev.app ?? ""],
            [fieldTitle("env"), ev.env ?? ""],
            ["Пользователь", ev.user ?? ""],
            [fieldTitle("provider"), ev.provider ?? ""],
            [fieldTitle("model"), ev.model ?? ""],
            [fieldTitle("source"), ev.source ?? ""],
            ["Потоковый ответ", yn(ev.stream)],
            ["Хранение содержимого", valueTitle("storage", ev.storage)],
          ]}
        />
      </Panel>
      {ev.non_text_unchecked && (
        <Banner kind="warning">В запросе есть нетекстовые части (изображения или аудио), они не проверялись.</Banner>
      )}
      <Why ev={ev} d={d} />
      <Findings d={d} threats={ev.threats} />
      <ContentBlock ev={ev} canRead={canReadContent} />
      {(d.latency.length > 0 || d.tokens) && (
        <section aria-labelledby="perf" className="flex flex-col gap-2">
          <h3 id="perf" className="text-md font-semibold">
            Задержки и токены
          </h3>
          <Meta
            rows={[
              ...d.latency.map(([k, v]): [string, string] => [`Задержка: ${k}`, `${formatNumber(v)} мс`]),
              ...(d.tokens
                ? ([
                    ["Токены запроса", formatNumber(d.tokens.prompt)],
                    ["Токены ответа", formatNumber(d.tokens.completion)],
                  ] as [string, string][])
                : []),
            ]}
          />
        </section>
      )}
    </>
  );
}
