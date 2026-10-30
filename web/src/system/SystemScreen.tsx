import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { isRefetch } from "../api/poll";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Banner, Panel, Table, Td, Th } from "../ui/Layout";
import { ShapeIcon } from "../ui/icons";
import { SyslogPanel } from "../shadowai/SyslogPanel";
import { type IntegrityCheck, type SystemStatus, systemApi } from "./api";
import { chainReasonText, formatBytes, gatewayText, problemText, reasonText, syncText, triggerText } from "./format";

// Состояние всегда словами и значком своей формы; цвет — дополнение (ТЗ 6.2).
function Tag({ ok, children }: { ok: boolean | null; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={ok === null ? "text-sev-info" : ok ? "text-[var(--c-dec-allowed)]" : "text-sev-critical"}>
        <ShapeIcon kind={ok === null ? "info" : ok ? "low" : "critical"} />
      </span>
      {children}
    </span>
  );
}

const when = (iso: string | null | undefined) => (iso ? formatAbsolute(iso) : "—");

function Report({ r, what }: { r: { ok: boolean; checked_at: string; failed: number; reason?: string | undefined } | null; what: string }) {
  if (r === null) return <span className="text-muted">нет данных</span>;
  return (
    <Tag ok={r.ok}>
      {r.ok ? `${what}: успешно` : `${what}: провалено${r.failed ? ` (${r.failed})` : ""}`}
      <span className="text-muted">, {formatAbsolute(r.checked_at)}</span>
    </Tag>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Panel aria-label={title} role="region" className="flex flex-col gap-2">
      <h2 className="text-lg font-semibold">{title}</h2>
      {children}
    </Panel>
  );
}

// Экран «Состояние системы» (ТЗ 6.3, п. 13): GET /system/status, проверка целостности по кнопке.
export function SystemScreen({ me }: { me: Me }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["system", "status"],
    queryFn: ({ signal, queryKey }) => systemApi.status(signal, isRefetch(qc, queryKey)),
    refetchInterval: 30_000,
  });
  const canVerify = me.permissions.includes("integrity.verify");
  const verify = useMutation({
    mutationFn: () => systemApi.verifyIntegrity(),
    onSuccess: () => void q.refetch(),
  });
  const s = q.data;

  return (
    <section aria-label="Состояние системы" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Состояние системы</h1>
        <div className="flex items-center gap-3">
          {s && <span className="text-sm text-muted">Обновлено {formatAbsolute(s.generated_at)}</span>}
          <Button onClick={() => void q.refetch()} disabled={q.isFetching}>
            <RefreshCw size={16} aria-hidden="true" />
            Обновить
          </Button>
        </div>
      </div>
      {q.isError && <ErrorBanner error={q.error} />}
      {q.isPending && <p className="text-sm text-muted">Загрузка состояния…</p>}
      {s && <Body s={s} />}
      {s && (
        <Section title="Целостность программы">
          <p className="text-sm text-muted">
            Сверка исполняемого файла и веб-консоли сервера с подписанным манифестом (ОЦЛ.2). Действующие шлюзы получают запрос проверки со
            следующим контактом с сервером, их итоги появятся в разделе шлюзов и в журнале аудита.
          </p>
          {canVerify ? (
            <div>
              <Button variant="primary" disabled={verify.isPending} onClick={() => verify.mutate()}>
                <ShieldCheck size={16} aria-hidden="true" />
                Проверить целостность
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted">Запускать проверку может администратор безопасности.</p>
          )}
          <ErrorBanner error={verify.error} />
          {verify.data && <VerifyResult r={verify.data} />}
        </Section>
      )}
    </section>
  );
}

function VerifyResult({ r }: { r: IntegrityCheck }) {
  return (
    <div className="flex flex-col gap-2" aria-live="polite">
      <Banner kind={r.ok ? "info" : "error"}>
        Проверка от {formatAbsolute(r.checked_at)}: {reasonText.get(r.reason) ?? r.reason}. Проверено файлов: {formatNumber(r.checked_files)}.
        {r.test_signed ? " Сборка подписана тестовым ключом, не для поставки." : ""}
      </Banner>
      {r.gateways_requested !== undefined && (
        <p className="text-sm text-muted">
          {r.gateways_requested > 0
            ? `Запрос проверки передан шлюзам: ${formatNumber(r.gateways_requested)}. Итоги придут в течение нескольких минут.`
            : "Действующих шлюзов нет."}
        </p>
      )}
      {r.failures.length > 0 && (
        <ul className="list-disc pl-5 text-sm">
          {r.failures.map((f) => (
            <li key={f.path}>
              <span className="font-mono">{f.path}</span>: {problemText.get(f.problem) ?? f.problem}
            </li>
          ))}
          {r.omitted > 0 && <li>…и ещё {formatNumber(r.omitted)}</li>}
        </ul>
      )}
    </div>
  );
}

function Body({ s }: { s: SystemStatus }) {
  const gone = new Set<string>(s.unavailable);
  const active = s.notifications.filter((n) => n.active);
  return (
    <>
      {s.unavailable.length > 0 && (
        <Banner kind="warning">Не удалось собрать разделы: {s.unavailable.join(", ")}. Остальные данные верны.</Banner>
      )}
      <Section title="Уведомления">
        {gone.has("notifications") ? (
          <p className="text-sm text-muted">Недоступно.</p>
        ) : active.length === 0 ? (
          <Tag ok>Активных уведомлений нет</Tag>
        ) : (
          <ul className="flex flex-col gap-2">
            {active.map((n) => (
              <li key={n.condition}>
                <Banner kind="warning">
                  {n.title} ({n.requirement})
                  {n.since ? `, с ${formatAbsolute(n.since)}` : ""}
                  {n.count !== null ? `, за 24 часа: ${formatNumber(n.count)}` : ""}
                </Banner>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Сервер">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
          <dt className="text-muted">Версия</dt>
          <dd>{s.server.version}</dd>
          <dt className="text-muted">Запущен</dt>
          <dd>{formatAbsolute(s.server.started_at)}</dd>
          <dt className="text-muted">Самотестирование</dt>
          <dd>
            <Report r={s.server.selftest} what="самотест" />
          </dd>
        </dl>
        {gone.has("integrity") ? (
          <p className="text-sm text-muted">Итоги контроля целостности недоступны.</p>
        ) : s.server.integrity.length === 0 ? (
          <p className="text-sm text-muted">Проверок целостности ещё не было.</p>
        ) : (
          <Table aria-label="Контроль целостности">
            <thead>
              <tr>
                <Th>Компонент</Th>
                <Th>Когда</Th>
                <Th>Итог</Th>
                <Th>Версия манифеста</Th>
              </tr>
            </thead>
            <tbody>
              {s.server.integrity.map((i) => (
                <tr key={i.component}>
                  <Td>{i.component}</Td>
                  <Td>
                    {formatAbsolute(i.checked_at)}, {triggerText.get(i.trigger) ?? i.trigger}
                  </Td>
                  <Td>
                    <Tag ok={i.ok}>
                      {i.ok ? "Нарушений нет" : `${i.reason}${i.failed ? ` (${i.failed})` : ""}`}
                    </Tag>
                  </Td>
                  <Td>
                    {i.manifest_version || "—"}
                    {i.test_signed ? " (тестовый ключ)" : ""}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Шлюзы">
        {gone.has("gateways") ? (
          <p className="text-sm text-muted">Недоступно.</p>
        ) : s.gateways.length === 0 ? (
          <p className="text-sm text-muted">Шлюзов нет. Зарегистрируйте шлюз командой aisec-gateway register.</p>
        ) : (
          <Table aria-label="Шлюзы">
            <thead>
              <tr>
                <Th>Шлюз</Th>
                <Th>Связь</Th>
                <Th>Версия</Th>
                <Th>Сертификат до</Th>
                <Th>Самотест</Th>
                <Th>Целостность</Th>
              </tr>
            </thead>
            <tbody>
              {s.gateways.map((g) => (
                <tr key={g.id}>
                  <Td>{g.name}</Td>
                  <Td>
                    <Tag ok={g.state === "online" ? true : g.state === "pending" ? null : false}>{gatewayText.get(g.state) ?? g.state}</Tag>
                    <div className="text-xs text-muted">последний контакт {when(g.last_seen_at)}</div>
                  </Td>
                  <Td>{g.version || "—"}</Td>
                  <Td>{when(g.cert_not_after)}</Td>
                  <Td>
                    <Report r={g.selftest} what="самотест" />
                  </Td>
                  <Td>
                    <Report r={g.integrity} what="целостность" />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="События">
        {gone.has("events") ? (
          <p className="text-sm text-muted">Недоступно.</p>
        ) : (
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
            <dt className="text-muted">Отброшено шлюзами</dt>
            <dd>{formatNumber(s.events.dropped)}</dd>
            <dt className="text-muted">Отклонено сервером</dt>
            <dd>{formatNumber(s.events.rejected)}</dd>
          </dl>
        )}
        <p className="text-xs text-muted">Счётчики идут с последнего запуска каждого шлюза.</p>
      </Section>

      {s.shadow_ai_syslog && (
        <Section title="Приём журналов теневого ИИ по syslog">
          <SyslogPanel s={s.shadow_ai_syslog} />
        </Section>
      )}

      <Section title="Время">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
          <dt className="text-muted">Время сервера (UTC)</dt>
          <dd>{formatAbsolute(s.time.server_time)}</dd>
          <dt className="text-muted">Часовой пояс показа</dt>
          <dd>{s.time.timezone}</dd>
          <dt className="text-muted">Синхронизация</dt>
          <dd>
            <Tag ok={s.time.sync === "synchronized" ? true : s.time.sync === "unknown" ? null : false}>{syncText.get(s.time.sync) ?? s.time.sync}</Tag>
            {s.time.error_micros !== null && <span className="text-muted">, ошибка около {formatNumber(s.time.error_micros)} мкс</span>}
          </dd>
        </dl>
        {s.time.sync !== "synchronized" && (
          <p className="text-sm text-muted">
            Время синхронизируется на хосте, сервер его только наблюдает. Как настроить источники времени — в руководстве docs/install/time-sync.md.
          </p>
        )}
      </Section>

      <Section title="Журнал аудита">
        {gone.has("storage") ? (
          <p className="text-sm text-muted">Заполнение журнала недоступно.</p>
        ) : s.storage.available ? (
          <div className="flex flex-col gap-1">
            <div
              role="progressbar"
              aria-label="Заполнение журнала аудита"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={s.storage.used_percent}
              className="h-2 w-full overflow-hidden rounded-full bg-bg"
            >
              <div className="h-full bg-accent" style={{ width: `${s.storage.used_percent}%` }} />
            </div>
            <p className="text-base">
              <Tag ok={!s.storage.warn_exceeded}>
                Занято {formatBytes(s.storage.audit_bytes)} из {formatBytes(s.storage.limit_bytes)} ({s.storage.used_percent}%)
              </Tag>
            </p>
            <p className="text-xs text-muted">
              Предупреждение при {s.storage.warn_percent}%. {s.storage.warn_exceeded ? "Порог превышен: архивируйте журнал." : ""}
            </p>
          </div>
        ) : (
          <p className="text-sm text-muted">Размер журнала определить не удалось. Предел {formatBytes(s.storage.limit_bytes)}, порог {s.storage.warn_percent}%.</p>
        )}
        {gone.has("audit_chain") ? (
          <p className="text-sm text-muted">Итог проверки цепочки недоступен.</p>
        ) : s.audit_chain ? (
          <p className="text-base">
            <Tag ok={s.audit_chain.ok}>
              Проверка цепочки от {formatAbsolute(s.audit_chain.checked_at)}: {s.audit_chain.ok ? "цепочка цела" : chainReasonText.get(s.audit_chain.reason) ?? s.audit_chain.reason}
            </Tag>
            <span className="text-muted">
              {" "}
              Проверено записей: {formatNumber(s.audit_chain.checked)}
              {s.audit_chain.broken_seq !== null ? `, нарушение на записи ${s.audit_chain.broken_seq}` : ""}.
            </span>
          </p>
        ) : (
          <p className="text-sm text-muted">Проверок цепочки журнала ещё не было. Сервер проверяет её при запуске и раз в час; вручную — aisec-cli audit verify.</p>
        )}
      </Section>
    </>
  );
}
