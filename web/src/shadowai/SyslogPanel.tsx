import { formatAbsolute, formatNumber } from "../events/format";
import { Banner, Table, Td } from "../ui/Layout";
import type { ShadowSyslog } from "./api";

// Счётчики приёма по syslog: отказы и разрывы сверх пределов, строки, запись сводок. Содержимого строк нет.
type Row = [(s: ShadowSyslog) => number, string];
const rejects: Row[] = [
  [(s) => s.accept_errors, "Временные ошибки приёма соединений"],
  [(s) => s.rejected_network, "Отказ: источник не из разрешённых сетей"],
  [(s) => s.rejected_limit, "Отказ: сверх предела соединений"],
  [(s) => s.tls_failed, "Рукопожатие TLS не удалось"],
  [(s) => s.frame_too_large, "Разрыв: кадр длиннее предела"],
  [(s) => s.bad_frame, "Разрыв: поток оборван внутри кадра"],
  [(s) => s.idle_timeouts, "Разрыв: нет данных дольше срока простоя"],
  [(s) => s.read_timeouts, "Разрыв: кадр не пришёл целиком за срок"],
];
const lines: Row[] = [
  [(s) => s.lines, "Строк принято"],
  [(s) => s.matched, "Обращений к сервисам каталога"],
  [(s) => s.unmatched, "Обращений к прочим узлам"],
  [(s) => s.errors, "Строк не разобрано"],
  [(s) => s.excluded, "Строк исключённых пользователей и сервисов"],
  [(s) => s.outdated, "Строк старше срока хранения"],
  [(s) => s.no_catalog, "Строк до загрузки каталога (не учтены)"],
  [(s) => s.dropped, "Строк сверх предела сводок в памяти (не учтены)"],
  [(s) => s.unlicensed, "Строк без модуля лицензии (не учтены)"],
  [(s) => s.throttled, "Кадров задержано пределом строк в секунду"],
];

function Counters({ s, rows, label }: { s: ShadowSyslog; rows: Row[]; label: string }) {
  return (
    <Table aria-label={label}>
      <tbody>
        {rows.map(([get, title]) => (
          <tr key={title}>
            <Td>{title}</Td>
            <Td className="text-right">{formatNumber(get(s))}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

// Состояние слушателя syslog: на экране «Теневой ИИ» и в «Состоянии системы».
export function SyslogPanel({ s }: { s: ShadowSyslog }) {
  if (!s.enabled) {
    return (
      <p className="text-sm text-muted">
        Приём журналов по syslog выключен. Он включается флагами сервера -shadow-ai-syslog-* (руководство администратора, раздел «Теневой ИИ:
        приём по syslog»). Журналы можно импортировать файлом.
      </p>
    );
  }
  const failed = s.last_flush_failed;
  return (
    <div className="flex flex-col gap-3">
      {!s.running && (
        <Banner kind="error">
          Приём по syslog остановлен{s.stopped_at ? ` ${formatAbsolute(s.stopped_at)}` : ""}: новые строки не принимаются. Причина в журнале сервера
          {s.last_error ? ` («${s.last_error}»)` : ""}. Перезапустите сервер управления.
        </Banner>
      )}
      {!s.license_module && (
        <Banner kind="error">
          Модуль «Теневой ИИ» не входит в лицензию: строки по syslog принимаются, но не учитываются. Чтобы включить модуль, загрузите
          лицензию с ним.
        </Banner>
      )}
      {failed && <Banner kind="error">Последняя запись сводок в базу не удалась. Строки сохранены в памяти, сервер повторит запись.</Banner>}
      {!s.tls && <Banner kind="warning">Приём без TLS: журналы идут по сети открытым текстом. Источники ограничены разрешёнными сетями.</Banner>}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
        <dt className="text-muted">Адрес</dt>
        <dd className="font-mono text-sm">{s.address}</dd>
        <dt className="text-muted">Формат сообщений</dt>
        <dd>{s.format === "cef" ? "CEF" : "Squid"}</dd>
        <dt className="text-muted">Защита канала</dt>
        <dd>{s.tls ? (s.client_cert_required ? "TLS, клиентский сертификат обязателен" : "TLS") : "без TLS"}</dd>
        <dt className="text-muted">Разрешённые сети</dt>
        <dd>{s.allowed_networks.length ? s.allowed_networks.join(", ") : "любые"}</dd>
        <dt className="text-muted">Запущен</dt>
        <dd>{s.started_at ? formatAbsolute(s.started_at) : "—"}</dd>
        <dt className="text-muted">Соединений</dt>
        <dd>
          {formatNumber(s.connections)} из {formatNumber(s.limits.max_connections)}, с одного адреса до {formatNumber(s.limits.max_connections_per_address)}
        </dd>
        <dt className="text-muted">Пределы</dt>
        <dd>
          кадр до {formatNumber(s.limits.max_frame_bytes)} байт, {formatNumber(s.limits.lines_per_second)} строк в секунду, простой{" "}
          {formatNumber(s.limits.idle_timeout_seconds)} с, кадр за {formatNumber(s.limits.frame_timeout_seconds)} с
        </dd>
        <dt className="text-muted">Запись сводок</dt>
        <dd>
          {s.last_flush_at ? `последняя ${formatAbsolute(s.last_flush_at)}` : "ещё не было"}
          {s.flush_failures ? `, неудачных: ${formatNumber(s.flush_failures)}` : ""}, в памяти сводок: {formatNumber(s.pending)}
        </dd>
      </dl>
      <div className="grid gap-3 md:grid-cols-2">
        <Counters s={s} rows={[[(s) => s.accepted, "Соединений принято"], ...rejects]} label="Соединения syslog" />
        <Counters s={s} rows={lines} label="Строки syslog" />
      </div>
      <p className="text-xs text-muted">Счётчики идут с последнего запуска сервера.</p>
    </div>
  );
}
