import type { components } from "../api/schema";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "./Button";
import { Table, Td, Th } from "./Layout";
import { Confirm } from "./Overlay";

export type ServiceDBVersion = components["schemas"]["ServiceDBVersion"];

// Причина, по которой сохранённая версия не прошла проверку (ADR-0028).
const reasons: Record<NonNullable<ServiceDBVersion["reason"]>, string> = {
  signature: "подпись неверна",
  purpose: "ключ заверен не для служебных баз",
  kind: "другой вид базы",
  expired: "срок заверения ключа",
  date: "дата вне срока заверения ключа",
  revoked: "ключ отозван производителем",
  content: "содержимое не прошло проверку",
  format: "файл повреждён",
};

function Row({ title, v, active }: { title: string; v: ServiceDBVersion | undefined; active: boolean }) {
  if (!v) {
    return (
      <tr>
        <Td>{title}</Td>
        <Td colSpan={4} className="text-muted">
          нет
        </Td>
      </tr>
    );
  }
  return (
    <tr>
      <Td>
        {title}
        {active && <span className="text-muted"> (действует)</span>}
      </Td>
      <Td>
        {v.version} от {v.date}
      </Td>
      <Td>{formatNumber(v.records)}</Td>
      <Td>{formatAbsolute(v.uploaded_at)}</Td>
      <Td>{v.valid ? "проверена" : `не прошла проверку: ${reasons[v.reason ?? "format"]}`}</Td>
    </tr>
  );
}

// Текущая и предыдущая версии служебной базы и возврат предыдущей
// (задача 5.15): возврат подтверждается, сервер перед ним заново
// проверяет подпись предыдущей версии.
export function ServiceDBVersions({
  title,
  recordsTitle,
  current,
  previous,
  active,
  canManage,
  pending,
  onRollback,
}: {
  // title — название базы в винительном падеже: «каталог», «базу требований».
  title: string;
  recordsTitle: string;
  current: ServiceDBVersion | undefined;
  previous: ServiceDBVersion | undefined;
  active: "current" | "previous" | "none";
  canManage: boolean;
  pending: boolean;
  onRollback: () => void;
}) {
  if (!current && !previous) return null;
  return (
    <div className="flex flex-col gap-2">
      <Table aria-label="Сохранённые версии">
        <thead>
          <tr>
            <Th>Версия</Th>
            <Th>Номер и дата выпуска</Th>
            <Th>{recordsTitle}</Th>
            <Th>Загружена</Th>
            <Th>Подпись</Th>
          </tr>
        </thead>
        <tbody>
          <Row title="Текущая" v={current} active={active === "current"} />
          <Row title="Предыдущая" v={previous} active={active === "previous"} />
        </tbody>
      </Table>
      {canManage && previous && !previous.valid && (
        <p className="text-muted">Предыдущую версию вернуть нельзя: она не прошла проверку подписи. Загрузите файл из текущего выпуска.</p>
      )}
      {canManage && previous?.valid && (
        <div>
          <Confirm
            trigger={<Button disabled={pending}>Вернуть предыдущую версию</Button>}
            title={`Вернуть предыдущую версию: ${title}`}
            description={`Версия ${previous.version} от ${previous.date} станет текущей, версия ${current?.version ?? "—"} будет удалена с сервера. Её можно загрузить снова тем же файлом. Перед возвратом сервер заново проверит подпись предыдущей версии.`}
            actionLabel="Вернуть версию"
            onConfirm={onRollback}
          />
        </div>
      )}
    </div>
  );
}
