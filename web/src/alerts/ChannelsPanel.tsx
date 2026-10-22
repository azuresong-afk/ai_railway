import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { alertsApi, type NotifyChannel, type NotifyDelivery } from "./api";
import { ChannelDialog } from "./ChannelDialog";

const typeText = { email: "Почта", webhook: "Webhook", syslog: "Syslog" } as const;
const delivText = { pending: "Ожидает", sent: "Доставлено", failed: "Не доставлено" } as const;
const secretText = new Map<string, string>([
  ["password", "пароль"],
  ["url", "адрес"],
  ["signing_key", "ключ подписи"],
]);

function Deliveries({ channel, onClose }: { channel: NotifyChannel; onClose: () => void }) {
  const q = useQuery({ queryKey: ["alerts", "deliveries", channel.id], queryFn: ({ signal }) => alertsApi.deliveries(channel.id, signal) });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Журнал доставки: ${channel.name}`} description="Последние 50 записей, новые сверху. Содержимого оповещений и секретов здесь нет.">
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка…</p>}
      {q.data && q.data.items.length === 0 && <p className="text-sm text-muted">Отправок не было.</p>}
      {q.data && q.data.items.length > 0 && (
        <div className="max-h-80 overflow-auto">
          <Table>
            <thead>
              <tr>
                <Th>Время</Th>
                <Th>Вид</Th>
                <Th>Итог</Th>
                <Th>Попыток</Th>
                <Th>Код ошибки</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((d: NotifyDelivery) => (
                <tr key={d.id}>
                  <Td>{formatAbsolute(d.created_at)}</Td>
                  <Td>{d.kind === "test" ? "Тест" : "Оповещение"}</Td>
                  <Td>{delivText[d.status]}</Td>
                  <Td>{d.attempts}</Td>
                  <Td className="font-mono">{d.error ?? "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      <div className="flex justify-end">
        <Button onClick={onClose}>Закрыть</Button>
      </div>
    </FormDialog>
  );
}

// Каналы уведомлений: почта, webhook, syslog. Секреты — только «задан»; тестовая отправка и журнал доставки.
export function ChannelsPanel({ me }: { me: Me }) {
  const qc = useQueryClient();
  const canManage = me.permissions.includes("notify_channels.manage");
  const q = useQuery({ queryKey: ["alerts", "channels"], queryFn: ({ signal }) => alertsApi.channels(signal) });
  const [dialog, setDialog] = useState<{ channel: NotifyChannel | null }>();
  const [log, setLog] = useState<NotifyChannel>();
  const [result, setResult] = useState<{ name: string; d: NotifyDelivery }>();
  const test = useMutation({
    mutationFn: (c: NotifyChannel) => alertsApi.testChannel(c.id).then((d) => ({ name: c.name, d })),
    onSuccess: async (r) => {
      setResult(r);
      await qc.invalidateQueries({ queryKey: ["alerts", "deliveries"] });
    },
  });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted">Оповещения от заданной серьёзности уходят во включённые каналы. Не больше 50 каналов.</p>
        {canManage && (
          <Button variant="primary" onClick={() => setDialog({ channel: null })}>
            Создать канал
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      <ErrorBanner error={test.error} />
      {result && (
        <Banner kind={result.d.status === "sent" ? "info" : "error"}>
          Тест канала «{result.name}»: {result.d.status === "sent" ? "доставлено" : `не доставлено (код ошибки: ${result.d.error ?? "неизвестен"})`}.
        </Banner>
      )}
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка каналов…</p>}
      {q.data && q.data.items.length === 0 && (
        <EmptyState title="Каналов уведомлений нет" action={<p className="text-sm text-muted">{canManage ? "Создайте канал, чтобы получать оповещения вне консоли." : "Канал создаёт администратор безопасности."}</p>} />
      )}
      {q.data && q.data.items.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>Тип</Th>
                <Th>Получатель</Th>
                <Th>Секреты</Th>
                <Th>Состояние</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((c) => (
                <tr key={c.id}>
                  <Td>{c.name}</Td>
                  <Td>{typeText[c.type]}</Td>
                  <Td className="font-mono text-sm">{c.settings.url_origin ?? (c.settings.host ? `${c.settings.host}${c.settings.port ? `:${c.settings.port}` : ""}` : "—")}</Td>
                  <Td>{c.secrets_set.length === 0 ? "не заданы" : `заданы: ${c.secrets_set.map((s) => secretText.get(s)).join(", ")}`}</Td>
                  <Td>{c.enabled ? "Включён" : "Отключён"}</Td>
                  <Td>
                    <span className="flex gap-2">
                      <Button onClick={() => setLog(c)} aria-label={`Журнал доставки ${c.name}`}>
                        Журнал
                      </Button>
                      {canManage && (
                        <>
                          <Button disabled={test.isPending} onClick={() => test.mutate(c)} aria-label={`Тестовая отправка ${c.name}`}>
                            Тест
                          </Button>
                          <Button onClick={() => setDialog({ channel: c })} aria-label={`Изменить канал ${c.name}`}>
                            Изменить
                          </Button>
                        </>
                      )}
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {dialog && <ChannelDialog key={dialog.channel?.id ?? "new"} channel={dialog.channel} mfa={me.mfa?.enabled === true} onClose={() => setDialog(undefined)} />}
      {log && <Deliveries channel={log} onClose={() => setLog(undefined)} />}
    </div>
  );
}
