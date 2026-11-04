import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ConfirmDialog, ErrorBanner } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Banner, EmptyState, Table, Td, Th } from "../ui/Layout";
import { redteamApi, type Target } from "./api";
import { TargetDialog, useApps } from "./TargetDialog";

const kindTitle = new Map<Target["kind"], string>([
  ["gateway", "Приложение продукта (через шлюз)"],
  ["endpoint", "Адрес приложения заказчика"],
]);

// Вкладка «Цели»: список разрешённых адресов (allowlist), на которые продукт отправляет атаки. Секретных значений в списке нет.
export function TargetsTab({ canManage, mfa }: { canManage: boolean; mfa: boolean }) {
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Target | null>(null);
  const apps = useApps();
  const appName = (id: string | undefined) => apps.data?.find((a) => a.id === id)?.name ?? (id ? `${id.slice(0, 8)}…` : "");
  const q = useQuery({ queryKey: ["redteam", "targets"], queryFn: ({ signal }) => redteamApi.targets(signal) });
  const remove = useMutation({
    mutationFn: (id: string) => redteamApi.deleteTarget(id),
    onSuccess: async () => {
      setRemoving(null);
      await qc.invalidateQueries({ queryKey: ["redteam"] });
    },
  });
  const items = q.data?.items ?? [];
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          Атаки отправляются только на цели из этого списка. Цель «через шлюз» — приложение продукта: проверяются его политика и детекторы. Цель «адрес
          приложения заказчика» — внешний адрес, его добавляют с основанием (договор, письмо) и повторным вводом пароля.
        </p>
        {canManage && <Button variant="primary" onClick={() => setAdding(true)}>Добавить цель</Button>}
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка целей…</p>}
      {q.data && !q.data.gateway_configured && (
        <Banner kind="warning">
          Адрес шлюза для тестирования не задан: цели «через шлюз» запускать нельзя. Запустите сервер с флагом -redteam-gateway-url.
        </Banner>
      )}
      {q.data && items.length === 0 && (
        <EmptyState title="Целей ещё нет." action={<p className="text-sm text-muted">{canManage ? "Добавьте приложение продукта или адрес приложения заказчика." : "Цели добавляет администратор безопасности."}</p>} />
      )}
      {items.length > 0 && (
        <div className="overflow-auto">
          <Table aria-label="Цели тестирования">
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>Вид</Th>
                <Th>Адрес или приложение</Th>
                <Th>Хранение выдержек</Th>
                <Th>Изменена</Th>
                {canManage && <Th>Действия</Th>}
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <Td className="break-words">{t.name}</Td>
                  <Td>{kindTitle.get(t.kind) ?? t.kind}</Td>
                  <Td className="font-mono text-sm break-all">
                    {t.kind === "endpoint" ? t.url : `${appName(t.app_id)}, модель ${t.model ?? ""}`}
                    {t.kind === "endpoint" && t.auth_header && <div className="text-xs text-muted">секретный заголовок: {t.auth_header}</div>}
                  </Td>
                  <Td>{t.storage === "masked" ? "замаскированные, до 1 КиБ" : "не хранятся"}</Td>
                  <Td>
                    {formatAbsolute(t.updated_at)}
                    <div className="text-xs text-muted break-words">{t.updated_by}</div>
                  </Td>
                  {canManage && (
                    <Td>
                      <Button onClick={() => setRemoving(t)}>Удалить</Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {adding && <TargetDialog mfa={mfa} onClose={() => setAdding(false)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => {
          if (!v) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Удалить цель"
        description={
          <>
            Цель «{removing?.name}» исчезнет из списка, расписания запусков по ней будут удалены. Прошлые запуски и их итоги останутся.
          </>
        }
        actionLabel="Удалить цель"
        busy={remove.isPending}
        error={remove.error}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </div>
  );
}
