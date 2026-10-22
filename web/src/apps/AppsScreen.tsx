import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ConfirmDialog, ErrorBanner } from "../admin/common";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { type Application, appsApi } from "./api";
import { ConnectWizard } from "./ConnectWizard";
import { KeysPanel } from "./KeysPanel";
import { ProtectionDialog } from "./ProtectionDialog";

const envText = { prod: "Промышленная", test: "Тестовая" } as const;
const modeText = { monitor: "Мониторинг", enforce: "Защита" } as const;
const storageText = { none: "Не хранить", masked: "Маскированное", full: "Полное" } as const;

// Экран «Приложения» (ТЗ 6.3, п. 5): список, мастер подключения, ключи. Кнопки показываются по правам из сессии;
// владелец видит только свои приложения, а решение о доступе всегда принимает сервер.
export function AppsScreen({ me }: { me: Me }) {
  const qc = useQueryClient();
  const has = (p: string) => me.permissions.includes(p);
  const q = useQuery({ queryKey: ["apps", "list"], queryFn: ({ signal }) => appsApi.applications(signal) });
  const [wizard, setWizard] = useState(false);
  const [selected, setSelected] = useState<string>();
  const [archive, setArchive] = useState<Application>();
  const [protect, setProtect] = useState<Application>();
  const mfa = me.mfa?.enabled === true;
  const archiveM = useMutation({
    mutationFn: (a: Application) => appsApi.archive(a.id),
    onSuccess: () => {
      setArchive(undefined);
      return qc.invalidateQueries({ queryKey: ["apps"] });
    },
  });
  const current = q.data?.find((a) => a.id === selected);

  return (
    <section aria-label="Приложения" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Приложения</h1>
        {has("applications.manage") && (
          <Button variant="primary" onClick={() => setWizard(true)}>
            Подключить приложение
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка приложений…</p>}
      {q.data && q.data.length === 0 && (
        <EmptyState
          title="Приложений пока нет"
          action={
            has("applications.manage") ? (
              <Button variant="primary" onClick={() => setWizard(true)}>
                Подключить первое приложение
              </Button>
            ) : (
              <p className="text-sm text-muted">Приложение подключает администратор. Обратитесь к нему.</p>
            )
          }
        />
      )}
      {q.data && q.data.length > 0 && (
        <Panel className="overflow-auto p-0">
          <Table>
            <thead>
              <tr>
                <Th>Название</Th>
                <Th>ID</Th>
                <Th>Среда</Th>
                <Th>Политика</Th>
                <Th>Режим</Th>
                <Th>Хранение</Th>
                <Th>Создано</Th>
                <Th>Действия</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.id} aria-selected={a.id === selected}>
                  <Td>
                    {a.name}
                    {a.status === "archived" && <span className="ml-2 text-xs text-muted">(в архиве)</span>}
                  </Td>
                  <Td className="font-mono">{a.slug}</Td>
                  <Td>{envText[a.env]}</Td>
                  <Td>{a.policy}</Td>
                  <Td>{modeText[a.policy_mode]}</Td>
                  <Td>{storageText[a.storage]}</Td>
                  <Td>{formatAbsolute(a.created_at)}</Td>
                  <Td>
                    <span className="flex gap-2">
                      <Button onClick={() => setSelected(a.id === selected ? undefined : a.id)} aria-label={`Ключи приложения ${a.name}`}>
                        Ключи
                      </Button>
                      {has("applications.policy") && a.status === "active" && (
                        <Button onClick={() => setProtect(a)} aria-label={`Защита приложения ${a.name}`}>
                          Защита
                        </Button>
                      )}
                      {has("applications.manage") && a.status === "active" && (
                        <Button
                          variant="danger"
                          aria-label={`В архив: ${a.name}`}
                          onClick={() => {
                            archiveM.reset();
                            setArchive(a);
                          }}
                        >
                          В архив
                        </Button>
                      )}
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}
      {current && <KeysPanel key={current.id} app={current} canKey={has("app_keys.manage")} />}

      {protect && <ProtectionDialog key={protect.id} app={protect} mfa={mfa} onClose={() => setProtect(undefined)} />}
      <ConnectWizard
        open={wizard}
        onClose={() => setWizard(false)}
        canPolicy={has("applications.policy")}
        canKey={has("app_keys.manage")}
        mfa={mfa}
      />
      <ConfirmDialog
        open={archive !== undefined}
        onOpenChange={(v) => !v && setArchive(undefined)}
        title="Перевести приложение в архив"
        description={
          <>
            Приложение «{archive?.name}» перестанет принимать запросы: все его ключи будут отозваны сразу. История событий и аудита
            сохранится, вернуть приложение из архива нельзя.
          </>
        }
        actionLabel="Перевести в архив и отозвать ключи"
        busy={archiveM.isPending}
        error={archiveM.error}
        onConfirm={() => archive && archiveM.mutate(archive)}
      />
    </section>
  );
}
