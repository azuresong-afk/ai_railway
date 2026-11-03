import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../api/client";
import { ConfirmDialog, ErrorBanner, FormDialog } from "../admin/common";
import { SecretField, secretBody } from "../agents/Secret";
import { formatAbsolute, formatNumber } from "../events/format";
import { formatBytes } from "../system/format";
import { Button } from "../ui/Button";
import { Banner, EmptyState, Panel, Table, Td, Th } from "../ui/Layout";
import { inventoryApi, type ModelCard } from "./api";
import { kindTitle, originTitle, roleTitle } from "./format";
import { ModelStatus } from "./Marks";
import { ModelDialog } from "./ModelDialog";
import { ScanReports } from "./ScanReports";

// Снятие запрета — ослабление защиты (DM-40): повторная проверка пароля или кода, только в сессии консоли.
function UnblockDialog({ card, mfa, onClose }: { card: ModelCard; mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [secret, setSecret] = useState("");
  const unblock = useMutation({
    mutationFn: () => inventoryApi.unblock(card.id, secretBody(mfa, secret)),
    onSuccess: async () => {
      setSecret("");
      await qc.invalidateQueries({ queryKey: ["inventory"] });
      onClose();
    },
    onError: () => setSecret(""),
  });
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title="Снятие запрета с модели"
      description={`Модель «${card.title || card.name}» вернётся в пакет шлюзов, и приложения снова смогут её использовать.`}
    >
      <Banner kind="warning">
        Это ослабление защиты. Сначала убедитесь, что файлы на узле заменены или проверены: новый отчёт сканера с той же находкой или расхождением хешей
        запретит модель снова. Действие записывается в журнал аудита, администраторы безопасности получают оповещение.
      </Banner>
      <SecretField mfa={mfa} value={secret} onChange={setSecret} />
      <ErrorBanner error={unblock.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="danger" disabled={unblock.isPending || secret === ""} onClick={() => unblock.mutate()}>
          Снять запрет
        </Button>
      </div>
    </FormDialog>
  );
}

// Карточка модели (задача 5.23): сведения, файлы с хешами, использование приложениями, отчёты сканера, запрет и его снятие.
export function ModelCardView({
  id,
  canManage,
  canUnblock,
  mfa,
  onBack,
}: {
  id: string;
  canManage: boolean;
  canUnblock: boolean;
  mfa: boolean;
  onBack: () => void;
}) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["inventory", "model", id], queryFn: ({ signal }) => inventoryApi.model(id, signal) });
  const overview = useQuery({ queryKey: ["inventory", "overview"], queryFn: ({ signal }) => inventoryApi.overview(signal) });
  const [editing, setEditing] = useState(false);
  const [unblocking, setUnblocking] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const remove = useMutation({
    mutationFn: () => inventoryApi.remove(id),
    onSuccess: async () => {
      setDeleting(false);
      await qc.invalidateQueries({ queryKey: ["inventory"] });
      onBack();
    },
  });
  const c = q.data;

  const back = (
    <div>
      <Button variant="ghost" onClick={onBack}>
        ← Все модели
      </Button>
    </div>
  );
  if (q.error instanceof ApiError && q.error.status === 404) {
    return (
      <div className="flex flex-col gap-3">
        {back}
        <EmptyState title="Модель не найдена" action={<p className="text-sm text-muted">Возможно, её удалили. Вернитесь к списку моделей.</p>} />
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {back}
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка карточки…</p>}
      {c && (
        <>
          <Panel role="region" aria-label="Карточка модели" className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-xl font-semibold break-words">{c.title || c.name}</h2>
              <ModelStatus status={c.status} />
            </div>
            {c.status === "blocked" && (
              <Banner kind="error">
                Использование модели запрещено: она исключена из пакета шлюзов, приложения получают отказ «model_not_allowed». Причины — в последнем отчёте
                сканера ниже.
              </Banner>
            )}
            {notice && <Banner kind="info">{notice}</Banner>}
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
              <dt className="text-muted">Имя</dt>
              <dd className="break-words">{c.name}</dd>
              <dt className="text-muted">Версия</dt>
              <dd>{c.version || "—"}</dd>
              <dt className="text-muted">Вид</dt>
              <dd>{kindTitle.get(c.kind)}</dd>
              <dt className="text-muted">Провайдер</dt>
              <dd>{overview.data?.providers.find((p) => p.slug === c.provider)?.name ?? (c.provider || "—")}</dd>
              <dt className="text-muted">Происхождение</dt>
              <dd>{originTitle.get(c.origin)}</dd>
              <dt className="text-muted">Ответственный</dt>
              <dd className="break-words">{c.owner || "—"}</dd>
              <dt className="text-muted">Описание</dt>
              <dd className="break-words">{c.description || "—"}</dd>
              <dt className="text-muted">В трафике</dt>
              <dd>{c.first_seen && c.last_seen ? `с ${formatAbsolute(c.first_seen)} по ${formatAbsolute(c.last_seen)}` : "не встречалась"}</dd>
              <dt className="text-muted">Изменена</dt>
              <dd>{formatAbsolute(c.updated_at)}</dd>
            </dl>
            {(canManage || (canUnblock && c.status === "blocked")) && (
              <div className="flex flex-wrap gap-2">
                {canUnblock && c.status === "blocked" && (
                  <Button variant="danger" onClick={() => setUnblocking(true)}>
                    Снять запрет
                  </Button>
                )}
                {canManage && <Button onClick={() => setEditing(true)}>Изменить модель</Button>}
                {canManage && c.status !== "blocked" && (
                  <Button variant="danger" onClick={() => setDeleting(true)}>
                    Удалить модель
                  </Button>
                )}
              </div>
            )}
            {canManage && c.status === "blocked" && <p className="text-sm text-muted">Запрещённую модель удалить нельзя: сначала администратор безопасности снимает запрет.</p>}
            {c.status === "blocked" && !canUnblock && <p className="text-sm text-muted">Снять запрет может только администратор безопасности.</p>}
          </Panel>

          <Panel role="region" aria-label="Файлы модели" className="flex flex-col gap-2">
            <h3 className="text-lg font-semibold">Файлы и эталонные хеши</h3>
            <p className="text-sm text-muted">Эталон для «aisec-cli models verify»: хеши весов и адаптеров на узле сравниваются с этими значениями.</p>
            {c.files.length === 0 ? (
              <p className="text-sm text-muted">Файлов в реестре нет: сверка хешей для этой модели не выполняется.</p>
            ) : (
              <div className="overflow-auto">
                <Table aria-label="Файлы модели">
                  <thead>
                    <tr>
                      <Th>Файл</Th>
                      <Th>Роль</Th>
                      <Th className="text-right">Размер</Th>
                      <Th>SHA-256</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.files.map((f) => (
                      <tr key={f.path}>
                        <Td className="break-all font-mono text-sm">{f.path}</Td>
                        <Td>{roleTitle.get(f.role)}</Td>
                        <Td className="text-right">{formatBytes(f.size)}</Td>
                        <Td className="break-all font-mono text-xs">{f.sha256}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </Panel>

          <Panel role="region" aria-label="Использование моделью приложениями" className="flex flex-col gap-2">
            <h3 className="text-lg font-semibold">Какие приложения используют модель</h3>
            {c.usage.length === 0 ? (
              <p className="text-sm text-muted">В трафике шлюзов модель не встречалась.</p>
            ) : (
              <div className="overflow-auto">
                <Table aria-label="Использование модели">
                  <thead>
                    <tr>
                      <Th>Приложение</Th>
                      <Th>Провайдер</Th>
                      <Th>Впервые</Th>
                      <Th>Последний раз</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.usage.map((u) => (
                      <tr key={`${u.application}:${u.provider}`}>
                        <Td>{u.application}</Td>
                        <Td>{u.provider || "—"}</Td>
                        <Td>{formatAbsolute(u.first_seen)}</Td>
                        <Td>{formatAbsolute(u.last_seen)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
            {c.usage.length > 0 && <p className="text-sm text-muted">Записей: {formatNumber(c.usage.length)} (показаны до 200). Счётчики запросов — на дашбордах.</p>}
          </Panel>

          <ScanReports modelId={c.id} />

          {editing && (
            <ModelDialog
              mode="edit"
              card={c}
              providers={overview.data?.providers ?? []}
              onClose={() => setEditing(false)}
              onDone={() => setNotice("Изменения сохранены.")}
            />
          )}
          {unblocking && <UnblockDialog card={c} mfa={mfa} onClose={() => setUnblocking(false)} />}
          <ConfirmDialog
            open={deleting}
            onOpenChange={(v) => {
              if (!v) {
                setDeleting(false);
                remove.reset();
              }
            }}
            title="Удалить модель из реестра?"
            description="Модель удаляется вместе с файлами, хешами и отчётами сканера. Если приложения продолжают её вызывать, она появится в реестре снова по трафику. Чтобы модель не использовали, уберите её из разрешённых моделей приложения."
            actionLabel="Удалить модель"
            busy={remove.isPending}
            error={remove.error}
            onConfirm={() => remove.mutate()}
          />
        </>
      )}
    </div>
  );
}
