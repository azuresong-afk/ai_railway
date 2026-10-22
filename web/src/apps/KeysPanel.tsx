import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { ConfirmDialog, ErrorBanner, FormDialog } from "../admin/common";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Panel, Table, Td, Th } from "../ui/Layout";
import { type Application, type AppKey, appsApi, splitList } from "./api";
import { ShownKey } from "./ShownKey";

const statusText: Record<AppKey["status"], string> = { active: "Действует", expired: "Истёк", revoked: "Отозван" };

// Ключи выбранного приложения (ИАФ.8): выпуск, ротация, отзыв. Новый ключ показывается один раз и стирается из состояния при закрытии.
export function KeysPanel({ app, canKey }: { app: Application; canKey: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["apps", "keys", app.id], queryFn: ({ signal }) => appsApi.keys(app.id, signal) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["apps", "keys", app.id] });
  const [secret, setSecret] = useState<string>();
  const [issue, setIssue] = useState(false);
  const [rotate, setRotate] = useState<AppKey>();
  const [revoke, setRevoke] = useState<AppKey>();
  const [name, setName] = useState("");
  const [days, setDays] = useState("365");
  const [cidrs, setCidrs] = useState("");
  const [overlap, setOverlap] = useState("24");

  const issueM = useMutation({
    mutationFn: () =>
      appsApi.issueKey(app.id, {
        name: name.trim(),
        expires_in_days: Number(days),
        ...(splitList(cidrs).length > 0 ? { allowed_cidrs: splitList(cidrs) } : {}),
      }),
    onSuccess: (k) => {
      setSecret(k.key);
      setIssue(false);
      void refresh();
    },
  });
  const rotateM = useMutation({
    mutationFn: (k: AppKey) => appsApi.rotateKey(k.id, { overlap_hours: Number(overlap), expires_in_days: Number(days) }),
    onSuccess: (k) => {
      setSecret(k.key);
      setRotate(undefined);
      void refresh();
    },
  });
  const revokeM = useMutation({
    mutationFn: (k: AppKey) => appsApi.revokeKey(k.id),
    onSuccess: () => {
      setRevoke(undefined);
      void refresh();
    },
  });

  const daysBad = !Number.isInteger(Number(days)) || Number(days) < 1 || Number(days) > 730;
  const overlapBad = !Number.isInteger(Number(overlap)) || Number(overlap) < 0 || Number(overlap) > 720;
  const archived = app.status === "archived";
  const submitIssue = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim() && !daysBad) issueM.mutate();
  };
  const submitRotate = (e: FormEvent) => {
    e.preventDefault();
    if (rotate && !daysBad && !overlapBad) rotateM.mutate(rotate);
  };

  return (
    <Panel aria-label={`Ключи приложения ${app.name}`} className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-md font-semibold">Ключи приложения «{app.name}»</h2>
        {canKey && !archived && (
          <Button
            variant="primary"
            onClick={() => {
              issueM.reset();
              setName("");
              setIssue(true);
            }}
          >
            Выпустить ключ
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.data && q.data.items.length === 0 && <p className="text-sm text-muted">Ключей нет.</p>}
      {q.data && q.data.items.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Название</Th>
              <Th>Начало ключа</Th>
              <Th>Состояние</Th>
              <Th>Действует до</Th>
              <Th>Подсети</Th>
              <Th>Действия</Th>
            </tr>
          </thead>
          <tbody>
            {q.data.items.map((k) => (
              <tr key={k.id}>
                <Td>{k.name}</Td>
                <Td className="font-mono">{k.prefix}</Td>
                <Td>{statusText[k.status]}</Td>
                <Td>{formatAbsolute(k.expires_at)}</Td>
                <Td>{k.allowed_cidrs.length > 0 ? k.allowed_cidrs.join(", ") : "любые"}</Td>
                <Td>
                  {canKey && k.status === "active" && (
                    <span className="flex gap-2">
                      <Button
                        onClick={() => {
                          rotateM.reset();
                          setRotate(k);
                        }}
                        aria-label={`Заменить ключ ${k.name}`}
                      >
                        Заменить
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => {
                          revokeM.reset();
                          setRevoke(k);
                        }}
                        aria-label={`Отозвать ключ ${k.name}`}
                      >
                        Отозвать
                      </Button>
                    </span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <FormDialog open={issue} onOpenChange={(v) => !v && setIssue(false)} title="Выпустить ключ" description={`Приложение «${app.name}».`}>
        <form onSubmit={submitIssue} className="flex flex-col gap-3">
          <Field label="Название ключа">{({ id }) => <Input id={id} autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />}</Field>
          <Field label="Срок действия, суток" hint="От 1 до 730." error={daysBad ? "Введите целое число суток от 1 до 730." : undefined}>
            {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />}
          </Field>
          <Field label="Разрешённые подсети (необязательно)" hint="Например 10.0.0.0/8; пусто — с любых адресов.">
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={cidrs} onChange={(e) => setCidrs(e.target.value)} />}
          </Field>
          <ErrorBanner error={issueM.error} />
          <div className="flex justify-end gap-2">
            <Button onClick={() => setIssue(false)}>Отменить</Button>
            <Button type="submit" variant="primary" disabled={issueM.isPending || !name.trim() || daysBad}>
              Выпустить ключ
            </Button>
          </div>
        </form>
      </FormDialog>

      <FormDialog
        open={rotate !== undefined}
        onOpenChange={(v) => !v && setRotate(undefined)}
        title="Заменить ключ"
        description={`Выпускается новый ключ с тем же названием и подсетями. Прежний ключ «${rotate?.name ?? ""}» продолжит работать ещё указанное число часов, затем перестанет.`}
      >
        <form onSubmit={submitRotate} className="flex flex-col gap-3">
          <Field label="Сколько часов прежний ключ ещё действует" hint="От 0 до 720; 0 — прежний ключ перестаёт работать сразу." error={overlapBad ? "Введите целое число часов от 0 до 720." : undefined}>
            {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={overlap} onChange={(e) => setOverlap(e.target.value)} />}
          </Field>
          <Field label="Срок нового ключа, суток" error={daysBad ? "Введите целое число суток от 1 до 730." : undefined}>
            {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />}
          </Field>
          <ErrorBanner error={rotateM.error} />
          <div className="flex justify-end gap-2">
            <Button onClick={() => setRotate(undefined)}>Отменить</Button>
            <Button type="submit" variant="primary" disabled={rotateM.isPending || daysBad || overlapBad}>
              Выпустить новый ключ
            </Button>
          </div>
        </form>
      </FormDialog>

      <ConfirmDialog
        open={revoke !== undefined}
        onOpenChange={(v) => !v && setRevoke(undefined)}
        title="Отозвать ключ"
        description={
          <>
            Ключ «{revoke?.name}» ({revoke?.prefix}) перестанет работать сразу, как только шлюзы получат обновлённую конфигурацию.
            Вернуть отозванный ключ нельзя — придётся выпустить новый. Действие записывается в журнал аудита.
          </>
        }
        actionLabel="Отозвать ключ"
        busy={revokeM.isPending}
        error={revokeM.error}
        onConfirm={() => revoke && revokeM.mutate(revoke)}
      />

      <FormDialog
        open={secret !== undefined}
        onOpenChange={(v) => !v && setSecret(undefined)}
        title="Новый ключ"
        description="Скопируйте ключ и передайте его владельцу приложения безопасным способом."
      >
        {secret !== undefined && <ShownKey secret={secret} onDone={() => setSecret(undefined)} />}
      </FormDialog>
    </Panel>
  );
}
