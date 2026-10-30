import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ConfirmDialog, ErrorBanner, fieldError, FormDialog } from "../admin/common";
import { SecretField, secretBody } from "../agents/Secret";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Table, Td, Th } from "../ui/Layout";
import { type ShadowCatalog, type ShadowExclusion, type ShadowExclusionInput, shadowApi } from "./api";
import { exclusionKindTitle, serviceName } from "./format";

// Что исключить: заполняется кнопкой «Исключить» в таблице или пустым — кнопкой «Добавить исключение».
export interface ExclusionDraft {
  kind: ShadowExclusion["kind"];
  // Логин или адрес из журнала, псевдоним или ID сервиса.
  value: string;
  by: "login" | "alias";
}

// Добавление исключения (задача 4.23): ослабление (DM-40), поэтому с повторной проверкой пароля или кода.
export function ExclusionDialog({
  draft,
  onClose,
  catalog,
  mfa,
  usersPseudonymized,
}: {
  draft: ExclusionDraft | null;
  onClose: () => void;
  catalog: ShadowCatalog | undefined;
  mfa: boolean;
  usersPseudonymized: boolean;
}) {
  const qc = useQueryClient();
  const [d, setD] = useState<ExclusionDraft>(draft ?? { kind: "service", value: "", by: "login" });
  const [comment, setComment] = useState("");
  const [secret, setSecret] = useState("");
  const add = useMutation({
    mutationFn: () => {
      const v = d.value.trim();
      const target: Partial<ShadowExclusionInput> = d.kind === "service" ? { service: v } : d.by === "alias" ? { alias: v } : { login: v };
      return shadowApi.addExclusion({ kind: d.kind, ...target, ...(comment ? { comment } : {}), ...secretBody(mfa, secret) });
    },
    onSuccess: async () => {
      setSecret("");
      await qc.invalidateQueries({ queryKey: ["shadow-ai"] });
      onClose();
    },
    onError: () => setSecret(""),
  });
  const services = catalog?.services ?? [];
  const valueField = d.kind === "service" ? "service" : d.by;
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title="Исключение из учёта теневого ИИ"
      description="Обращения исключённого пользователя или сервиса не попадают в сводки и оповещения."
    >
      <Banner kind="warning">
        Это ослабление контроля: накопленные сводки исключённого удаляются сразу и не возвращаются при снятии исключения. Действие записывается в
        журнал аудита.
      </Banner>
      <Field label="Что исключить">
        {({ id }) => (
          <Select id={id} value={d.kind} onChange={(e) => setD({ kind: e.target.value as ExclusionDraft["kind"], value: "", by: "login" })}>
            <option value="service">Сервис каталога</option>
            <option value="user">Пользователя</option>
          </Select>
        )}
      </Field>
      {d.kind === "service" ? (
        <Field label="Сервис" {...(fieldError(add.error, "service") ? { error: fieldError(add.error, "service")! } : {})}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={d.value} onChange={(e) => setD({ ...d, value: e.target.value })}>
              <option value="">Выберите сервис</option>
              {(services.some((s) => s.id === d.value) || d.value === "" ? services : [...services, { id: d.value, name: d.value }]).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      ) : (
        <>
          {!usersPseudonymized && <Banner kind="info">Ключ псевдонимов пользователей серверу не задан: пользователи не учитываются, исключать некого.</Banner>}
          <Field label="Как указать пользователя">
            {({ id }) => (
              <Select id={id} value={d.by} onChange={(e) => setD({ ...d, by: e.target.value as ExclusionDraft["by"], value: "" })}>
                <option value="login">Логин или адрес из журнала</option>
                <option value="alias">Псевдоним</option>
              </Select>
            )}
          </Field>
          <Field
            label={d.by === "login" ? "Логин или адрес" : "Псевдоним"}
            hint={d.by === "login" ? "Сервер сразу заменит его псевдонимом; сам логин нигде не сохраняется." : "32 шестнадцатеричных знака, как в таблице пользователей."}
            {...(fieldError(add.error, valueField) ? { error: fieldError(add.error, valueField)! } : {})}
          >
            {({ id, describedBy }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                className={d.by === "alias" ? "font-mono" : ""}
                maxLength={d.by === "alias" ? 32 : 256}
                autoComplete="off"
                value={d.value}
                onChange={(e) => setD({ ...d, value: e.target.value })}
              />
            )}
          </Field>
        </>
      )}
      <Field label="Комментарий" hint="До 200 знаков: почему исключение безопасно, например «учётная запись шлюза AISec».">
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={200} value={comment} onChange={(e) => setComment(e.target.value)} />}
      </Field>
      <SecretField mfa={mfa} value={secret} onChange={setSecret} />
      <ErrorBanner error={add.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={add.isPending || d.value.trim() === "" || secret === ""} onClick={() => add.mutate()}>
          Добавить исключение
        </Button>
      </div>
    </FormDialog>
  );
}

// Вкладка «Исключения»: список, снятие и добавление (кнопки — только с правом shadow_ai.exclusions.manage).
export function ExclusionsTab({
  canExclude,
  catalog,
  mfa,
  usersPseudonymized,
}: {
  canExclude: boolean;
  catalog: ShadowCatalog | undefined;
  mfa: boolean;
  usersPseudonymized: boolean;
}) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["shadow-ai", "exclusions"], queryFn: ({ signal }) => shadowApi.exclusions(signal) });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<ShadowExclusion | null>(null);
  const remove = useMutation({
    mutationFn: (x: ShadowExclusion) => shadowApi.removeExclusion(x.kind, x.value),
    onSuccess: async () => {
      setRemoving(null);
      await qc.invalidateQueries({ queryKey: ["shadow-ai"] });
    },
  });
  const items = q.data?.items ?? [];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted">
          Например, учётная запись самого шлюза AISec, которая ходит к провайдерам через прокси. Пользователи хранятся только псевдонимами.
        </p>
        {canExclude && (
          <Button variant="primary" onClick={() => setAdding(true)}>
            Добавить исключение
          </Button>
        )}
      </div>
      <ErrorBanner error={q.error} />
      {q.isPending && <p className="text-sm text-muted">Загрузка исключений…</p>}
      {q.data && items.length === 0 && <EmptyState title="Исключений нет" action={<p className="text-sm text-muted">Учитываются все пользователи и сервисы каталога.</p>} />}
      {items.length > 0 && (
        <Table aria-label="Исключения">
          <thead>
            <tr>
              <Th>Вид</Th>
              <Th>Кто или что</Th>
              <Th>Комментарий</Th>
              <Th>Добавлено</Th>
              {canExclude && <Th>Действия</Th>}
            </tr>
          </thead>
          <tbody>
            {items.map((x) => (
              <tr key={`${x.kind}:${x.value}`}>
                <Td>{exclusionKindTitle.get(x.kind)}</Td>
                <Td className={x.kind === "user" ? "font-mono text-sm" : ""}>{x.kind === "service" ? serviceName(catalog, x.value) : x.value}</Td>
                <Td className="break-words">{x.comment || "—"}</Td>
                <Td>
                  {formatAbsolute(x.created_at)}
                  <div className="text-xs text-muted">{x.created_by}</div>
                </Td>
                {canExclude && (
                  <Td>
                    <Button variant="ghost" onClick={() => setRemoving(x)} aria-label={`Снять исключение ${x.value}`}>
                      Снять исключение
                    </Button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {adding && <ExclusionDialog draft={null} onClose={() => setAdding(false)} catalog={catalog} mfa={mfa} usersPseudonymized={usersPseudonymized} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => {
          if (!v) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Снять исключение?"
        description="Следующие обращения снова попадут в сводки и оповещения. Удалённые при добавлении исключения сводки не вернутся."
        actionLabel="Снять исключение"
        busy={remove.isPending}
        error={remove.error}
        onConfirm={() => removing && remove.mutate(removing)}
      />
    </div>
  );
}
