import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import type { Me } from "../api/client";
import { Button } from "../ui/Button";
import { Check, Field, Input, Select } from "../ui/Field";
import { Banner, Table, Td, Th } from "../ui/Layout";
import { adminApi, type Permission, type RoleDetails, type RoleInput } from "./api";
import { ConfirmDialog, ErrorBanner, FormDialog } from "./common";
import { buildMatrix, type Cell } from "./matrix";

const cellText = (c: Cell) => (c === "all" ? "да" : c === "own" ? "свои" : "нет");

export function RolesTab({ me }: { me: Me }) {
  const perms = new Set(me.permissions);
  const canManage = perms.has("roles.manage");
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["admin", "roles"], queryFn: ({ signal }) => adminApi.roles(signal) });
  const catalog = useQuery({ queryKey: ["admin", "permissions"], queryFn: ({ signal }) => adminApi.permissions(signal) });
  const [edit, setEdit] = useState<RoleDetails | "new" | null>(null);
  const [del, setDel] = useState<RoleDetails | null>(null);
  const remove = useMutation({
    mutationFn: (id: string) => adminApi.deleteRole(id),
    onSuccess: () => {
      setDel(null);
      void qc.invalidateQueries({ queryKey: ["admin", "roles"] });
    },
  });

  const list = roles.data?.items ?? [];
  const matrix = roles.data && catalog.data ? buildMatrix(catalog.data.items, list) : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">Предустановленные роли не изменяются. Свои роли собираются из каталога разрешений (УПД.1).</p>
        {canManage && <Button variant="primary" onClick={() => setEdit("new")}>Создать роль</Button>}
      </div>
      {(roles.isError || catalog.isError) && <ErrorBanner error={roles.error ?? catalog.error} />}
      {(roles.isPending || catalog.isPending) && <p className="text-sm text-muted">Загрузка ролей…</p>}

      {roles.isSuccess && (
        <Table aria-label="Роли">
          <thead>
            <tr>
              <Th>Роль</Th>
              <Th>Тип</Th>
              <Th>Второй фактор</Th>
              <Th>Пользователей</Th>
              <Th>
                <span className="sr-only">Действия</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {list.map((r) => (
              <tr key={r.id}>
                <Td>
                  <div className="font-medium">{r.display_name}</div>
                  <div className="text-xs text-muted">{r.description}</div>
                </Td>
                <Td>{r.builtin ? "Предустановленная" : "Своя"}</Td>
                <Td>{r.mfa_required ? "Обязателен" : "По политике"}</Td>
                <Td className="text-right">{r.users}</Td>
                <Td>
                  {canManage && !r.builtin && (
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" onClick={() => setEdit(r)} aria-label={`Изменить роль: ${r.display_name}`}>
                        Изменить
                      </Button>
                      <Button variant="ghost" onClick={() => setDel(r)} aria-label={`Удалить роль: ${r.display_name}`}>
                        Удалить
                      </Button>
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {matrix.length > 0 && (
        <section aria-label="Матрица разрешений" className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">Матрица разрешений</h2>
          <p className="text-sm text-muted">
            «да» — на все объекты, «свои» — только на собственные (УПД.8). Данные берутся из каталога сервера. Разрешения, помеченные «безопасность», не
            выдаются администратору системы.
          </p>
          <div className="overflow-auto">
            <Table aria-label="Разрешения по ролям">
              <thead>
                <tr>
                  <Th>Разрешение</Th>
                  {list.map((r) => (
                    <Th key={r.id}>{r.display_name}</Th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matrix.map((g) => (
                  <MatrixGroupRows key={g.group} group={g} />
                ))}
              </tbody>
            </Table>
          </div>
        </section>
      )}

      {edit && catalog.data && (
        <RoleEditor
          key={edit === "new" ? "new" : edit.id}
          role={edit === "new" ? null : edit}
          catalog={catalog.data.items}
          mine={perms}
          onClose={() => setEdit(null)}
          onDone={() => {
            setEdit(null);
            void qc.invalidateQueries({ queryKey: ["admin", "roles"] });
          }}
        />
      )}
      {del && (
        <ConfirmDialog
          open
          onOpenChange={(v) => {
            if (!v) {
              setDel(null);
              remove.reset();
            }
          }}
          title={`Удалить роль: ${del.display_name}`}
          description="Роль с пользователями (включая деактивированных) не удаляется. Действие записывается в журнал аудита."
          actionLabel="Удалить роль"
          busy={remove.isPending}
          error={remove.error}
          onConfirm={() => remove.mutate(del.id)}
        />
      )}
    </div>
  );
}

function MatrixGroupRows({ group }: { group: ReturnType<typeof buildMatrix>[number] }) {
  return (
    <>
      <tr>
        <th scope="colgroup" colSpan={99} className="bg-bg px-3 py-1 text-left text-sm font-semibold">
          {group.group}
        </th>
      </tr>
      {group.rows.map((row) => (
        <tr key={row.permission.name}>
          <Td>
            <div>{row.permission.title}</div>
            <div className="font-mono text-xs text-muted">
              {row.permission.name}
              {row.permission.security ? " · безопасность" : ""}
            </div>
          </Td>
          {row.cells.map((c, i) => (
            <Td key={i} className={c ? "font-medium" : "text-muted"}>
              {cellText(c)}
            </Td>
          ))}
        </tr>
      ))}
    </>
  );
}

function RoleEditor({
  role,
  catalog,
  mine,
  onClose,
  onDone,
}: {
  role: RoleDetails | null;
  catalog: Permission[];
  mine: ReadonlySet<string>;
  onClose: () => void;
  onDone: () => void;
}) {
  const [id, setId] = useState(role?.id ?? "");
  const [name, setName] = useState(role?.display_name ?? "");
  const [descr, setDescr] = useState(role?.description ?? "");
  const [mfa, setMfa] = useState(role?.mfa_required ?? false);
  const [grants, setGrants] = useState(() => new Map(role?.permissions.map((g) => [g.permission, g.scope]) ?? []));
  const [confirm, setConfirm] = useState(false);

  const body = (): RoleInput => ({
    display_name: name,
    description: descr,
    mfa_required: mfa,
    permissions: [...grants].map(([permission, scope]) => ({ permission, scope })),
  });
  const m = useMutation({
    mutationFn: () => (role ? adminApi.updateRole(role.id, body()) : adminApi.createRole({ ...body(), id })),
    onSuccess: onDone,
  });
  const toggle = (p: Permission, on: boolean) =>
    setGrants((prev) => {
      const next = new Map(prev);
      if (on) next.set(p.name, "all");
      else next.delete(p.name);
      return next;
    });
  const groups = [...new Set(catalog.map((p) => p.group))];
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setConfirm(true);
  };

  return (
    <>
      <FormDialog
        open={!confirm}
        onOpenChange={(v) => !v && onClose()}
        title={role ? `Изменить роль: ${role.display_name}` : "Создать роль"}
        description="Выдать можно только разрешения, которые есть у вас (УПД.2). Роль с правом на изменение требует второй фактор."
      >
        <form onSubmit={submit} className="flex flex-col gap-3">
          {!role && (
            <Field label="Идентификатор" hint="Латиница, цифры и «_», от 3 символов, начинается с буквы. Потом не меняется.">
              {({ id: fid, describedBy }) => (
                <Input id={fid} aria-describedby={describedBy} required pattern="[a-z][a-z0-9_]{2,47}" value={id} onChange={(e) => setId(e.target.value)} />
              )}
            </Field>
          )}
          <Field label="Название">
            {({ id: fid }) => <Input id={fid} required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <Field label="Описание">
            {({ id: fid }) => <Input id={fid} maxLength={500} value={descr} onChange={(e) => setDescr(e.target.value)} />}
          </Field>
          <Check label="Требовать второй фактор" checked={mfa} onCheckedChange={setMfa} />
          {groups.map((g) => (
            <fieldset key={g} className="flex flex-col gap-1 rounded-control border border-line p-2">
              <legend className="px-1 text-sm font-medium">{g}</legend>
              {catalog
                .filter((p) => p.group === g)
                .map((p) => {
                  const have = mine.has(p.name);
                  return (
                    <div key={p.name} className="flex items-center justify-between gap-2">
                      <Check
                        label={`${p.title}${p.security ? " (безопасность)" : ""}${have ? "" : " — нет вашего права"}`}
                        checked={grants.has(p.name)}
                        disabled={!have && !grants.has(p.name)}
                        onCheckedChange={(v) => toggle(p, v)}
                      />
                      {p.ownable && grants.has(p.name) && (
                        <Select
                          aria-label={`Область: ${p.title}`}
                          className="w-32"
                          value={grants.get(p.name)}
                          onChange={(e) => setGrants((prev) => new Map(prev).set(p.name, e.target.value as "all" | "own"))}
                        >
                          <option value="all">Все объекты</option>
                          <option value="own">Только свои</option>
                        </Select>
                      )}
                    </div>
                  );
                })}
            </fieldset>
          ))}
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Отменить</Button>
            <Button type="submit" variant="primary" disabled={grants.size === 0}>
              {role ? "Сохранить роль" : "Создать роль"}
            </Button>
          </div>
        </form>
      </FormDialog>
      <ConfirmDialog
        open={confirm}
        onOpenChange={(v) => {
          if (!v) {
            setConfirm(false);
            m.reset();
          }
        }}
        title={role ? `Сохранить роль: ${role.display_name}` : `Создать роль: ${name}`}
        description={
          <>
            <p>Выбрано разрешений: {grants.size}. Изменение действует на пользователей роли сразу и записывается в журнал аудита.</p>
            {mfa || [...grants.keys()].some((k) => k.endsWith(".manage")) ? (
              <div className="mt-2">
                <Banner kind="info">Для роли будет требоваться второй фактор.</Banner>
              </div>
            ) : null}
          </>
        }
        actionLabel={role ? "Сохранить роль" : "Создать роль"}
        busy={m.isPending}
        error={m.error}
        onConfirm={() => m.mutate()}
      />
    </>
  );
}
