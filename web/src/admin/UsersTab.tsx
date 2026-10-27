import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Table, Td, Th } from "../ui/Layout";
import { adminApi, type RoleDetails, type User } from "./api";
import { ConfirmDialog, ErrorBanner, FormDialog, SecretDialog } from "./common";
import { assignable } from "./matrix";

type Action =
  | { kind: "role" | "email" | "password" | "mfa" | "sessions" | "deactivate" | "activate" | "list"; user: User }
  | { kind: "create" };

const roleName = (roles: RoleDetails[] | undefined, id: string) => roles?.find((r) => r.id === id)?.display_name ?? id;

function statusText(u: User): string {
  if (u.status === "deactivated") return "Деактивирована";
  if (u.locked) return u.locked_until ? `Заблокирована до ${formatAbsolute(u.locked_until)}` : "Заблокирована";
  return u.must_change_password ? "Активна, нужна смена пароля" : "Активна";
}

export function UsersTab({ me }: { me: Me }) {
  const perms = new Set(me.permissions);
  const canManage = perms.has("users.manage");
  const canRole = perms.has("roles.manage") && perms.has("roles.read");
  const canSessions = perms.has("sessions.manage");
  const canSeeSessions = perms.has("sessions.read");
  const qc = useQueryClient();
  const [action, setAction] = useState<Action | null>(null);
  const [secret, setSecret] = useState<{ title: string; value: string } | null>(null);

  const users = useQuery({ queryKey: ["admin", "users"], queryFn: ({ signal }) => adminApi.users(signal) });
  const roles = useQuery({
    queryKey: ["admin", "roles"],
    queryFn: ({ signal }) => adminApi.roles(signal),
    enabled: perms.has("roles.read"),
  });
  const roleList = roles.data?.items;
  const close = () => setAction(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["admin", "users"] });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">Учётные записи не удаляются, только деактивируются (УПД.5).</p>
        {canManage && <Button variant="primary" onClick={() => setAction({ kind: "create" })}>Создать пользователя</Button>}
      </div>
      {users.isError && <ErrorBanner error={users.error} />}
      {users.isPending && <p className="text-sm text-muted">Загрузка пользователей…</p>}
      {users.isSuccess && users.data.length === 0 && (
        <EmptyState title="Пользователей пока нет" action={<p className="text-sm text-muted">Создайте первую учётную запись.</p>} />
      )}
      {users.isSuccess && users.data.length > 0 && (
        <Table aria-label="Пользователи">
          <thead>
            <tr>
              <Th>Логин</Th>
              <Th>Имя</Th>
              <Th>E-mail</Th>
              <Th>Роль</Th>
              <Th>Состояние</Th>
              <Th>Последний вход</Th>
              <Th>
                <span className="sr-only">Действия</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {users.data.map((u) => {
              const self = u.id === me.user.id;
              return (
                <tr key={u.id}>
                  <Td>
                    {u.login}
                    {self ? " (вы)" : ""}
                  </Td>
                  <Td>{u.display_name}</Td>
                  <Td>{u.email || <span className="text-muted">не задан</span>}</Td>
                  <Td>{roleName(roleList, u.role)}</Td>
                  <Td>{statusText(u)}</Td>
                  <Td>{u.last_login_at ? formatAbsolute(u.last_login_at) : "не входил"}</Td>
                  <Td>
                    <div className="flex flex-wrap justify-end gap-1">
                      {canSeeSessions && (
                        <Button variant="ghost" onClick={() => setAction({ kind: "list", user: u })} aria-label={`Сессии: ${u.login}`}>
                          Сессии
                        </Button>
                      )}
                      {canRole && (
                        <Button
                          variant="ghost"
                          disabled={self}
                          title={self ? "Свою роль менять нельзя: разделение обязанностей" : undefined}
                          onClick={() => setAction({ kind: "role", user: u })}
                          aria-label={`Сменить роль: ${u.login}`}
                        >
                          Роль
                        </Button>
                      )}
                      {canManage && (
                        <>
                          <Button variant="ghost" onClick={() => setAction({ kind: "email", user: u })} aria-label={`E-mail: ${u.login}`}>
                            E-mail
                          </Button>
                          <Button
                            variant="ghost"
                            disabled={self}
                            onClick={() => setAction({ kind: "password", user: u })}
                            aria-label={`Сбросить пароль: ${u.login}`}
                          >
                            Пароль
                          </Button>
                          <Button
                            variant="ghost"
                            disabled={self}
                            onClick={() => setAction({ kind: "mfa", user: u })}
                            aria-label={`Сбросить второй фактор: ${u.login}`}
                          >
                            Фактор
                          </Button>
                          {u.status === "active" ? (
                            <Button
                              variant="ghost"
                              disabled={self}
                              onClick={() => setAction({ kind: "deactivate", user: u })}
                              aria-label={`Деактивировать: ${u.login}`}
                            >
                              Деактивировать
                            </Button>
                          ) : (
                            <Button variant="ghost" onClick={() => setAction({ kind: "activate", user: u })} aria-label={`Активировать: ${u.login}`}>
                              Активировать
                            </Button>
                          )}
                        </>
                      )}
                      {canSessions && (
                        <Button variant="ghost" onClick={() => setAction({ kind: "sessions", user: u })} aria-label={`Завершить сессии: ${u.login}`}>
                          Завершить сессии
                        </Button>
                      )}
                    </div>
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}

      {action?.kind === "create" && (
        <CreateUser
          roles={roleList}
          mine={perms}
          onClose={close}
          onCreated={(r) => {
            close();
            refresh();
            setSecret({ title: `Временный пароль: ${r.user.login}`, value: r.temporary_password });
          }}
        />
      )}
      {action?.kind === "role" && (
        <ChangeRole
          user={action.user}
          roles={roleList ?? []}
          mine={perms}
          onClose={close}
          onDone={() => {
            close();
            refresh();
          }}
        />
      )}
      {action?.kind === "email" && (
        <EditEmail
          user={action.user}
          onClose={close}
          onDone={() => {
            close();
            refresh();
          }}
        />
      )}
      {action?.kind === "list" && <SessionsList user={action.user} onClose={close} />}
      {action?.kind === "sessions" && (
        <RevokeSessions
          user={action.user}
          onClose={close}
          onDone={() => {
            close();
            refresh();
          }}
        />
      )}
      {(action?.kind === "password" || action?.kind === "mfa" || action?.kind === "deactivate" || action?.kind === "activate") && (
        <UserAction
          key={`${action.kind}-${action.user.id}`}
          kind={action.kind}
          user={action.user}
          onClose={close}
          onDone={(s) => {
            close();
            refresh();
            if (s) setSecret(s);
          }}
        />
      )}
      <SecretDialog
        open={secret !== null}
        onClose={() => setSecret(null)}
        title={secret?.title ?? ""}
        description="Передайте пароль пользователю по защищённому каналу. При первом входе его нужно сменить."
        label="Временный пароль"
        value={secret?.value ?? ""}
      />
    </div>
  );
}

function CreateUser({
  roles,
  mine,
  onClose,
  onCreated,
}: {
  roles: RoleDetails[] | undefined;
  mine: ReadonlySet<string>;
  onClose: () => void;
  onCreated: (r: { user: User; temporary_password: string }) => void;
}) {
  const [login, setLogin] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("");
  const m = useMutation({
    mutationFn: () => adminApi.createUser({ login, display_name: name, role }),
    onSuccess: onCreated,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    m.mutate();
  };
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title="Создать пользователя" description="Сервер выдаст временный пароль и покажет его один раз.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Логин" hint="Латиница, цифры, «.», «_», «-», до 64 символов.">
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} required value={login} onChange={(e) => setLogin(e.target.value)} />}
        </Field>
        <Field label="Имя для показа">
          {({ id }) => <Input id={id} required value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label="Роль" hint="Выдать можно роль, все права которой есть и у вас (УПД.2).">
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} required value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="">Выберите роль</option>
              {(roles ?? []).map((r) => (
                <option key={r.id} value={r.id} disabled={!assignable(r, mine)}>
                  {r.display_name}
                  {assignable(r, mine) ? "" : " — нет ваших прав"}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || !role}>
            Создать пользователя
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function ChangeRole({
  user,
  roles,
  mine,
  onClose,
  onDone,
}: {
  user: User;
  roles: RoleDetails[];
  mine: ReadonlySet<string>;
  onClose: () => void;
  onDone: () => void;
}) {
  const [role, setRole] = useState(user.role);
  const m = useMutation({ mutationFn: () => adminApi.setRole(user.id, role), onSuccess: onDone });
  const current = roles.find((r) => r.id === user.role);
  const mayChange = current ? assignable(current, mine) : true;
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`Сменить роль: ${user.login}`}
      description="Все сессии пользователя будут завершены, новые права вступят в силу со следующего входа."
    >
      {!mayChange && <Banner kind="warning">У вас нет части прав этой роли, поэтому сервер, скорее всего, откажет (УПД.2).</Banner>}
      <Field label="Новая роль">
        {({ id }) => (
          <Select id={id} value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => (
              <option key={r.id} value={r.id} disabled={!assignable(r, mine)}>
                {r.display_name}
                {assignable(r, mine) ? "" : " — нет ваших прав"}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <ErrorBanner error={m.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="danger" disabled={m.isPending || role === user.role} onClick={() => m.mutate()}>
          Назначить роль и завершить сессии
        </Button>
      </div>
    </FormDialog>
  );
}

// E-mail нужен для рассылки отчётов; проверку формата делает сервер, без письма-подтверждения.
function EditEmail({ user, onClose, onDone }: { user: User; onClose: () => void; onDone: () => void }) {
  const [email, setEmail] = useState(user.email);
  const m = useMutation({ mutationFn: () => adminApi.setEmail(user.id, email.trim()), onSuccess: onDone });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    m.mutate();
  };
  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`E-mail: ${user.login}`}
      description="Адрес нужен для рассылки отчётов по расписанию. Проверочное письмо не отправляется. Пустое поле убирает адрес."
    >
      <form noValidate onSubmit={submit} className="flex flex-col gap-3">
        <Field label="E-mail" hint="Вида user@example.ru, до 254 символов.">
          {({ id, describedBy }) => (
            <Input id={id} type="email" autoComplete="off" aria-describedby={describedBy} value={email} onChange={(e) => setEmail(e.target.value)} />
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || email.trim() === user.email}>
            Сохранить
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function SessionsList({ user, onClose }: { user: User; onClose: () => void }) {
  const q = useQuery({ queryKey: ["admin", "sessions", user.id], queryFn: ({ signal }) => adminApi.sessions(user.id, signal) });
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title={`Сессии: ${user.login}`}>
      {q.isError && <ErrorBanner error={q.error} />}
      {q.isPending && <p className="text-sm text-muted">Загрузка…</p>}
      {q.isSuccess && q.data.items.length === 0 && <p className="text-sm text-muted">Действующих сессий нет.</p>}
      {q.isSuccess && q.data.items.length > 0 && (
        <ul className="flex flex-col gap-2 text-sm">
          {q.data.items.map((s) => (
            <li key={s.id} className="rounded-control border border-line p-2">
              <div>Начата {formatAbsolute(s.created_at)}, активность {formatAbsolute(s.last_seen_at)}</div>
              <div className="text-muted">
                Истекает {formatAbsolute(s.expires_at)}
                {s.source_ip ? `, адрес ${s.source_ip}` : ""}
              </div>
              <div className="break-words text-muted">{s.user_agent}</div>
            </li>
          ))}
        </ul>
      )}
      <div className="flex justify-end">
        <Button onClick={onClose}>Закрыть</Button>
      </div>
    </FormDialog>
  );
}

function RevokeSessions({ user, onClose, onDone }: { user: User; onClose: () => void; onDone: () => void }) {
  // Токены API по умолчанию отзываются вместе с сессиями (В8 ревью 2.r2).
  const [tokens, setTokens] = useState(true);
  const m = useMutation({ mutationFn: () => adminApi.revokeSessions(user.id, tokens), onSuccess: onDone });
  return (
    <ConfirmDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`Завершить сессии: ${user.login}`}
      description={
        <div className="flex flex-col gap-3">
          <p>Пользователь будет разлогинен на всех устройствах.</p>
          <label className="flex items-center gap-2 text-base text-fg">
            <input type="checkbox" checked={tokens} onChange={(e) => setTokens(e.target.checked)} />
            Отозвать и токены API пользователя
          </label>
        </div>
      }
      actionLabel="Завершить сессии"
      busy={m.isPending}
      error={m.error}
      onConfirm={() => m.mutate()}
    />
  );
}

type ActionKind = "password" | "mfa" | "deactivate" | "activate";

const texts: Record<ActionKind, { title: string; text: string; label: string }> = {
  password: {
    title: "Сбросить пароль",
    text: "Пользователю выдаётся новый временный пароль, его сессии завершаются, токены API отзываются.",
    label: "Сбросить пароль",
  },
  mfa: {
    title: "Сбросить второй фактор",
    text: "Секрет и коды восстановления будут уничтожены, сессии завершены. При следующем входе фактор подключается заново.",
    label: "Сбросить второй фактор",
  },
  deactivate: {
    title: "Деактивировать учётную запись",
    text: "Пользователь не сможет войти, его сессии завершатся. Запись остаётся в системе и в журнале аудита.",
    label: "Деактивировать",
  },
  activate: {
    title: "Активировать учётную запись",
    text: "Пользователь снова сможет войти; блокировка после неудачных попыток также снимается.",
    label: "Активировать",
  },
};

// Тексты выбираются переключателем, а не индексом по ключу: ключ приходит из состояния экрана.
function textFor(kind: ActionKind) {
  switch (kind) {
    case "password":
      return texts.password;
    case "mfa":
      return texts.mfa;
    case "deactivate":
      return texts.deactivate;
    case "activate":
      return texts.activate;
  }
}

function UserAction({
  kind,
  user,
  onClose,
  onDone,
}: {
  kind: ActionKind;
  user: User;
  onClose: () => void;
  onDone: (secret?: { title: string; value: string }) => void;
}) {
  const t = textFor(kind);
  const m = useMutation({
    mutationFn: async () => {
      switch (kind) {
        case "password":
          return adminApi.resetPassword(user.id);
        case "mfa":
          return adminApi.resetMfa(user.id);
        case "deactivate":
          return adminApi.deactivate(user.id);
        case "activate":
          return adminApi.activate(user.id);
      }
    },
    onSuccess: (r) => {
      if (kind === "password") {
        const p = r as { temporary_password: string };
        onDone({ title: `Временный пароль: ${user.login}`, value: p.temporary_password });
      } else onDone();
    },
  });
  return (
    <ConfirmDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={`${t.title}: ${user.login}`}
      description={t.text}
      actionLabel={t.label}
      busy={m.isPending}
      error={m.error}
      onConfirm={() => m.mutate()}
    />
  );
}
