import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import type { Me } from "../api/client";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Check, Field, Input } from "../ui/Field";
import { Table, Td, Th } from "../ui/Layout";
import { type APIToken, adminApi, type Permission } from "./api";
import { ConfirmDialog, ErrorBanner, FormDialog, SecretDialog } from "./common";

const statusText = new Map([
  ["active", "Действует"],
  ["expired", "Истёк"],
  ["revoked", "Отозван"],
]);

// Разрешения, которые можно дать токену: не «безопасность», не про сами токены и не сессионные (ИАФ.9).
export function tokenGrantable(p: Permission, mine: ReadonlySet<string>): boolean {
  return mine.has(p.name) && !p.security && !p.name.startsWith("api_tokens.") && p.name !== "session" && p.name !== "self";
}

export function TokensTab({ me }: { me: Me }) {
  const perms = new Set(me.permissions);
  const canManage = perms.has("api_tokens.manage");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin", "tokens"], queryFn: ({ signal }) => adminApi.tokens(signal) });
  const catalog = useQuery({
    queryKey: ["admin", "permissions"],
    queryFn: ({ signal }) => adminApi.permissions(signal),
    enabled: perms.has("roles.read"),
  });
  const [creating, setCreating] = useState(false);
  // Выданный токен живёт только в этом состоянии и стирается при закрытии окна.
  const [issued, setIssued] = useState<string | null>(null);
  const [revoke, setRevoke] = useState<APIToken | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["admin", "tokens"] });
  const rv = useMutation({
    mutationFn: (id: string) => adminApi.revokeToken(id),
    onSuccess: () => {
      setRevoke(null);
      refresh();
    },
  });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">Токен действует от вашего имени и не шире ваших прав. Сам токен показывается один раз (ИАФ.9).</p>
        {canManage && <Button variant="primary" onClick={() => setCreating(true)}>Выпустить токен</Button>}
      </div>
      {q.isError && <ErrorBanner error={q.error} />}
      {q.isPending && <p className="text-sm text-muted">Загрузка токенов…</p>}
      {q.isSuccess && q.data.length === 0 && <p className="text-sm text-muted">Токенов пока нет.</p>}
      {q.isSuccess && q.data.length > 0 && (
        <Table aria-label="Токены API">
          <thead>
            <tr>
              <Th>Название</Th>
              <Th>Начало токена</Th>
              <Th>Состояние</Th>
              <Th>Истекает</Th>
              <Th>Последнее использование</Th>
              <Th>
                <span className="sr-only">Действия</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((t) => (
              <tr key={t.id}>
                <Td>{t.name}</Td>
                <Td className="font-mono text-sm">{t.prefix}…</Td>
                <Td>{statusText.get(t.status) ?? t.status}</Td>
                <Td>{formatAbsolute(t.expires_at)}</Td>
                <Td>{t.last_used_at ? formatAbsolute(t.last_used_at) : "не использовался"}</Td>
                <Td>
                  {canManage && t.status === "active" && (
                    <div className="flex justify-end">
                      <Button variant="ghost" onClick={() => setRevoke(t)} aria-label={`Отозвать токен: ${t.name}`}>
                        Отозвать
                      </Button>
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {creating && (
        <CreateToken
          catalog={catalog.data?.items}
          mine={perms}
          mfa={me.mfa?.enabled === true}
          onClose={() => setCreating(false)}
          onCreated={(token) => {
            setCreating(false);
            setIssued(token);
            refresh();
          }}
        />
      )}
      <SecretDialog
        open={issued !== null}
        onClose={() => setIssued(null)}
        title="Токен API выпущен"
        description="Скопируйте токен и сохраните его в хранилище секретов. Сервер хранит только хеш."
        label="Токен"
        value={issued ?? ""}
      />
      {revoke && (
        <ConfirmDialog
          open
          onOpenChange={(v) => {
            if (!v) {
              setRevoke(null);
              rv.reset();
            }
          }}
          title={`Отозвать токен: ${revoke.name}`}
          description="Токен перестанет работать сразу. Отзыв нельзя отменить."
          actionLabel="Отозвать токен"
          busy={rv.isPending}
          error={rv.error}
          onConfirm={() => rv.mutate(revoke.id)}
        />
      )}
    </div>
  );
}

function CreateToken({
  catalog,
  mine,
  mfa,
  onClose,
  onCreated,
}: {
  catalog: Permission[] | undefined;
  mine: ReadonlySet<string>;
  mfa: boolean;
  onClose: () => void;
  onCreated: (token: string) => void;
}) {
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [secret, setSecret] = useState("");
  const options = (catalog ?? []).filter((p) => tokenGrantable(p, mine));
  const d = Number(days);
  const daysErr = !Number.isInteger(d) || d < 1 || d > 365 ? "Введите целое число суток от 1 до 365." : undefined;
  const m = useMutation({
    mutationFn: () =>
      adminApi.createToken({
        name,
        expires_in_days: d,
        permissions: [...chosen].map((permission) => ({ permission, scope: "all" as const })),
        // Повторная проверка: второй фактор, если подключён, иначе пароль (В8).
        ...(mfa ? { code: secret } : { password: secret }),
      }),
    onSuccess: (r) => {
      setSecret("");
      onCreated(r.token);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    m.mutate();
  };
  return (
    <FormDialog open onOpenChange={(v) => !v && onClose()} title="Выпустить токен API" description="Нужна повторная проверка: подтвердите, что это вы.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Название">
          {({ id }) => <Input id={id} required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label="Срок действия, суток" hint="От 1 до 365." error={daysErr}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
          )}
        </Field>
        <fieldset className="flex flex-col gap-1 rounded-control border border-line p-2">
          <legend className="px-1 text-sm font-medium">Разрешения токена</legend>
          {catalog === undefined && <p className="text-sm text-muted">Каталог разрешений недоступен: нужно право «Просмотр ролей».</p>}
          {options.map((p) => (
            <Check
              key={p.name}
              label={p.title}
              checked={chosen.has(p.name)}
              onCheckedChange={(v) =>
                setChosen((prev) => {
                  const next = new Set(prev);
                  if (v) next.add(p.name);
                  else next.delete(p.name);
                  return next;
                })
              }
            />
          ))}
        </fieldset>
        <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"}>
          {({ id }) => (
            <Input
              id={id}
              required
              autoComplete={mfa ? "one-time-code" : "current-password"}
              type={mfa ? "text" : "password"}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          )}
        </Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || chosen.size === 0 || Boolean(daysErr) || !secret}>
            Выпустить токен
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}
