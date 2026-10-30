import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { ErrorBanner } from "../admin/common";
import { RiskBadge } from "../agents/labels";
import { conflictText, isConflict, SecretField, secretBody } from "../agents/Secret";
import type { Me } from "../api/client";
import { isRefetch } from "../api/poll";
import { formatAbsolute } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner, EmptyState, Panel, RawText } from "../ui/Layout";
import { hasInvisible, revealInvisible } from "../ui/reveal";
import { type Approval, type ApprovalState, approvalsApi } from "./api";
import { formatCountdown, useCountdown } from "./countdown";

const stateText = new Map<ApprovalState, string>([
  ["pending", "Ждёт решения"],
  ["approved", "Одобрен"],
  ["denied", "Отклонён"],
  ["timeout", "Срок истёк"],
  ["cancelled", "Агент отменил вызов"],
  ["interrupted", "Прерван перезапуском шлюза"],
]);
const filters: (ApprovalState | "")[] = ["pending", "", "approved", "denied", "timeout", "cancelled", "interrupted"];

function useVisible(): boolean {
  const [v, setV] = useState(() => document.visibilityState === "visible");
  useEffect(() => {
    const on = () => setV(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", on);
    return () => document.removeEventListener("visibilitychange", on);
  }, []);
  return v;
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="contents">
      <dt className="text-sm text-muted">{k}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

// Карточка запроса. Аргументы приходят от модели или агента: выводятся только как текст.
function ApprovalCard({ a, canDecide, canSession, mfa, visible }: { a: Approval; canDecide: boolean; canSession: boolean; mfa: boolean; visible: boolean }) {
  const qc = useQueryClient();
  const pending = a.state === "pending";
  const left = useCountdown(a.deadline, pending && visible);
  const expired = pending && left === 0;
  const [showArgs, setShowArgs] = useState(pending);
  const [comment, setComment] = useState("");
  const [secret, setSecret] = useState("");
  const detail = useQuery({
    queryKey: ["approval", a.id],
    queryFn: ({ signal }) => approvalsApi.get(a.id, signal),
    enabled: canDecide && showArgs,
  });
  // Решение относится к тем аргументам, которые человек видел: хеш берётся из показанного запроса.
  const shown = detail.data;
  const refresh = () => qc.invalidateQueries({ queryKey: ["approvals"] });
  const settle = async () => {
    setSecret("");
    await qc.invalidateQueries({ queryKey: ["approval", a.id] });
    await refresh();
  };
  const approve = useMutation({
    mutationFn: () => approvalsApi.approve(a.id, { args_hash: shown!.args_hash, ...(comment ? { comment } : {}), ...secretBody(mfa, secret) }),
    onSuccess: settle,
    onError: async (e) => {
      setSecret("");
      if (isConflict(e)) await settle();
    },
  });
  const deny = useMutation({ mutationFn: () => approvalsApi.deny(a.id, comment), onSuccess: settle, onError: async (e) => {
      if (isConflict(e)) await settle();
    } });
  // Скрытые символы в аргументах (4В20 ревью 4.r2) — показываются маркерами, одобрение — с повторной проверкой, как при critical.
  const hidden = !!shown?.args && hasInvisible(shown.args);
  // Без второго фактора в сессии любое одобрение — с паролем (4В37): украденного пароля входа не должно хватать.
  const critical = a.risk === "critical" || hidden || !mfa;
  const busy = approve.isPending || deny.isPending;
  const conflict = conflictText(approve.error ?? deny.error, "Запрос изменился или уже закрыт. Данные обновлены, проверьте их и повторите.");

  return (
    <Panel aria-label={`Подтверждение: ${a.tool}`} className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-md font-semibold">
          <span className="font-mono">{a.tool}</span> · {a.server}
        </h2>
        <div className="flex items-center gap-2">
          <RiskBadge risk={a.risk} />
          <span className="text-sm">{stateText.get(a.state)}</span>
        </div>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <Row k="Приложение">{a.application}</Row>
        <Row k="Агент">{a.agent ?? "без агента (чат)"}</Row>
        <Row k="MCP-сервер">{a.server}</Row>
        <Row k="Инструмент">{a.tool}</Row>
        <Row k="Правило">{a.rule}</Row>
        {a.message && <Row k="Сообщение правила">{a.message}</Row>}
        <Row k="Создан">{formatAbsolute(a.created_at)}</Row>
        {pending && (
          <Row k="Осталось">{expired ? "Срок истёк. Запрос закроется сам; обновите список." : <span aria-live="off">{formatCountdown(left)}</span>}</Row>
        )}
        {!pending && a.closed_at && <Row k="Закрыт">{formatAbsolute(a.closed_at)}</Row>}
        {a.decided_by && <Row k="Решил">{a.decided_by}</Row>}
        {a.comment && <Row k="Комментарий">{a.comment}</Row>}
        {a.session && (
          <Row k="Сессия">
            {canSession ? (
              <Link className="underline" to={`/session/${encodeURIComponent(a.session)}`} aria-label={`Хронология сессии ${a.session}`}>
                Хронология сессии
              </Link>
            ) : (
              <span className="font-mono text-sm">{a.session}</span>
            )}
          </Row>
        )}
      </dl>
      {canDecide && !pending && !showArgs && (
        <div>
          <Button onClick={() => setShowArgs(true)}>Показать аргументы</Button>
        </div>
      )}
      {canDecide && showArgs && (
        <section aria-label="Аргументы вызова" className="flex flex-col gap-1">
          <h3 className="text-sm font-medium">Аргументы (персональные данные и секреты заменены категорией)</h3>
          {detail.isPending && <p className="text-sm text-muted">Загрузка аргументов…</p>}
          <ErrorBanner error={detail.error} />
          {hidden && (
            <Banner kind="error">
              В аргументах есть скрытые управляющие символы: они могут менять видимый порядок текста. Ниже они показаны как ⟦U+…⟧. Проверьте
              аргументы внимательно.
            </Banner>
          )}
          {shown &&
            (shown.args_deleted ? (
              <p className="text-sm text-muted">Аргументы удалены по сроку хранения.</p>
            ) : (
              <RawText>{revealInvisible(shown.args ?? "")}</RawText>
            ))}
        </section>
      )}
      {canDecide && pending && (
        <div className="flex flex-col gap-3">
          <Field label="Комментарий" hint="До 500 знаков. Виден в событии вызова, агенту не передаётся.">
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={500} value={comment} onChange={(e) => setComment(e.target.value)} />}
          </Field>
          {critical && (
            <>
              <Banner kind="warning">
                {hidden ? "В аргументах скрытые символы" : a.risk === "critical" ? "Риск критический" : "Второй фактор не подключён"}: для одобрения нужно
                подтвердить, что это вы.
              </Banner>
              <SecretField mfa={mfa} value={secret} onChange={setSecret} />
            </>
          )}
          {conflict && <Banner kind="warning">{conflict}</Banner>}
          {!conflict && <ErrorBanner error={approve.error ?? deny.error} />}
          <div className="flex justify-end gap-2">
            <Button variant="danger" disabled={busy || expired} onClick={() => deny.mutate()}>
              Отклонить вызов
            </Button>
            <Button variant="primary" disabled={busy || expired || !shown || (critical && secret === "")} onClick={() => approve.mutate()}>
              Одобрить вызов
            </Button>
          </div>
        </div>
      )}
    </Panel>
  );
}

// Экран «Подтверждения» (ТЗ 5.10, DM-22): очередь вызовов, которые политика отправила на решение человеку.
export function ApprovalsScreen({ me }: { me: Me }) {
  const has = (p: string) => me.permissions.includes(p);
  const [state, setState] = useState<ApprovalState | "">("pending");
  const visible = useVisible();
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["approvals", "list", state],
    queryFn: ({ signal, queryKey }) => approvalsApi.list(state || undefined, signal, isRefetch(qc, queryKey)),
    // Опрос раз в 5 секунд, пока вкладка видима.
    refetchInterval: () => (document.visibilityState === "visible" ? 5000 : false),
  });
  const items = useMemo(() => [...(q.data?.items ?? [])].sort((x, y) => Number(y.state === "pending") - Number(x.state === "pending")), [q.data]);
  return (
    <section aria-label="Подтверждения" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Подтверждения</h1>
        <label className="flex items-center gap-2 text-sm">
          Состояние
          <Select value={state} onChange={(e) => setState(e.target.value as ApprovalState | "")} className="w-64">
            {filters.map((s) => (
              <option key={s} value={s}>
                {s === "" ? "Все" : stateText.get(s)}
              </option>
            ))}
          </Select>
        </label>
      </div>
      {!has("approvals.decide") && <Banner kind="info">Решения принимает администратор безопасности или аналитик. У вас доступен только просмотр очереди.</Banner>}
      <ErrorBanner error={q.error} />
      {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка очереди…</p>}
      {q.data && items.length === 0 && (
        <EmptyState title={state === "pending" ? "Вызовов, ожидающих решения, нет" : "Запросов с таким состоянием нет"} action={<p className="text-sm text-muted">Список обновляется каждые 5 секунд.</p>} />
      )}
      {items.map((a) => (
        <ApprovalCard key={a.id} a={a} canDecide={has("approvals.decide")} canSession={has("events.read")} mfa={me.mfa?.enabled === true} visible={visible} />
      ))}
    </section>
  );
}
