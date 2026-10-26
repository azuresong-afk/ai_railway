import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type FormEvent, useEffect, useState } from "react";
import { ErrorBanner, FormDialog } from "../admin/common";
import { ReauthPrompt, useReauth, visibleError } from "../admin/reauth";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { DiffView } from "./DiffView";
import { type Policy, policiesApi, type PolicySummary } from "./api";

const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/;
const templates: [string, string][] = [
  ["base", "Базовая защита"],
  ["pii-strict", "Строгая защита персональных данных"],
  ["external-no-pii", "Внешний провайдер без персональных данных"],
  ["monitor-only", "Только мониторинг"],
];

// Новая политика — копия шаблона (ТЗ 5.3); дальше её содержимое меняют загрузкой YAML.
export function CreateDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (p: Policy) => void }) {
  const qc = useQueryClient();
  const [pid, setPid] = useState("");
  const [tpl, setTpl] = useState("base");
  const [name, setName] = useState("");
  const m = useMutation({
    mutationFn: () => policiesApi.create({ id: pid, from_template: tpl as "base", ...(name.trim() ? { name: name.trim() } : {}) }),
    onSuccess: async (p) => {
      await qc.invalidateQueries({ queryKey: ["policies"] });
      setPid("");
      setName("");
      onDone(p);
    },
  });
  const bad = pid !== "" && !idPattern.test(pid) ? "ID: латиница в нижнем регистре, цифры и «-», до 63 символов." : undefined;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (idPattern.test(pid)) m.mutate();
  };
  return (
    <FormDialog open={open} onOpenChange={(v) => !v && onClose()} title="Создать политику из шаблона" description="Копия шаблона получает версию 1 и дальше меняется как обычная политика.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="ID политики" hint="Не совпадает с ID шаблонов; потом не меняется." error={bad}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} autoFocus value={pid} onChange={(e) => setPid(e.target.value)} />}
        </Field>
        <Field label="Шаблон">
          {({ id }) => (
            <Select id={id} value={tpl} onChange={(e) => setTpl(e.target.value)}>
              {templates.map(([v, t]) => (
                <option key={v} value={v}>
                  {t}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Название (необязательно)">{({ id }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} maxLength={128} />}</Field>
        <ErrorBanner error={m.error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || !idPattern.test(pid)}>
            Создать политику
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

const maxYaml = 1 << 20;

// Загрузка YAML по строгой схеме этапа 1: новая политика или новая версия выбранной (поверх её текущей версии).
export function ImportDialog({
  open,
  onClose,
  current,
  mfa,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  current?: PolicySummary;
  mfa: boolean;
  onDone: (p: Policy) => void;
}) {
  const qc = useQueryClient();
  const [yaml, setYaml] = useState("");
  const [comment, setComment] = useState("");
  const [asVersion, setAsVersion] = useState(true);
  const [fileErr, setFileErr] = useState<string>();
  const re = useReauth(mfa);
  const baseVersion = current && !current.template ? current.current_version : undefined;
  const base = asVersion ? baseVersion : undefined;
  // Различия до отправки для любого YAML (Н46, задача 3.35): сервер разбирает документ так же, как при загрузке, и ничего
  // не сохраняет. Запрос — после паузы в наборе текста, чтобы не проверять каждый символ.
  const [checked, setChecked] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setChecked(yaml), 400);
    return () => clearTimeout(t);
  }, [yaml]);
  const tooBig = new TextEncoder().encode(yaml).length > maxYaml;
  const preview = useQuery({
    queryKey: ["policies", "import-preview", base, checked],
    queryFn: ({ signal }) => policiesApi.previewYaml(checked, base, signal),
    enabled: open && checked.trim() !== "" && checked === yaml && !tooBig,
    retry: false,
    staleTime: Infinity,
  });
  const m = useMutation({
    mutationFn: () => policiesApi.importYaml(yaml, asVersion ? baseVersion : undefined, comment.trim(), re.body()),
    onSuccess: async (p) => {
      re.reset();
      await qc.invalidateQueries({ queryKey: ["policies"] });
      setYaml("");
      setComment("");
      onDone(p);
    },
    onError: re.onError,
  });
  const close = () => {
    re.reset();
    m.reset();
    onClose();
  };
  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileErr(undefined);
    if (f.size > maxYaml) {
      setFileErr("Файл больше 1 МиБ. Загрузите файл меньшего размера.");
      return;
    }
    setYaml(await f.text());
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (yaml.trim() !== "" && !tooBig && re.ready) m.mutate();
  };
  return (
    <FormDialog open={open} onOpenChange={(v) => !v && close()} title="Загрузить политику из YAML" description="Файл проверяется строго: неизвестное поле, второй документ или неизвестный детектор отклоняют загрузку целиком.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Файл YAML" error={fileErr}>
          {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} type="file" accept=".yaml,.yml,text/yaml,application/yaml" onChange={onFile} className="text-sm" />}
        </Field>
        <Field label="Или вставьте текст" error={tooBig ? "Документ больше 1 МиБ." : undefined}>
          {({ id, describedBy, invalid }) => (
            <textarea
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              rows={10}
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              className="w-full rounded-control border border-line-strong bg-surface px-2 py-1 font-mono text-sm aria-[invalid=true]:border-sev-critical"
            />
          )}
        </Field>
        {current && baseVersion !== undefined && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={asVersion} onChange={(e) => setAsVersion(e.target.checked)} />
            Сохранить как новую версию политики «{current.name}» (поверх версии {baseVersion})
          </label>
        )}
        {preview.isFetching && <p className="text-sm text-muted">Проверяем документ…</p>}
        {preview.data && !preview.isFetching && (
          <>
            {preview.data.created ? (
              <p className="text-sm">Будет создана новая политика «{preview.data.policy}».</p>
            ) : (
              current?.id !== undefined && preview.data.policy !== current.id && (
                <Banner kind="warning">Документ относится к другой политике: «{preview.data.policy}», её версия {preview.data.current_version}.</Banner>
              )
            )}
            <DiffView diff={preview.data.diff} preview />
          </>
        )}
        {preview.error && !preview.isFetching && (
          <ErrorBanner error={preview.error} />
        )}
        <Field label="Комментарий к версии (необязательно)">{({ id }) => <Input id={id} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={500} />}</Field>
        <ReauthPrompt r={re} />
        <ErrorBanner error={visibleError(m.error)} />
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отменить</Button>
          <Button type="submit" variant="primary" disabled={m.isPending || yaml.trim() === "" || tooBig || !re.ready}>
            Загрузить политику
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

// Откат создаёт новую версию с содержимым прежней; перед подтверждением показывается, что изменится.
export function RollbackDialog({
  policyId,
  current,
  target,
  mfa,
  onClose,
  onDone,
}: {
  policyId: string;
  current: number;
  target: number | undefined;
  mfa: boolean;
  onClose: () => void;
  onDone: (p: Policy) => void;
}) {
  const qc = useQueryClient();
  const open = target !== undefined;
  const diff = useQuery({
    queryKey: ["policies", policyId, "diff", current, target],
    queryFn: ({ signal }) => policiesApi.diff(policyId, current, target!, signal),
    enabled: open,
  });
  const [comment, setComment] = useState("");
  const re = useReauth(mfa);
  const m = useMutation({
    mutationFn: () => policiesApi.rollback(policyId, target!, current, comment.trim(), re.body()),
    onSuccess: async (p) => {
      re.reset();
      await qc.invalidateQueries({ queryKey: ["policies"] });
      setComment("");
      onDone(p);
    },
    onError: re.onError,
  });
  const close = () => {
    re.reset();
    m.reset();
    onClose();
  };
  return (
    <FormDialog
      open={open}
      onOpenChange={(v) => !v && close()}
      title={`Откатить к версии ${target ?? ""}`}
      description={`Появится новая версия ${current + 1} с содержимым версии ${target ?? ""}. Прежние версии останутся.`}
    >
      <ErrorBanner error={diff.error} />
      {diff.data && <DiffView diff={diff.data} />}
      <Field label="Комментарий (необязательно)">{({ id }) => <Input id={id} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={500} />}</Field>
      <ReauthPrompt r={re} />
      <ErrorBanner error={visibleError(m.error)} />
      {!diff.data && !diff.error && <Banner kind="info">Загружаю различия…</Banner>}
      <div className="flex justify-end gap-2">
        <Button onClick={close}>Отменить</Button>
        <Button variant="danger" disabled={m.isPending || !diff.data || !re.ready} onClick={() => m.mutate()}>
          Откатить к версии {target}
        </Button>
      </div>
    </FormDialog>
  );
}
