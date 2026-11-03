import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBanner, fieldError, FormDialog } from "../admin/common";
import { Button } from "../ui/Button";
import { Field, Input, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { inventoryApi, type ModelCard, type ModelFile, type ModelPatch, type NewModel, type Overview } from "./api";
import { kindTitle, roleTitle, sha256Re } from "./format";

interface Row {
  path: string;
  role: ModelFile["role"];
  size: string;
  sha256: string;
}

const toRow = (f: ModelFile): Row => ({ path: f.path, role: f.role, size: String(f.size), sha256: f.sha256 });
const emptyRow = (): Row => ({ path: "", role: "weights", size: "", sha256: "" });

// Строка файла → файл API; null — строка заполнена неверно (текст ошибки отдаёт rowError).
function toFile(r: Row): ModelFile | null {
  const size = Number(r.size);
  if (r.path.trim() === "" || !/^\d{1,16}$/.test(r.size.trim()) || !Number.isSafeInteger(size) || !sha256Re.test(r.sha256.trim().toLowerCase())) return null;
  return { path: r.path.trim(), role: r.role, size, sha256: r.sha256.trim().toLowerCase() };
}

function rowError(r: Row): string | undefined {
  if (r.path.trim() === "") return "Укажите путь файла относительно каталога модели.";
  if (!/^\d{1,16}$/.test(r.size.trim())) return "Размер — целое число байт.";
  if (!sha256Re.test(r.sha256.trim().toLowerCase())) return "SHA-256 — 64 шестнадцатеричных знака.";
  return undefined;
}

const sameFile = (a: ModelFile, b: ModelFile) => a.path === b.path && a.role === b.role && a.size === b.size && a.sha256 === b.sha256;

// Ручная запись модели (задача 5.23): добавление модели заказчика и изменение карточки. Файлы с хешами — эталон для сверки
// сканером (DM-29): aisec-cli models verify сравнивает с ними файлы на узле.
export function ModelDialog({
  mode,
  card,
  providers,
  onClose,
  onDone,
}: {
  mode: "create" | "edit";
  card?: ModelCard;
  providers: Overview["providers"];
  onClose: () => void;
  onDone: (id: string) => void;
}) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<ModelCard["kind"]>(card?.kind ?? "customer");
  const [provider, setProvider] = useState(card?.provider ?? "");
  const [name, setName] = useState(card?.name ?? "");
  const [version, setVersion] = useState(card?.version ?? "");
  const [title, setTitle] = useState(card?.title ?? "");
  const [description, setDescription] = useState(card?.description ?? "");
  const [owner, setOwner] = useState(card?.owner ?? "");
  const [rows, setRows] = useState<Row[]>(card ? card.files.map(toRow) : []);
  const [checked, setChecked] = useState(false);

  const save = useMutation({
    mutationFn: (): Promise<ModelCard> => {
      const files = rows.map(toFile).filter((f): f is ModelFile => f !== null);
      if (mode === "create") {
        const body: NewModel = {
          kind,
          name: name.trim(),
          ...(provider ? { provider } : {}),
          ...(version.trim() ? { version: version.trim() } : {}),
          ...(title.trim() ? { title: title.trim() } : {}),
          ...(description.trim() ? { description: description.trim() } : {}),
          ...(owner.trim() ? { owner: owner.trim() } : {}),
          ...(files.length ? { files } : {}),
        };
        return inventoryApi.create(body);
      }
      const c = card!;
      const patch: ModelPatch = {};
      if (kind !== c.kind) patch.kind = kind;
      if (version.trim() !== c.version) patch.version = version.trim();
      if (title.trim() !== c.title) patch.title = title.trim();
      if (description.trim() !== c.description) patch.description = description.trim();
      if (owner.trim() !== c.owner) patch.owner = owner.trim();
      if (files.length !== c.files.length || files.some((f, i) => !sameFile(f, c.files.at(i)!))) patch.files = files;
      return inventoryApi.update(c.id, patch);
    },
    onSuccess: async (m) => {
      await qc.invalidateQueries({ queryKey: ["inventory"] });
      onDone(m.id);
      onClose();
    },
  });

  const rowErrors = rows.map(rowError);
  const invalidRows = rowErrors.some(Boolean);
  const providerMissing = kind === "provider" && provider === "";
  const nameMissing = mode === "create" && name.trim() === "";
  const canSave = !invalidRows && !save.isPending;
  const setRow = (i: number, r: Partial<Row>) => setRows(rows.map((x, j) => (j === i ? { ...x, ...r } : x)));

  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title={mode === "create" ? "Добавление модели в реестр" : "Изменение модели"}
      description={
        mode === "create"
          ? "Модель заказчика или модель провайдера, которой ещё не было в трафике. Хеши файлов станут эталоном для сверки на узле."
          : "Имя и провайдер не меняются: по ним модель связана с трафиком."
      }
    >
      <Field label="Вид">
        {({ id }) => (
          <Select id={id} value={kind} onChange={(e) => setKind(e.target.value as ModelCard["kind"])}>
            <option value="customer">{kindTitle.get("customer")}</option>
            <option value="provider">{kindTitle.get("provider")}</option>
          </Select>
        )}
      </Field>
      {mode === "create" ? (
        <>
          <Field
            label="Провайдер"
            hint={kind === "provider" ? "Обязателен для модели провайдера." : "Необязательно: укажите, если модель обслуживает провайдер продукта."}
            {...(fieldError(save.error, "provider") ? { error: fieldError(save.error, "provider")! } : {})}
          >
            {({ id, describedBy }) => (
              <Select id={id} aria-describedby={describedBy} value={provider} onChange={(e) => setProvider(e.target.value)}>
                <option value="">{kind === "provider" ? "Выберите провайдера" : "Без провайдера"}</option>
                {providers.map((p) => (
                  <option key={p.id} value={p.slug}>
                    {p.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Имя модели" hint="Как модель называется у провайдера или в каталоге, до 256 знаков." {...(fieldError(save.error, "name") ? { error: fieldError(save.error, "name")! } : {})}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={256} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
        </>
      ) : (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
          <dt className="text-muted">Имя</dt>
          <dd className="break-words">{card!.name}</dd>
          <dt className="text-muted">Провайдер</dt>
          <dd>{card!.provider || "—"}</dd>
        </dl>
      )}
      <Field label="Версия">{({ id }) => <Input id={id} maxLength={128} value={version} onChange={(e) => setVersion(e.target.value)} />}</Field>
      <Field label="Название">{({ id }) => <Input id={id} maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />}</Field>
      <Field label="Описание">{({ id }) => <Input id={id} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
      <Field label="Ответственный">{({ id }) => <Input id={id} maxLength={200} value={owner} onChange={(e) => setOwner(e.target.value)} />}</Field>

      <fieldset className="flex flex-col gap-2 rounded-panel border border-line p-3">
        <legend className="px-1 text-sm font-medium">Файлы и их SHA-256</legend>
        {mode === "edit" && (
          <Banner kind="warning">
            Смена хеша, размера или роли файла и удаление файла весов или адаптера ослабляют сверку хешей. Такое изменение записывается в журнал аудита как ослабление защиты.
          </Banner>
        )}
        {rows.length === 0 && <p className="text-sm text-muted">Файлов нет: сверка хешей для модели не выполняется.</p>}
        {rows.map((r, i) => (
          <div key={i} className="flex flex-col gap-2 border-b border-line pb-2">
            <div className="grid grid-cols-[1fr_9rem] gap-2">
              <Field label={`Путь файла ${i + 1}`} hint="Относительно каталога модели, через «/»">
                {({ id }) => <Input id={id} maxLength={512} value={r.path} onChange={(e) => setRow(i, { path: e.target.value })} />}
              </Field>
              <Field label={`Роль файла ${i + 1}`}>
                {({ id }) => (
                  <Select id={id} value={r.role} onChange={(e) => setRow(i, { role: e.target.value as ModelFile["role"] })}>
                    {[...roleTitle].map(([v, t]) => (
                      <option key={v} value={v}>
                        {t}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            <div className="grid grid-cols-[9rem_1fr] gap-2">
              <Field label={`Размер файла ${i + 1}, байт`}>
                {({ id }) => <Input id={id} inputMode="numeric" value={r.size} onChange={(e) => setRow(i, { size: e.target.value })} />}
              </Field>
              <Field
                label={`SHA-256 файла ${i + 1}`}
                {...(checked && rowErrors.at(i) ? { error: rowErrors.at(i)! } : {})}
              >
                {({ id, describedBy }) => (
                  <Input id={id} aria-describedby={describedBy} className="font-mono text-sm" maxLength={64} autoComplete="off" value={r.sha256} onChange={(e) => setRow(i, { sha256: e.target.value })} />
                )}
              </Field>
            </div>
            <div>
              <Button variant="ghost" aria-label={`Убрать файл ${i + 1}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                Убрать файл
              </Button>
            </div>
          </div>
        ))}
        <div>
          <Button disabled={rows.length >= 256} onClick={() => setRows([...rows, emptyRow()])}>
            Добавить файл
          </Button>
        </div>
      </fieldset>

      <ErrorBanner error={save.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button
          variant="primary"
          disabled={save.isPending || nameMissing || providerMissing}
          onClick={() => {
            setChecked(true);
            if (canSave) save.mutate();
          }}
        >
          {mode === "create" ? "Добавить модель" : "Сохранить изменения"}
        </Button>
      </div>
    </FormDialog>
  );
}
