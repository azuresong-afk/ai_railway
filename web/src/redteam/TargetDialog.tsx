import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { area, ErrorBanner, fieldError, FormDialog } from "../admin/common";
import { appsApi } from "../apps/api";
import { Button } from "../ui/Button";
import { Field, Input, Radios, Select } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { redteamApi, type TargetInput } from "./api";

// Приложения для выбора цели «через шлюз». Список читается правом applications.read: без него поле — обычный ввод ID.
export function useApps() {
  return useQuery({ queryKey: ["redteam", "apps"], queryFn: ({ signal }) => appsApi.applications(signal), retry: false });
}

const defaultTemplate = '{"model": "default", "messages": "{{messages}}"}';
const defaultLimits = { rate_per_minute: 30, concurrency: 2, request_timeout_sec: 30, run_timeout_min: 30 };
type Header = { name: string; value: string };

// Добавление цели. Для адреса заказчика сервер требует основание и повторную проверку (пароль или код второго фактора) — только из консоли.
// Пароль и код живут в состоянии диалога и стираются при закрытии.
export function TargetDialog({ mfa, onClose }: { mfa: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const apps = useApps();
  const [kind, setKind] = useState<"gateway" | "endpoint">("gateway");
  const [name, setName] = useState("");
  const [appId, setAppId] = useState("");
  const [model, setModel] = useState("");
  const [url, setUrl] = useState("");
  const [template, setTemplate] = useState(defaultTemplate);
  const [path, setPath] = useState("choices.0.message.content");
  const [headers, setHeaders] = useState<Header[]>([]);
  const [authHeader, setAuthHeader] = useState("");
  const [ca, setCa] = useState("");
  const [note, setNote] = useState("");
  const [storage, setStorage] = useState("none");
  const [limits, setLimits] = useState(defaultLimits);
  const [secret, setSecret] = useState("");

  const save = useMutation({
    mutationFn: () => {
      const body: TargetInput =
        kind === "gateway"
          ? { name: name.trim(), kind, app_id: appId.trim(), model: model.trim(), storage: storage as "none" | "masked", limits }
          : {
              name: name.trim(),
              kind,
              url: url.trim(),
              request_template: template,
              response_path: path.trim(),
              ...(headers.length ? { headers: headers.map((h) => ({ name: h.name.trim(), value: h.value })) } : {}),
              ...(authHeader.trim() ? { auth_header: authHeader.trim() } : {}),
              ...(ca.trim() ? { ca_pem: ca.trim() } : {}),
              authorization_note: note.trim(),
              storage: storage as "none" | "masked",
              limits,
              ...(mfa ? { code: secret } : { password: secret }),
            };
      return redteamApi.createTarget(body);
    },
    onSuccess: async () => {
      setSecret("");
      await qc.invalidateQueries({ queryKey: ["redteam"] });
      onClose();
    },
    onError: () => setSecret(""),
  });
  const err = (f: string) => {
    const e = fieldError(save.error, f);
    return e ? { error: e } : {};
  };
  const ready =
    name.trim() !== "" &&
    (kind === "gateway" ? appId.trim() !== "" && model.trim() !== "" : url.trim() !== "" && note.trim().length >= 10 && secret !== "");
  const setHeader = (i: number, h: Partial<Header>) => setHeaders(headers.map((x, j) => (j === i ? { ...x, ...h } : x)));
  const setLimit = (k: keyof typeof defaultLimits) => (e: { target: { value: string } }) => setLimits({ ...limits, [k]: Number(e.target.value) || 0 });

  return (
    <FormDialog
      open
      onOpenChange={(v) => !v && onClose()}
      title="Добавление цели"
      description="Цель — адрес, на который продукт отправляет атаки. Секретные значения здесь не сохраняются: заголовок с секретом вводится при каждом запуске."
    >
      <Field label="Название" {...err("name")}>
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}
      </Field>
      <Radios
        label="Вид цели"
        value={kind}
        onValueChange={(v) => setKind(v === "endpoint" ? "endpoint" : "gateway")}
        options={[
          { value: "gateway", label: "Приложение продукта (через шлюз)" },
          { value: "endpoint", label: "Адрес приложения заказчика" },
        ]}
      />
      {kind === "gateway" ? (
        <>
          <Field label="Приложение" hint="Атаки пойдут через шлюз с ключом, который сервер выпустит на время запуска." {...err("app_id")}>
            {({ id, describedBy }) =>
              apps.data ? (
                <Select id={id} aria-describedby={describedBy} value={appId} onChange={(e) => setAppId(e.target.value)}>
                  <option value="">Выберите приложение</option>
                  {apps.data.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              ) : (
                <Input id={id} aria-describedby={describedBy} value={appId} onChange={(e) => setAppId(e.target.value)} />
              )
            }
          </Field>
          <Field label="Модель" hint="Одна из моделей, разрешённых приложению." {...err("model")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={128} value={model} onChange={(e) => setModel(e.target.value)} />}
          </Field>
        </>
      ) : (
        <>
          <Banner kind="warning">
            Атаки уйдут на внешний адрес. Добавляйте только свои приложения или те, на проверку которых есть письменное разрешение. Действие запишется в журнал
            аудита.
          </Banner>
          <Field label="Адрес" hint="Схема (http или https), узел, явный порт и путь: схема, затем bot.example.org:8443/v1/chat." {...err("url")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={2048} value={url} onChange={(e) => setUrl(e.target.value)} />}
          </Field>
          <Field label="Основание" hint="Договор, письмо или другое разрешение на проверку, от 10 до 500 знаков." {...err("authorization_note")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />}
          </Field>
          <Field label="Шаблон запроса" hint="JSON; строка «{{prompt}}» заменяется текстом атаки, «{{messages}}» — историей сообщений." {...err("request_template")}>
            {({ id, describedBy }) => (
              <textarea id={id} aria-describedby={describedBy} rows={4} maxLength={16384} value={template} onChange={(e) => setTemplate(e.target.value)} className={area} />
            )}
          </Field>
          <Field label="Путь к тексту ответа" hint="Через точку, например choices.0.message.content." {...err("response_path")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={256} value={path} onChange={(e) => setPath(e.target.value)} />}
          </Field>
          <fieldset className="flex flex-col gap-2">
            <legend className="text-sm font-medium">Постоянные заголовки</legend>
            <p className="text-xs text-muted">Без секретов: токены и ключи вводятся в поле ниже и не сохраняются.</p>
            {headers.map((h, i) => (
              <div key={i} className="flex gap-2">
                <Input aria-label={`Имя заголовка ${i + 1}`} maxLength={64} value={h.name} onChange={(e) => setHeader(i, { name: e.target.value })} />
                <Input aria-label={`Значение заголовка ${i + 1}`} maxLength={1024} value={h.value} onChange={(e) => setHeader(i, { value: e.target.value })} />
                <Button aria-label={`Убрать заголовок ${i + 1}`} onClick={() => setHeaders(headers.filter((_, j) => j !== i))}>
                  Убрать
                </Button>
              </div>
            ))}
            {headers.length < 8 && (
              <div>
                <Button onClick={() => setHeaders([...headers, { name: "", value: "" }])}>Добавить заголовок</Button>
              </div>
            )}
          </fieldset>
          <Field label="Имя секретного заголовка" hint="Например Authorization. Значение спросим при запуске и не сохраним." {...err("auth_header")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} maxLength={64} value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} />}
          </Field>
          <Field label="Корневой сертификат цели (PEM)" hint="Только если адрес https и сертификат выдан не общим удостоверяющим центром." {...err("ca_pem")}>
            {({ id, describedBy }) => <textarea id={id} aria-describedby={describedBy} rows={4} maxLength={65536} value={ca} onChange={(e) => setCa(e.target.value)} className={area} />}
          </Field>
        </>
      )}
      <Radios
        label="Выдержки ответов цели"
        value={storage}
        onValueChange={setStorage}
        options={[
          { value: "none", label: "Не хранить (ответы цели нигде не сохраняются)" },
          ...(kind === "endpoint" ? [{ value: "masked", label: "Хранить замаскированные выдержки до 1 КиБ у удавшихся атак" }] : []),
        ]}
      />
      <fieldset className="grid grid-cols-2 gap-3">
        <legend className="text-sm font-medium">Пределы нагрузки</legend>
        <Field label="Запросов в минуту (1–600)">{({ id }) => <Input id={id} type="number" min={1} max={600} value={limits.rate_per_minute} onChange={setLimit("rate_per_minute")} />}</Field>
        <Field label="Одновременных запросов (1–8)">{({ id }) => <Input id={id} type="number" min={1} max={8} value={limits.concurrency} onChange={setLimit("concurrency")} />}</Field>
        <Field label="Срок запроса, с (5–120)">{({ id }) => <Input id={id} type="number" min={5} max={120} value={limits.request_timeout_sec} onChange={setLimit("request_timeout_sec")} />}</Field>
        <Field label="Срок запуска, мин (1–120)">{({ id }) => <Input id={id} type="number" min={1} max={120} value={limits.run_timeout_min} onChange={setLimit("run_timeout_min")} />}</Field>
      </fieldset>
      {kind === "endpoint" && (
        <Field label={mfa ? "Код из приложения-аутентификатора" : "Текущий пароль"} hint="Подтверждение нужно для адреса заказчика: так мы убеждаемся, что цель добавляете вы.">
          {({ id, describedBy }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              type={mfa ? "text" : "password"}
              autoComplete={mfa ? "one-time-code" : "current-password"}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          )}
        </Field>
      )}
      <ErrorBanner error={save.error} />
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Отменить</Button>
        <Button variant="primary" disabled={!ready || save.isPending} onClick={() => save.mutate()}>
          Добавить цель
        </Button>
      </div>
    </FormDialog>
  );
}
