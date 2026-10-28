import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useRef, useState } from "react";
import type { Me } from "../api/client";
import { formatAbsolute, formatNumber } from "../events/format";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Field";
import { Banner } from "../ui/Layout";
import { adminApi, type LicenseInfo } from "./api";
import { ErrorBanner } from "./common";
import { formatDay, licenseNotice, moduleTitles, stateTitles, typeTitle } from "./licenseText";

// Предел файла лицензии — как на сервере (ADR-0026, п. 2).
const maxFile = 16 * 1024;

// Вкладка «Лицензия» (ТЗ 5.15, задача 4.27): сведения — license.read, загрузка — license.manage с паролем или кодом.
export function LicenseTab({ me }: { me: Me }) {
  const q = useQuery({ queryKey: ["license"], queryFn: ({ signal }) => adminApi.license(signal) });
  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Лицензия</h2>
        {q.isError && <ErrorBanner error={q.error} />}
        {!q.data && !q.isError && <p className="text-sm text-muted">Загрузка сведений о лицензии…</p>}
        {q.data && <LicenseDetails l={q.data} />}
      </section>
      {me.permissions.includes("license.manage") && <UploadForm mfa={me.mfa?.enabled === true} replacing={(q.data?.number ?? 0) > 0} />}
    </div>
  );
}

function limitText(limit: number, used: number | undefined): string {
  const u = used === undefined ? "" : `используется ${formatNumber(used)}`;
  if (limit === 0) return u ? `без ограничения, ${u}` : "без ограничения";
  return u ? `${formatNumber(limit)}, ${u}` : formatNumber(limit);
}

function LicenseDetails({ l }: { l: LicenseInfo }) {
  const notice = licenseNotice(l);
  if (l.state === "none") {
    return (
      <Banner kind="info">
        Лицензия не загружена: установка работает в режиме «пилот по договору» без ограничений. Загрузите файл лицензии, полученный от
        производителя. После загрузки вернуться в режим пилота нельзя.
      </Banner>
    );
  }
  const rows: [string, string][] = [
    ["Состояние", stateTitles[l.state]],
    ["Номер", `№ ${l.number}`],
    ["Вид", typeTitle(l.type)],
    ["Владелец", l.licensee ? `${l.licensee.organization}, ИНН ${l.licensee.inn}` : "—"],
    ["Выдана", formatDay(l.issued_at)],
    ["Срок", `с ${formatDay(l.valid_from)} до ${formatDay(l.valid_until)}`],
    ["Льготный период до", formatDay(l.grace_until)],
    ["Шлюзы", l.limits ? limitText(l.limits.gateways, l.usage?.gateways) : "—"],
    ["Приложения", l.limits ? limitText(l.limits.applications, l.usage?.applications) : "—"],
    ["Модули", [...moduleTitles].map(([m, title]) => `${title}: ${l.modules.includes(m) ? "включён" : "нет"}`).join("; ")],
    ["Ключ подписи", l.subkey_serial ? `заверение № ${l.subkey_serial} до ${formatDay(l.subkey_not_after)}` : "—"],
    ["Отпечаток ключа", l.fingerprint ?? "—"],
    ["Загружена", l.loaded_at ? formatAbsolute(l.loaded_at) : "—"],
  ];
  return (
    <>
      {notice && <Banner kind={notice.kind}>{notice.text}</Banner>}
      <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-base">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className={k === "Отпечаток ключа" ? "font-mono text-sm break-all" : ""}>{v}</dd>
          </div>
        ))}
      </dl>
    </>
  );
}

function UploadForm({ mfa, replacing }: { mfa: boolean; replacing: boolean }) {
  const qc = useQueryClient();
  const file = useRef<HTMLInputElement>(null);
  const [secret, setSecret] = useState("");
  const [fileError, setFileError] = useState("");
  const [done, setDone] = useState<LicenseInfo>();
  const m = useMutation({
    mutationFn: (text: string) => adminApi.uploadLicense(text, mfa ? { code: secret } : { password: secret }),
    onSuccess: (v) => {
      setSecret("");
      setDone(v);
      if (file.current) file.current.value = "";
      qc.setQueryData(["license"], v);
    },
    // Пароль или код живёт только в состоянии формы и стирается после каждой попытки.
    onError: () => setSecret(""),
  });
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setDone(undefined);
    setFileError("");
    const f = file.current?.files?.[0];
    if (!f) {
      setFileError("Выберите файл лицензии.");
      return;
    }
    if (f.size > maxFile) {
      setFileError("Файл больше 16 КиБ: это не файл лицензии.");
      return;
    }
    m.mutate(await f.text());
  };
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">{replacing ? "Заменить лицензию" : "Загрузить лицензию"}</h2>
      <p className="text-sm text-muted">
        Файл *.aiseclic проверяется подписью производителя без обращения в интернет.
        {replacing ? " Заменить можно только на лицензию с большим номером." : ""} Действие запишется в журнал аудита.
      </p>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Файл лицензии" error={fileError || undefined}>
          {({ id, describedBy }) => (
            <input id={id} aria-describedby={describedBy} ref={file} type="file" accept=".aiseclic,application/json" className="text-sm" />
          )}
        </Field>
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
        {m.isError && <ErrorBanner error={m.error} />}
        {done && <Banner kind="info">Лицензия № {done.number} загружена: {stateTitles[done.state].toLowerCase()}.</Banner>}
        <div>
          <Button type="submit" variant="primary" disabled={m.isPending || secret === ""}>
            {replacing ? "Заменить лицензию" : "Загрузить лицензию"}
          </Button>
        </div>
      </form>
    </section>
  );
}
