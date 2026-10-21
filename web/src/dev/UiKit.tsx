import { useEffect, useState } from "react";
import { DecisionBadge, SeverityBadge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Check, Field, Input, Radios, Select, Toggle } from "../ui/Field";
import { Banner, EmptyState, Panel, RawText, TabBar, Table, Td, Th } from "../ui/Layout";
import { Confirm, Hint, Modal } from "../ui/Overlay";
import { type Decision, type Severity } from "../ui/icons";
import { Toaster } from "../ui/Toaster";

// Страница /dev/ui-kit (ТЗ 6.2): токены, типографика и базовые компоненты в обеих темах.
// Доступна только в dev-сборке и сборке e2e (см. main.tsx), в поставку не входит.

const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
const decisions: Decision[] = ["allowed", "masked", "blocked", "would_block"];
const scale = [
  ["12", "text-xs"],
  ["13", "text-sm"],
  ["14", "text-base"],
  ["16", "text-[length:var(--fs-md)]"],
  ["20", "text-lg"],
  ["24", "text-xl"],
  ["32", "text-2xl"],
] as const;
const swatches = [
  ["bg", "bg-bg"],
  ["surface", "bg-surface"],
  ["text", "bg-fg"],
  ["text-muted", "bg-muted"],
  ["accent", "bg-accent"],
  ["border", "bg-line"],
  ["border-strong", "bg-line-strong"],
] as const;

type Theme = "auto" | "light" | "dark";

function useRootAttr(name: "data-theme" | "data-density", value: string | undefined) {
  useEffect(() => {
    const el = document.documentElement;
    if (value) el.setAttribute(name, value);
    else el.removeAttribute(name);
    return () => el.removeAttribute(name);
  }, [name, value]);
}

export function UiKit() {
  const [theme, setTheme] = useState<Theme>("auto");
  const [density, setDensity] = useState("compact");
  const [checked, setChecked] = useState(true);
  const [on, setOn] = useState(false);
  const [radio, setRadio] = useState("monitor");
  const [toast, setToast] = useState(false);
  const [name, setName] = useState("");

  useRootAttr("data-theme", theme === "auto" ? undefined : theme);
  useRootAttr("data-density", density === "compact" ? undefined : density);

  return (
    <main className="mx-auto max-w-5xl space-y-8 p-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="text-2xl font-semibold">Дизайн-система консоли</h1>
        <div className="flex flex-wrap gap-4">
          <Field label="Тема">
            {({ id }) => (
              <Select id={id} value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
                <option value="auto">Как в системе</option>
                <option value="light">Светлая</option>
                <option value="dark">Тёмная</option>
              </Select>
            )}
          </Field>
          <Field label="Плотность">
            {({ id }) => (
              <Select id={id} value={density} onChange={(e) => setDensity(e.target.value)}>
                <option value="compact">Компактно</option>
                <option value="comfortable">Удобно</option>
              </Select>
            )}
          </Field>
        </div>
      </header>

      <Panel aria-label="Цвета">
        <h2 className="mb-3 text-lg font-semibold">Цвета</h2>
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {swatches.map(([label, cls]) => (
            <li key={label} className="flex items-center gap-2">
              <span className={`size-8 rounded-control border border-line-strong ${cls}`} />
              <span className="text-sm">{label}</span>
            </li>
          ))}
        </ul>
      </Panel>

      <Panel aria-label="Типографика">
        <h2 className="mb-3 text-lg font-semibold">Типографика</h2>
        <div className="space-y-1">
          {scale.map(([px, cls]) => (
            <p key={px} className={cls}>
              {px} px. Подозрительный запрос заблокирован по правилу «Утечка ключей»
            </p>
          ))}
        </div>
        <p className="mt-3 text-base">Табличные цифры: 12 345,67; 98 765,43; 11 111,11</p>
        <p className="mt-1 text-base">Ёлочки «так», дата 21.10.2026, время 15:04, буква ё: ещё, всё, её.</p>
        <p className="mt-3 text-sm text-muted">Моноширинный шрифт — только для сырого содержимого и идентификаторов:</p>
        <RawText>{"POST /v1/chat/completions\nid: evt_01HXYZ-0042\nСнилс 112-233-445 95 заменён на [СНИЛС]"}</RawText>
      </Panel>

      <Panel aria-label="Серьёзность и решения">
        <h2 className="mb-3 text-lg font-semibold">Серьёзность и решения политики</h2>
        <div className="flex flex-wrap gap-2">
          {severities.map((s) => (
            <SeverityBadge key={s} level={s} />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {decisions.map((d) => (
            <DecisionBadge key={d} decision={d} />
          ))}
        </div>
      </Panel>

      <Panel aria-label="Кнопки">
        <h2 className="mb-3 text-lg font-semibold">Кнопки</h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary">Сохранить политику</Button>
          <Button>Отменить</Button>
          <Button variant="danger">Удалить ключ</Button>
          <Button variant="ghost">Показать ещё</Button>
          <Button variant="primary" disabled>
            Недоступно
          </Button>
          <Hint text="Копирует идентификатор события">
            <Button>Копировать</Button>
          </Hint>
        </div>
      </Panel>

      <Panel aria-label="Поля">
        <h2 className="mb-3 text-lg font-semibold">Поля и переключатели</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Название политики" hint="Например, «Для службы поддержки»">
            {({ id, describedBy }) => (
              <Input id={id} aria-describedby={describedBy} value={name} onChange={(e) => setName(e.target.value)} />
            )}
          </Field>
          <Field label="Срок хранения" error="Укажите число от 1 до 365 дней">
            {({ id, describedBy, invalid }) => (
              <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} defaultValue="0" />
            )}
          </Field>
          <Field label="Режим политики">
            {({ id }) => (
              <Select id={id} defaultValue="monitor">
                <option value="monitor">Мониторинг</option>
                <option value="enforce">Защита</option>
              </Select>
            )}
          </Field>
          <Radios
            label="Действие при находке"
            value={radio}
            onValueChange={setRadio}
            options={[
              { value: "monitor", label: "Только записать" },
              { value: "mask", label: "Замаскировать" },
              { value: "block", label: "Заблокировать" },
            ]}
          />
          <Check label="Сохранять содержимое запросов" checked={checked} onCheckedChange={setChecked} />
          <Toggle label="Режим мониторинга" checked={on} onCheckedChange={setOn} />
        </div>
      </Panel>

      <Panel aria-label="Таблица">
        <h2 className="mb-3 text-lg font-semibold">Таблица</h2>
        <Table>
          <caption className="sr-only">Последние события</caption>
          <thead>
            <tr>
              <Th>Время</Th>
              <Th>Приложение</Th>
              <Th>Серьёзность</Th>
              <Th>Решение</Th>
              <Th className="text-right">Токенов</Th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <Td>21.10.2026 15:04</Td>
              <Td>Поддержка</Td>
              <Td>
                <SeverityBadge level="high" />
              </Td>
              <Td>
                <DecisionBadge decision="masked" />
              </Td>
              <Td className="text-right">1 284</Td>
            </tr>
            <tr>
              <Td>21.10.2026 15:02</Td>
              <Td>Чат HR</Td>
              <Td>
                <SeverityBadge level="critical" />
              </Td>
              <Td>
                <DecisionBadge decision="blocked" />
              </Td>
              <Td className="text-right">12 345</Td>
            </tr>
          </tbody>
        </Table>
      </Panel>

      <Panel aria-label="Вкладки и сообщения">
        <h2 className="mb-3 text-lg font-semibold">Вкладки и сообщения</h2>
        <TabBar
          label="Разделы политики"
          defaultValue="rules"
          tabs={[
            { value: "rules", title: "Правила", content: <p>Правила политики.</p> },
            { value: "history", title: "История", content: <p>История изменений.</p> },
          ]}
        />
        <div className="mt-4 space-y-2">
          <Banner kind="info">Изменения применятся к новым запросам.</Banner>
          <Banner kind="warning">Политика работает в режиме мониторинга: запросы не блокируются.</Banner>
          <Banner kind="error">Не удалось сохранить политику. Проверьте подключение и повторите.</Banner>
        </div>
        <div className="mt-4">
          <EmptyState title="Подключите первое приложение" action={<Button variant="primary">Добавить приложение</Button>} />
        </div>
      </Panel>

      <Panel aria-label="Окна">
        <h2 className="mb-3 text-lg font-semibold">Окна и уведомления</h2>
        <div className="flex flex-wrap gap-2">
          <Modal
            trigger={<Button>Открыть карточку</Button>}
            title="Карточка события"
            description="Содержимое запроса замаскировано."
          >
            <RawText>{"Мой СНИЛС: [СНИЛС]"}</RawText>
          </Modal>
          <Confirm
            trigger={<Button variant="danger">Удалить политику</Button>}
            title="Удалить политику?"
            description="Действие попадёт в журнал аудита и необратимо."
            actionLabel="Удалить"
            onConfirm={() => setToast(true)}
          />
          <Button onClick={() => setToast(true)}>Опубликовать</Button>
        </div>
      </Panel>

      <Toaster open={toast} onOpenChange={setToast} title="Опубликовано">
        Политика применена.
      </Toaster>
    </main>
  );
}
