import * as AlertDialog from "@radix-ui/react-alert-dialog";
import * as Checkbox from "@radix-ui/react-checkbox";
import * as Collapsible from "@radix-ui/react-collapsible";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Label from "@radix-ui/react-label";
import * as Popover from "@radix-ui/react-popover";
import * as RadioGroup from "@radix-ui/react-radio-group";
import * as Switch from "@radix-ui/react-switch";
import * as Tabs from "@radix-ui/react-tabs";
import * as Toast from "@radix-ui/react-toast";
import * as Tooltip from "@radix-ui/react-tooltip";
import { useState } from "react";

// Макет примитивов Radix UI для проверки строгого CSP (ТЗ, 6.9; задача 2.22).
// Доступен по адресу #/dev/radix, экранов консоли не содержит.
export function RadixMockup() {
  const [toastOpen, setToastOpen] = useState(false);
  const [checked, setChecked] = useState(false);
  const [on, setOn] = useState(false);
  const [open, setOpen] = useState(false);

  return (
    <Tooltip.Provider delayDuration={0}>
      <Toast.Provider>
        <main className="mx-auto max-w-3xl space-y-6 p-8">
          <h1 className="text-2xl font-semibold">Макет Radix UI</h1>

          <section aria-label="Диалог" className="space-x-2">
            <Dialog.Root>
              <Dialog.Trigger className="rounded border px-3 py-1">Открыть карточку</Dialog.Trigger>
              <Dialog.Portal>
                <Dialog.Overlay className="fixed inset-0 bg-black/40" />
                <Dialog.Content className="fixed top-1/2 left-1/2 w-96 -translate-x-1/2 -translate-y-1/2 rounded bg-white p-4">
                  <Dialog.Title>Карточка события</Dialog.Title>
                  <Dialog.Description>Содержимое замаскировано.</Dialog.Description>
                  <Dialog.Close className="mt-2 rounded border px-3 py-1">Закрыть</Dialog.Close>
                </Dialog.Content>
              </Dialog.Portal>
            </Dialog.Root>

            <AlertDialog.Root>
              <AlertDialog.Trigger className="rounded border px-3 py-1">Принять оповещения</AlertDialog.Trigger>
              <AlertDialog.Portal>
                <AlertDialog.Overlay className="fixed inset-0 bg-black/40" />
                <AlertDialog.Content className="fixed top-1/2 left-1/2 w-96 -translate-x-1/2 -translate-y-1/2 rounded bg-white p-4">
                  <AlertDialog.Title>Принять выбранные оповещения?</AlertDialog.Title>
                  <AlertDialog.Description>Действие попадёт в журнал аудита.</AlertDialog.Description>
                  <AlertDialog.Cancel className="mr-2 rounded border px-3 py-1">Отменить</AlertDialog.Cancel>
                  <AlertDialog.Action className="rounded border px-3 py-1">Принять</AlertDialog.Action>
                </AlertDialog.Content>
              </AlertDialog.Portal>
            </AlertDialog.Root>
          </section>

          <section aria-label="Меню и всплывающие" className="space-x-2">
            <DropdownMenu.Root>
              <DropdownMenu.Trigger className="rounded border px-3 py-1">Колонки</DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content className="rounded border bg-white p-1">
                  <DropdownMenu.CheckboxItem checked className="px-2 py-1">Время</DropdownMenu.CheckboxItem>
                  <DropdownMenu.Item className="px-2 py-1">Приложение</DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>

            <Popover.Root>
              <Popover.Trigger className="rounded border px-3 py-1">Фильтр</Popover.Trigger>
              <Popover.Portal>
                <Popover.Content className="rounded border bg-white p-3">
                  Фильтр по решению
                  <Popover.Arrow />
                </Popover.Content>
              </Popover.Portal>
            </Popover.Root>

            <Tooltip.Root>
              <Tooltip.Trigger className="rounded border px-3 py-1">3 мин назад</Tooltip.Trigger>
              <Tooltip.Portal>
                <Tooltip.Content className="rounded bg-black px-2 py-1 text-white">
                  21.10.2026 12:03:41
                  <Tooltip.Arrow />
                </Tooltip.Content>
              </Tooltip.Portal>
            </Tooltip.Root>
          </section>

          <section aria-label="Поля формы" className="space-y-3">
            {/* Radix Select вставляет <style> (ADR-0010): вместо него — родной select */}
            <div className="flex items-center gap-2">
              <Label.Root htmlFor="mode">Режим</Label.Root>
              <select id="mode" className="rounded border px-2 py-1" defaultValue="">
                <option value="" disabled>
                  Выберите режим
                </option>
                <option value="mask">Маскировать</option>
                <option value="block">Блокировать</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <Checkbox.Root id="cb" checked={checked} onCheckedChange={(v) => setChecked(v === true)} className="size-5 rounded border">
                <Checkbox.Indicator>✓</Checkbox.Indicator>
              </Checkbox.Root>
              <Label.Root htmlFor="cb">Выбрать строку</Label.Root>
            </div>

            <div className="flex items-center gap-2">
              <Switch.Root id="sw" checked={on} onCheckedChange={setOn} className="h-5 w-9 rounded-full border">
                <Switch.Thumb className="block size-4 rounded-full bg-gray-600" />
              </Switch.Root>
              <Label.Root htmlFor="sw">Включить правило</Label.Root>
            </div>

            <RadioGroup.Root defaultValue="a" aria-label="Режим хранения" className="flex gap-4">
              <label className="flex items-center gap-1">
                <RadioGroup.Item value="a" className="size-4 rounded-full border">
                  <RadioGroup.Indicator>●</RadioGroup.Indicator>
                </RadioGroup.Item>
                Без содержимого
              </label>
              <label className="flex items-center gap-1">
                <RadioGroup.Item value="b" className="size-4 rounded-full border">
                  <RadioGroup.Indicator>●</RadioGroup.Indicator>
                </RadioGroup.Item>
                Полное
              </label>
            </RadioGroup.Root>
          </section>

          <section aria-label="Вкладки и раскрытие" className="space-y-3">
            <Tabs.Root defaultValue="rules">
              <Tabs.List aria-label="Политика" className="flex gap-2">
                <Tabs.Trigger value="rules">Правила</Tabs.Trigger>
                <Tabs.Trigger value="exceptions">Исключения</Tabs.Trigger>
              </Tabs.List>
              <Tabs.Content value="rules">Таблица правил</Tabs.Content>
              <Tabs.Content value="exceptions">Исключения со сроками</Tabs.Content>
            </Tabs.Root>

            <Collapsible.Root open={open} onOpenChange={setOpen}>
              <Collapsible.Trigger className="rounded border px-3 py-1">Трассировка решения</Collapsible.Trigger>
              <Collapsible.Content className="p-2">Детекторы и оценки</Collapsible.Content>
            </Collapsible.Root>

            <div className="h-24 w-64 overflow-auto border" tabIndex={0} aria-label="Содержимое запроса">
              <div className="h-64 p-2">Длинное содержимое запроса</div>
            </div>
          </section>

          <section aria-label="Уведомление">
            <button type="button" className="rounded border px-3 py-1" onClick={() => setToastOpen(true)}>
              Опубликовать
            </button>
            <Toast.Root open={toastOpen} onOpenChange={setToastOpen} className="rounded border bg-white p-3">
              <Toast.Title>Опубликовано</Toast.Title>
            </Toast.Root>
          </section>
        </main>
        <Toast.Viewport className="fixed right-4 bottom-4" />
      </Toast.Provider>
    </Tooltip.Provider>
  );
}
