import * as Tabs from "@radix-ui/react-tabs";
import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { type Severity, ShapeIcon } from "./icons";

// Панель отделяется фоном и линией 1 px, без тени (ТЗ 6.2).
export function Panel({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`rounded-panel border border-line bg-surface p-4 ${className}`} {...rest} />;
}

export function TabBar({
  label,
  tabs,
  defaultValue,
}: {
  label: string;
  tabs: { value: string; title: string; content: ReactNode }[];
  defaultValue: string;
}) {
  return (
    <Tabs.Root defaultValue={defaultValue}>
      <Tabs.List aria-label={label} className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <Tabs.Trigger
            key={t.value}
            value={t.value}
            className="-mb-px h-[var(--control-h)] border-b-2 border-transparent px-3 text-base text-muted hover:text-fg data-[state=active]:border-accent data-[state=active]:font-medium data-[state=active]:text-fg"
          >
            {t.title}
          </Tabs.Trigger>
        ))}
      </Tabs.List>
      {tabs.map((t) => (
        <Tabs.Content key={t.value} value={t.value} className="pt-3">
          {t.content}
        </Tabs.Content>
      ))}
    </Tabs.Root>
  );
}

export function Table({ className = "", ...rest }: HTMLAttributes<HTMLTableElement>) {
  return (
    <table className={`w-full border-collapse text-left text-base ${className}`} {...rest} />
  );
}

export function Th({ className = "", ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={`border-b border-line-strong px-3 py-1.5 text-sm font-medium text-muted ${className}`}
      {...rest}
    />
  );
}

// Числовые колонки выравниваются вправо, цифры табличные (font-variant-numeric в body).
export function Td({ className = "", ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={`h-[var(--row-h)] border-b border-line px-3 ${className}`} {...rest} />;
}

type BannerKind = "info" | "warning" | "error";
// Форма значка, подпись и цвет значка для каждого вида сообщения.
const banners = new Map<BannerKind, { shape: Severity; title: string; color: string }>([
  ["info", { shape: "info", title: "Сообщение", color: "text-sev-info" }],
  ["warning", { shape: "medium", title: "Внимание", color: "text-sev-medium" }],
  ["error", { shape: "critical", title: "Ошибка", color: "text-sev-critical" }],
]);

// Встроенное сообщение: значок своей формы и текст-подпись, цвет — дополнение.
export function Banner({ kind, children }: { kind: BannerKind; children: ReactNode }) {
  const b = banners.get(kind)!;
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      className="flex items-start gap-2 rounded-panel border border-line bg-surface p-3 text-base"
    >
      <span className={`mt-0.5 ${b.color}`}>
        <ShapeIcon kind={b.shape} />
      </span>
      <div>
        <span className="font-medium">{b.title}. </span>
        {children}
      </div>
    </div>
  );
}

export function EmptyState({ title, action }: { title: string; action: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-panel border border-dashed border-line-strong p-8 text-center">
      <p className="text-md font-medium">{title}</p>
      {action}
    </div>
  );
}

// Сырое содержимое запросов и ответов: только текст (ТЗ 6.9), моноширинный шрифт, ссылки не кликабельны.
export function RawText({ children }: { children: string }) {
  return (
    <pre className="overflow-auto rounded-control border border-line bg-bg p-3 font-mono text-sm whitespace-pre-wrap break-words">
      {children}
    </pre>
  );
}
