import * as Checkbox from "@radix-ui/react-checkbox";
import * as Label from "@radix-ui/react-label";
import * as RadioGroup from "@radix-ui/react-radio-group";
import * as Switch from "@radix-ui/react-switch";
import { forwardRef, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, useId } from "react";

const control =
  "h-[var(--control-h)] w-full rounded-control border border-line-strong bg-surface px-2 text-base text-fg placeholder:text-muted disabled:opacity-50 aria-[invalid=true]:border-sev-critical";

// Подпись, подсказка и ошибка поля. Ошибка говорит, что случилось и как исправить (ТЗ 6.7).
export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const describedBy = [hintId, errId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="flex flex-col gap-1">
      <Label.Root htmlFor={id} className="text-sm font-medium">
        {label}
      </Label.Root>
      {children({ id, describedBy, invalid: Boolean(error) })}
      {hint && (
        <p id={hintId} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errId} role="alert" className="text-xs font-medium text-fg">
          <span className="text-sev-critical" aria-hidden="true">
            ●{" "}
          </span>
          {error}
        </p>
      )}
    </div>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className = "", ...rest },
  ref,
) {
  return <input ref={ref} className={`${control} ${className}`} {...rest} />;
});

// Родной <select>: Radix Select вставляет <style> и не проходит строгий CSP (ADR-0010).
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className = "", ...rest },
  ref,
) {
  return <select ref={ref} className={`${control} ${className}`} {...rest} />;
});

export function Check({
  label,
  checked,
  onCheckedChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex items-center gap-2">
      <Checkbox.Root
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(v) => onCheckedChange(v === true)}
        className="flex size-4 items-center justify-center rounded-control border border-line-strong bg-surface data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:opacity-50"
      >
        <Checkbox.Indicator className="text-on-accent">
          <svg viewBox="0 0 12 12" width="10" height="10" aria-hidden="true">
            <path d="m2 6.2 2.6 2.6L10 3.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </Checkbox.Indicator>
      </Checkbox.Root>
      <Label.Root htmlFor={id} className="text-base">
        {label}
      </Label.Root>
    </div>
  );
}

export function Toggle({
  label,
  checked,
  onCheckedChange,
}: {
  label: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="flex items-center gap-2">
      <Switch.Root
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        className="relative h-5 w-9 rounded-full border border-line-strong bg-surface data-[state=checked]:border-accent data-[state=checked]:bg-accent"
      >
        <Switch.Thumb className="block size-3.5 translate-x-0.5 rounded-full bg-[var(--c-border-strong)] transition-transform duration-[var(--dur-fast)] data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-on-accent" />
      </Switch.Root>
      <Label.Root htmlFor={id} className="text-base">
        {label}
      </Label.Root>
    </div>
  );
}

export function Radios({
  label,
  value,
  onValueChange,
  options,
}: {
  label: string;
  value: string;
  onValueChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  const base = useId();
  return (
    <RadioGroup.Root aria-label={label} value={value} onValueChange={onValueChange} className="flex flex-col gap-1.5">
      {options.map((o) => (
        <div key={o.value} className="flex items-center gap-2">
          <RadioGroup.Item
            id={`${base}-${o.value}`}
            value={o.value}
            className="flex size-4 items-center justify-center rounded-full border border-line-strong bg-surface data-[state=checked]:border-accent"
          >
            <RadioGroup.Indicator className="block size-2 rounded-full bg-accent" />
          </RadioGroup.Item>
          <Label.Root htmlFor={`${base}-${o.value}`} className="text-base">
            {o.label}
          </Label.Root>
        </div>
      ))}
    </RadioGroup.Root>
  );
}
