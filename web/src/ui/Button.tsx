import { type ButtonHTMLAttributes, forwardRef } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const variants = new Map<Variant, string>([
  ["primary", "bg-accent text-on-accent border-transparent hover:brightness-110"],
  ["secondary", "bg-surface text-fg border-line-strong hover:bg-surface-hover"],
  ["danger", "bg-surface text-fg border-sev-critical hover:bg-surface-hover"],
  ["ghost", "bg-transparent text-fg border-transparent hover:bg-surface-hover"],
]);

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

// Подпись кнопки говорит, что произойдёт (ТЗ 6.7). Тип по умолчанию button, а не submit.
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", className = "", type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={`inline-flex h-[var(--control-h)] items-center justify-center gap-2 rounded-control border px-3 text-base font-medium transition-colors duration-[var(--dur-fast)] disabled:cursor-not-allowed disabled:opacity-50 ${variants.get(variant)} ${className}`}
      {...rest}
    />
  );
});
