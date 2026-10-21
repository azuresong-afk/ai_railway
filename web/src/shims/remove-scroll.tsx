import { type ElementType, forwardRef, type ReactNode, useEffect } from "react";

// Замена react-remove-scroll (ADR-0010). Оригинал вставляет элемент <style>, который
// строгий CSP из ТЗ 6.9 (style-src 'self') блокирует. Здесь блокировка прокрутки —
// атрибут data-scroll-locked на body; правило для него лежит в index.css.
// Подключается алиасом в vite.config.ts; Radix передаёт as, allowPinchZoom, shards и др.

let locks = 0;

function lock(): () => void {
  locks += 1;
  document.body.setAttribute("data-scroll-locked", String(locks));
  return () => {
    locks -= 1;
    if (locks <= 0) {
      locks = 0;
      document.body.removeAttribute("data-scroll-locked");
    } else {
      document.body.setAttribute("data-scroll-locked", String(locks));
    }
  };
}

interface Props {
  as?: ElementType;
  children?: ReactNode;
  enabled?: boolean;
  // Параметры оригинала, не нужные здесь: не должны попасть в DOM.
  allowPinchZoom?: boolean;
  shards?: unknown;
  forwardProps?: boolean;
  inert?: boolean;
  noRelative?: boolean;
  noIsolation?: boolean;
  removeScrollBar?: boolean;
  [key: string]: unknown;
}

export const RemoveScroll = forwardRef<unknown, Props>(function RemoveScroll(
  { as: As = "div" as ElementType, children, enabled = true, allowPinchZoom, shards, forwardProps, inert, noRelative, noIsolation, removeScrollBar, ...rest },
  ref,
) {
  const Comp = As as ElementType;
  void [allowPinchZoom, shards, forwardProps, inert, noRelative, noIsolation, removeScrollBar];
  useEffect(() => (enabled ? lock() : undefined), [enabled]);
  return (
    <Comp {...rest} ref={ref}>
      {children}
    </Comp>
  );
});
