import * as Toast from "@radix-ui/react-toast";
import type { ReactNode } from "react";
import { Button } from "./Button";

// Уведомление о совершённом действии: название действия совпадает с кнопкой («Опубликовать» → «Опубликовано»).
export function Toaster({
  open,
  onOpenChange,
  title,
  children,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  children: ReactNode;
}) {
  return (
    <Toast.Provider duration={5000}>
      <Toast.Root
        open={open}
        onOpenChange={onOpenChange}
        className="rounded-panel border border-line bg-surface p-3 text-fg shadow-popup"
      >
        <Toast.Title className="text-base font-medium">{title}</Toast.Title>
        <Toast.Description className="text-sm text-muted">{children}</Toast.Description>
        <Toast.Close asChild>
          <Button variant="ghost" className="mt-2">
            Закрыть
          </Button>
        </Toast.Close>
      </Toast.Root>
      <Toast.Viewport className="fixed right-4 bottom-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2" />
    </Toast.Provider>
  );
}
