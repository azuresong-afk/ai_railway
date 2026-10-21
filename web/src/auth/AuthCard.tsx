import type { FormEvent, ReactNode } from "react";
import { Button } from "../ui/Button";
import { Banner, Panel } from "../ui/Layout";

// Общая рамка экранов входа и первичной настройки.
export function AuthCard({
  title,
  intro,
  error,
  submit,
  busy,
  onSubmit,
  children,
  footer,
}: {
  title: string;
  intro?: string;
  error?: string | undefined;
  submit: string;
  busy?: boolean;
  onSubmit: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const handle = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <Panel className="w-full max-w-sm space-y-4 p-6">
        <h1 className="text-xl font-semibold">{title}</h1>
        {intro && <p className="text-sm text-muted">{intro}</p>}
        <form onSubmit={handle} className="space-y-4" noValidate>
          {children}
          {error && <Banner kind="error">{error}</Banner>}
          <Button type="submit" variant="primary" className="w-full" disabled={busy}>
            {submit}
          </Button>
        </form>
        {footer}
      </Panel>
    </main>
  );
}
