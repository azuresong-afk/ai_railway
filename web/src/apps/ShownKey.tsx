import { useState } from "react";
import { Button } from "../ui/Button";
import { Banner } from "../ui/Layout";

// Ключ приложения, показанный один раз (ИАФ.8). Значение живёт только в состоянии того, кто показывает
// диалог: закрытие диалога обнуляет это состояние, в хранилища браузера ключ не попадает.
export function ShownKey({ secret, onDone }: { secret: string; onDone: () => void }) {
  const [copied, setCopied] = useState<"yes" | "no">();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied("yes");
    } catch {
      // Буфер обмена недоступен (запрет браузера, не защищённый контекст): ключ можно выделить и скопировать руками.
      setCopied("no");
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-sm font-medium">
        Ключ приложения
        <input
          readOnly
          value={secret}
          onFocus={(e) => e.currentTarget.select()}
          className="h-[var(--control-h)] w-full rounded-control border border-line-strong bg-bg px-2 font-mono text-base"
        />
      </label>
      <div className="flex items-center gap-3">
        <Button onClick={copy}>Скопировать ключ</Button>
        {copied === "yes" && <span role="status" className="text-sm text-muted">Ключ скопирован.</span>}
        {copied === "no" && (
          <span role="status" className="text-sm text-muted">
            Не удалось скопировать автоматически. Выделите ключ в поле и скопируйте сочетанием Ctrl+C.
          </span>
        )}
      </div>
      <Banner kind="warning">
        Ключ показан один раз. После закрытия окна его нельзя посмотреть, останется только выпустить новый. Храните его в менеджере
        секретов, а не в коде и не в переписке.
      </Banner>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onDone}>
          Я сохранил ключ
        </Button>
      </div>
    </div>
  );
}
