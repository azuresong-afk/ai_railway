import { useEffect, useState } from "react";

// Секунд до срока, не меньше нуля; пересчёт раз в секунду, пока вкладка видима.
export function remainingSeconds(deadline: string, now: number): number {
  return Math.max(0, Math.ceil((new Date(deadline).getTime() - now) / 1000));
}

export function useCountdown(deadline: string, active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active, deadline]);
  return remainingSeconds(deadline, now);
}

// «4:05» или «1:02:03».
export function formatCountdown(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const two = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${two(m)}:${two(s)}` : `${m}:${two(s)}`;
}
