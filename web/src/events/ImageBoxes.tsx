// Рамки находок поверх изображения (ТЗ 5.17, 6.x, задача 5.46). Всё рисуется SVG без внешних ресурсов: размеры холста — пиксели исходного растра,
// поэтому рамки из события ложатся на изображение без пересчёта. Само изображение — только data:-адрес (строгий CSP: img-src 'self' data:).

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface BoxMark {
  // Номер находки в списке под рисунком.
  n: number;
  title: string;
  box: Box;
}

// Больше рамок не рисуем: в событии находок до 1024, а читаемость рисунка теряется раньше.
export const maxDrawnBoxes = 200;

const dataImage = /^data:image\/(png|jpeg|gif|webp|bmp|tiff);base64,[A-Za-z0-9+/=_-]+$/;

// Рамка внутри холста: координаты из события не доверяются, лишнее обрезается.
export function clampBox(b: Box, width: number, height: number): Box | null {
  if (![b.x, b.y, b.w, b.h, width, height].every((v) => Number.isFinite(v)) || width <= 0 || height <= 0) return null;
  const x = Math.min(Math.max(b.x, 0), width);
  const y = Math.min(Math.max(b.y, 0), height);
  const w = Math.min(b.w, width - x);
  const h = Math.min(b.h, height - y);
  return w > 0 && h > 0 ? { x, y, w, h } : null;
}

export function ImageBoxes({ width, height, marks, src, label }: { width: number; height: number; marks: BoxMark[]; src?: string | undefined; label: string }) {
  const drawn = marks.slice(0, maxDrawnBoxes).flatMap((m) => {
    const box = clampBox(m.box, width, height);
    return box ? [{ ...m, box }] : [];
  });
  // Размеры подписи — доля холста: у скриншота 1920 пикселей и у значка 64 пикселя читаемы одинаково.
  const unit = Math.max(width, height) / 100;
  const font = Math.max(unit * 2.4, 6);
  const stroke = Math.max(unit * 0.25, 1);
  const image = src !== undefined && dataImage.test(src) ? src : undefined;
  return (
    <figure className="flex flex-col gap-1">
      <svg
        role="img"
        aria-label={label}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="xMidYMid meet"
        className="h-auto max-h-[28rem] w-full rounded-control border border-line bg-bg"
      >
        {image ? (
          <image href={image} x={0} y={0} width={width} height={height} />
        ) : (
          <>
            <rect x={0} y={0} width={width} height={height} className="fill-[var(--c-surface-hover)]" />
            <text x={width / 2} y={height / 2} textAnchor="middle" fontSize={font * 1.4} className="fill-[var(--c-text-muted)]">
              {`${width} × ${height} пикселей`}
            </text>
          </>
        )}
        {drawn.map((m) => (
          <g key={m.n}>
            <title>{m.title}</title>
            <rect
              x={m.box.x}
              y={m.box.y}
              width={m.box.w}
              height={m.box.h}
              fill="none"
              strokeWidth={stroke}
              strokeDasharray={`${stroke * 4} ${stroke * 2}`}
              className="stroke-[var(--c-sev-critical)]"
            />
            <rect x={m.box.x} y={m.box.y} width={font * (String(m.n).length + 1)} height={font * 1.4} className="fill-[var(--c-sev-critical)]" />
            <text x={m.box.x + font * 0.4} y={m.box.y + font * 1.05} fontSize={font} fontWeight={700} className="fill-white">
              {m.n}
            </text>
          </g>
        ))}
      </svg>
      {marks.length > maxDrawnBoxes && <figcaption className="text-xs text-muted">На рисунке первые {maxDrawnBoxes} рамок из {marks.length}.</figcaption>}
    </figure>
  );
}
