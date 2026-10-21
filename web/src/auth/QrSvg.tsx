// QR-код TOTP из матрицы модулей, которую отдаёт сервер: рисуется как SVG без сторонних
// сервисов и без элемента style (строгий CSP, ТЗ 6.9).
export function QrSvg({ rows, label }: { rows: string[]; label: string }) {
  const quiet = 4;
  const size = (rows[0]?.length ?? 0) + quiet * 2;
  const path: string[] = [];
  rows.forEach((row, y) => {
    for (const run of row.matchAll(/1+/g)) {
      path.push(`M${run.index + quiet} ${y + quiet}h${run[0].length}v1h-${run[0].length}z`);
    }
  });
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className="h-48 w-48 rounded-control border border-line"
    >
      <rect width={size} height={size} fill="#ffffff" />
      <path d={path.join("")} fill="#000000" />
    </svg>
  );
}
