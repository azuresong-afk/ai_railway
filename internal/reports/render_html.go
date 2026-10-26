package reports

import (
	"html/template"
	"io"
)

// Сформированная страница отчёта — для просмотра и печати в PDF средствами
// браузера (Р5). Без скриптов, внешних ресурсов, шрифтов и ссылок: стили
// внутри страницы, поэтому сервер отдаёт её со своей политикой CSP
// (default-src 'none'; style-src 'unsafe-inline'), а не с политикой консоли.
// Значения выводит html/template с экранированием по контексту.
var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
:root { color-scheme: light; }
body { font: 14px/1.45 "Onest", "Segoe UI", Arial, sans-serif; color: #1a1d21; background: #fff; margin: 0; padding: 24px 32px; max-width: 1100px; }
h1 { font-size: 22px; margin: 0 0 8px; }
h2 { font-size: 16px; margin: 28px 0 6px; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0 0 8px; }
dl.meta dt { color: #4b5563; }
dl.meta dd { margin: 0; }
p.note { color: #4b5563; margin: 0 0 8px; }
table { border-collapse: collapse; width: 100%; margin: 4px 0 8px; }
th, td { border: 1px solid #c8ccd2; padding: 4px 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #eef1f5; font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
tr { break-inside: avoid; }
thead { display: table-header-group; }
p.empty { color: #4b5563; font-style: italic; }
footer { margin-top: 28px; padding-top: 8px; border-top: 1px solid #c8ccd2; color: #4b5563; font-size: 12px; }
@page { size: A4; margin: 15mm; }
@media print { body { padding: 0; max-width: none; font-size: 11px; } h2 { break-after: avoid; } }
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<dl class="meta">{{range .Meta}}<dt>{{index . 0}}</dt><dd>{{index . 1}}</dd>{{end}}</dl>
{{range .Sections}}<section>
<h2>{{.Title}}</h2>
{{if .Note}}<p class="note">{{.Note}}</p>{{end}}
{{if .Rows}}<table>
{{if .Header}}<thead><tr>{{range .Header}}<th scope="col">{{.}}</th>{{end}}</tr></thead>{{end}}
<tbody>
{{range .Rows}}<tr>{{range .}}<td{{if ne .Kind 0}} class="num"{{end}}>{{.Text}}</td>{{end}}</tr>
{{end}}</tbody>
</table>{{else}}<p class="empty">Нет данных за период.</p>{{end}}
</section>
{{end}}<footer>Отчёт сформирован платформой AISec. Содержимого запросов и ответов в отчёте нет.</footer>
</body>
</html>
`))

// WriteHTML пишет страницу отчёта.
func WriteHTML(w io.Writer, d Doc) error { return htmlTmpl.Execute(w, d) }
