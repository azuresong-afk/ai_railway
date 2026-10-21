// Пакет web встраивает собранную статику веб-консоли (web/dist) в Go-бинарник
// (ADR-0011). Каталог dist/ заполняет make web-build; в репозитории лежит
// только dist/.gitkeep, чтобы go build работал и без сборки фронтенда.
package web

import "embed"

// Dist — содержимое web/dist: index.html и assets/.
//
//go:embed all:dist
var Dist embed.FS
