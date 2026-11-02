// Команда synth-media строит корпус изображений testdata/corpus/media
// (задача 5.36; строки DM-45–DM-47): карточки и сканы с синтетическими ПДн,
// бледный и мелкий текст, инструкции-инъекции на изображении, QR-коды с
// текстом, текст в метаданных PNG и JPEG, чистые изображения для ложных
// срабатываний. На каждое изображение — эталонный текст для CER (<id>.txt)
// и ожидаемые находки (<id>.json); манифест — с SHA-256 каждого файла.
//
//	go run ./tools/synth-media                 # перегенерировать корпус (нужен Chromium)
//	go run ./tools/synth-media -only card-01   # один образец и манифест
//	go run ./tools/synth-media -check          # сверить корпус с манифестом (без Chromium)
//
// Отрисовка — headless Chromium из окружения (AISEC_CHROMIUM), без новых
// библиотек; CI корпус не перегенерирует — готовые файлы лежат в
// репозитории. Подробности — testdata/corpus/media/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	out := flag.String("out", "testdata/corpus/media", "каталог корпуса")
	chromium := flag.String("chromium", os.Getenv("AISEC_CHROMIUM"), "путь к Chromium (по умолчанию — AISEC_CHROMIUM)")
	fonts := flag.String("fonts", "web/src/assets/fonts", "каталог локальных шрифтов (OFL)")
	only := flag.String("only", "", "перегенерировать только образец с этим ID")
	check := flag.Bool("check", false, "только сверить корпус с манифестом")
	flag.Parse()
	if err := run(*out, *chromium, *fonts, *only, *check); err != nil {
		fmt.Fprintln(os.Stderr, "synth-media:", err)
		os.Exit(1)
	}
}

func run(out, chromium, fonts, only string, check bool) error {
	if !check {
		if chromium == "" {
			return fmt.Errorf("задайте путь к Chromium: -chromium или AISEC_CHROMIUM")
		}
		css, err := fontFaces(fonts)
		if err != nil {
			return err
		}
		work, err := os.MkdirTemp("", "synth-media-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(work) }() //nolint:gosec // G104: временный каталог; ошибка удаления не влияет на корпус
		if err := os.MkdirAll(out, 0o750); err != nil {
			return err
		}
		if err := generate(&renderer{chromium: chromium, fontCSS: css, work: work}, out, only); err != nil {
			return err
		}
	}
	problems, err := verify(out)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n%s", errProblems, strings.Join(problems, "\n"))
	}
	total, err := dirSize(out)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "synth-media: изображений %d, объём каталога %.1f КиБ (%s)\n", len(samples()), float64(total)/1024, out)
	return err
}

func dirSize(dir string) (int64, error) {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			return 0, err
		}
		total += fi.Size()
	}
	return total, nil
}
