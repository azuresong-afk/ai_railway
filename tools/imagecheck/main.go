// Команда imagecheck проверяет поставку пилота в docker compose (ЗИ.5,
// ADR-0019) — цель make images-verify.
//
//	imagecheck image -kind release|test [-release build/release] build/images/aisec-*.tar
//	imagecheck compose deploy/compose/pilot/compose.yaml
//
// image — архивы docker save: пользователь не root, нет оболочки, пакетного
// менеджера и лишних файлов, только свои порты, бинарники статические и
// побайтно совпадают с подписанным каталогом выпуска. compose — правила
// запуска: только чтение, без capabilities и повышения привилегий, отдельные
// пользователи, порты только свои и по умолчанию на 127.0.0.1, секреты
// файлами, образы закреплены.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "imagecheck:", err)
		os.Exit(1)
	}
}

// errFailed — найдены нарушения (они уже напечатаны).
var errFailed = errors.New("проверка не пройдена")

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается команда: image или compose")
	}
	switch args[0] {
	case "image":
		return runImage(args[1:], stdout, stderr)
	case "compose":
		return runCompose(args[1:], stdout, stderr)
	}
	return fmt.Errorf("неизвестная команда %q: ожидается image или compose", args[0])
}

func report(w io.Writer, what string, problems []string) error {
	if len(problems) == 0 {
		_, err := fmt.Fprintf(w, "imagecheck: %s — нарушений нет\n", what)
		return err
	}
	for _, p := range problems {
		if _, err := fmt.Fprintf(w, "imagecheck: %s: %s\n", what, p); err != nil {
			return err
		}
	}
	return errFailed
}

func runImage(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "", "вид сборки в метке ru.aisec.build-kind: release или test")
	release := fs.String("release", "", "каталог выпуска (build/release): бинарники, манифест и подпись образа должны совпасть с ним")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind != "release" && *kind != "test" {
		return errors.New("-kind: release или test")
	}
	if fs.NArg() == 0 {
		return errors.New("не указаны архивы образов")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return err
	}
	failed := false
	for _, archive := range fs.Args() {
		img, err := loadImage(archive, hasher)
		if err != nil {
			return err
		}
		if err := report(stdout, img.Tag, checkImage(img, *kind, *release)); errors.Is(err, errFailed) {
			failed = true
		} else if err != nil {
			return err
		}
	}
	if failed {
		return errFailed
	}
	return nil
}

func runCompose(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("compose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("укажите один compose-файл")
	}
	data, err := readLimitedN(fs.Arg(0), maxCompose)
	if err != nil {
		return err
	}
	c, err := parseCompose(data)
	if err != nil {
		return err
	}
	return report(stdout, fs.Arg(0), checkCompose(c))
}

func readLimitedN(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: путь к compose задаёт Makefile
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s больше %d байт", p, limit)
	}
	return data, nil
}
