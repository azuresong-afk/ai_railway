// Команда aisec-cli — служебные операции: выпуск ключей приложений (этап 1);
// инициализация, миграции, резервное копирование, проверка целостности —
// с этапа 2.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

var version = "dev"

const usage = `aisec-cli — служебные операции AISec.

Команды:
  app-key -expires ГГГГ-ММ-ДД   выпустить ключ приложения
  version                       версия
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

// say пишет сообщение для человека; если вывод недоступен, сообщить об этом
// уже некуда — код возврата всё равно отражает результат.
func say(w io.Writer, format string, a ...any) {
	if _, err := fmt.Fprintf(w, format, a...); err != nil {
		return
	}
}

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) == 0 {
		say(stderr, "%s", usage)
		return 2
	}
	switch args[0] {
	case "app-key":
		if err := appKey(args[1:], stdout, stderr, now); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli app-key: %v\n", err)
			return 1
		}
		return 0
	case "version":
		say(stdout, "%s\n", version)
		return 0
	default:
		say(stderr, "неизвестная команда %q\n\n%s", args[0], usage)
		return 2
	}
}

// appKey выпускает ключ приложения. Ключ печатается один раз и нигде не
// сохраняется (ТЗ, 5.4); в конфигурацию шлюза вносится только префикс и
// SHA-256.
func appKey(args []string, stdout, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("app-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	expires := fs.String("expires", "", "срок действия ключа, ГГГГ-ММ-ДД (рекомендуется)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *expires != "" {
		t, err := time.Parse(time.DateOnly, *expires)
		if err != nil {
			return errors.New("expires — дата ГГГГ-ММ-ДД")
		}
		if !t.After(now) {
			return errors.New("expires — дата в будущем")
		}
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	key, prefix, hash, err := auth.NewAppKey(rnd, h)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Ключ приложения (показывается один раз, передайте владельцу приложения по защищённому каналу):\n\n  %s\n\n"+
		"Добавьте в applications[].keys файла конфигурации шлюза:\n\n%s", key, auth.FormatKeyEntry(prefix, hash, *expires))
	return err
}
