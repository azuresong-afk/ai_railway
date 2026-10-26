// Команда aisec-cli — служебные операции: выпуск ключей приложений (этап 1);
// инициализация, миграции, резервное копирование, проверка целостности —
// с этапа 2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

var version = "dev"

const usage = `aisec-cli — служебные операции AISec.

Команды:
  app-key -expires ГГГГ-ММ-ДД   выпустить ключ приложения
  init -dir КАТАЛОГ             создать ключи установки и токен первичной настройки (AISEC_DATABASE_URL)
  init -dir КАТАЛОГ -add-audit-key
                                создать только ключ подписи журнала аудита (установка до ADR-0008)
  init -reissue-setup-token     выпустить новый токен первичной настройки, прежние погасить (только до первичной настройки)
  migrate                       применить SQL-миграции к PostgreSQL (строка подключения — AISEC_DATABASE_URL)
  audit verify [-keys КАТАЛОГ]  проверить цепочку журнала аудита (AISEC_DATABASE_URL); 3 — цепочка нарушена
  audit archive -keys КАТАЛОГ -out ФАЙЛ [-before ГГГГ-ММ-ДД]
                                архивировать записи старше срока хранения с подписанной контрольной точкой
  audit export -out ФАЙЛ [-from ГГГГ-ММ-ДД] [-to ГГГГ-ММ-ДД]
                                выгрузить журнал аудита в файл
  audit verify-archive -keys КАТАЛОГ ФАЙЛ
                                проверить файл архива без БД; 3 — архив недействителен
  gateway token -name ИМЯ [-ttl 24h] [-reregister]
                                выпустить одноразовый токен регистрации шлюза (AISEC_DATABASE_URL)
  gateway list                  шлюзы, сроки сертификатов и последний контакт
  gateway revoke -name ИМЯ      отозвать шлюз: сертификат перестаёт приниматься сразу
  user unlock -login ЛОГИН       снять блокировку учётной записи консоли (AISEC_DATABASE_URL)
  user reset-password -login ЛОГИН
                                выдать временный пароль; сессии завершаются, токены API отзываются
  user reset-mfa -login ЛОГИН    сбросить второй фактор; сессии завершаются
  verify [-manifest ФАЙЛ] [-accept-rollback [-gateway ИМЯ]]
                                проверить целостность установки по подписанному манифесту без сервера;
                                с AISEC_DATABASE_URL итог пишется в журнал; 3 — целостность нарушена;
                                -accept-rollback — принять намеренный откат на старый выпуск (сервера или шлюза)
  verify -release КАТАЛОГ [-allow-older]
                                проверить новый выпуск до обновления (ОБН.1): подпись — ключом этой версии,
                                все файлы каталога; себя не сверяет, в журнал не пишет; выпуск старше
                                установленного — только с -allow-older; 3 — выпуск не прошёл
  backup create -keys КАТАЛОГ -out ФАЙЛ (-user-hmac-key ФАЙЛ | -no-user-hmac-key) [-passphrase-file ФАЙЛ]
                                резервная копия конфигурации в зашифрованный файл (AISEC_DATABASE_URL)
  backup restore -keys КАТАЛОГ -in ФАЙЛ [-user-hmac-key-out ФАЙЛ] [-passphrase-file ФАЙЛ] [-allow-nonempty]
               [-keep-api-tokens] [-accept-old-copy]
                                восстановить конфигурацию в новую установку после init; 3 — копия недействительна;
                                токены API восстанавливаются отозванными; копия старше 7 суток — с -accept-old-copy
  restore-finish [-copy-dir ИМЯ]
                                после восстановления полной копии (restore.sh): завершить все сессии консоли,
                                отозвать все токены API, погасить токены регистрации шлюзов и первичной настройки,
                                записать system.restored; копия старше 7 суток — предупреждение
  keys status                   версии ключа данных и число строк под каждой (AISEC_DATABASE_URL)
  keys rotate-data -dir КАТАЛОГ [-resume] [-batch 500] [-settle 2m]
                                новая версия ключа данных, перешифрование TOTP, учётных данных провайдеров
                                и содержимого событий, удаление прежней версии; прерванное — продолжить -resume
  keys rotate-master -dir КАТАЛОГ
                                новый мастер-ключ: перешифровать ключи данных, прежний файл сохраняется
                                как master.key.<время>.retired; прерванное — повторить ту же команду
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
	case "migrate":
		if err := migrate(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli migrate: %v\n", err)
			return 1
		}
		return 0
	case "init":
		if err := initCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr, now); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli init: %v\n", err)
			return 1
		}
		return 0
	case "audit":
		if err := auditCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli audit: %v\n", err)
			if errors.Is(err, errChainBroken) || errors.Is(err, audit.ErrArchiveInvalid) {
				return 3
			}
			return 1
		}
		return 0
	case "gateway":
		if err := gatewayCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli gateway: %v\n", err)
			return 1
		}
		return 0
	case "user":
		if err := userCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli user: %v\n", err)
			return 1
		}
		return 0
	case "verify":
		if err := verifyCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli verify: %v\n", err)
			if errors.Is(err, errIntegrityViolated) || errors.Is(err, errReleaseRejected) {
				return 3
			}
			return 1
		}
		return 0
	case "backup":
		if err := backupCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr, now); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli backup: %v\n", err)
			if errors.Is(err, errBackupInvalid) {
				return 3
			}
			return 1
		}
		return 0
	case "restore-finish":
		if err := restoreFinish(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr, now); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli restore-finish: %v\n", err)
			return 1
		}
		return 0
	case "keys":
		if err := keysCmd(args[1:], os.Getenv("AISEC_DATABASE_URL"), stdout, stderr, now); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			say(stderr, "aisec-cli keys: %v\n", err)
			if errors.Is(err, errChainBroken) {
				return 3
			}
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
	expires := fs.String("expires", "", "срок действия ключа, ГГГГ-ММ-ДД (рекомендуется): ключ действует до 00:00 UTC этой даты (03:00 МСК), сама дата в срок не входит")
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

// migrate применяет встроенные миграции. Строка подключения содержит пароль,
// поэтому приходит только из окружения, а не из аргументов командной строки.
func migrate(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if dsn == "" {
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return err
	}
	defer db.Close()
	done, err := (&store.Migrator{Exec: db, Hasher: h, Migrations: ms}).Up(ctx)
	if err != nil {
		return err
	}
	say(stdout, "применено миграций: %d\n", len(done))
	return nil
}
