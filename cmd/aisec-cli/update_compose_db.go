package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// БД при обновлении установки в docker compose (задача 6.21, ADR-0036,
// раздел 7). PostgreSQL установки живёт в контейнере во внутренней сети без
// выхода на хост, а клиентов PostgreSQL на хосте может не быть, поэтому:
//   - копия и восстановление — pg_dump, pg_restore и psql внутри контейнера
//     postgres через docker compose exec (как backup.sh и restore.sh); пароль
//     владельца схемы читается из секрета внутри контейнера и в аргументы
//     хоста не попадает;
//   - список миграций, размер, заголовок восстановления и запись в журнал
//     аудита — служебная команда aisec-cli update-db в одноразовом
//     контейнере aisec-cli (строка подключения владельца схемы — как у
//     migrate).

var schemaNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// dbInfo — ответ aisec-cli update-db info.
type dbInfo struct {
	Schema  string         `json:"schema"`
	Size    int64          `json:"size"`
	Applied []dbInfoMigrat `json:"applied"`
}

type dbInfoMigrat struct {
	Version  int    `json:"version"`
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
}

// composeDB — БД установки: действия через docker compose.
type composeDB struct {
	sys *composeSys
	p   aisecCrypto.Provider
	// tag — тег образа aisec-cli ДОВЕРЕННОЙ (установленной до обновления)
	// версии: служебные операции с БД выполняет он, а не образ нового
	// выпуска, на который уже переключён .env. Иначе откат зависел бы от
	// кода выпуска, который как раз не прошёл. Пусто — как в .env (тесты).
	tag string
}

func (c *composeDB) cli(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	call := dockerCall{Args: append([]string{"compose", "run", "--rm", "--no-deps", "-T", composeCLIService, "update-db"}, args...), Stdin: stdin}
	if c.tag != "" {
		call.Env = []string{"AISEC_VERSION=" + c.tag}
	}
	return c.sys.r.Run(ctx, call)
}

func (c *composeDB) info(ctx context.Context) (*dbInfo, error) {
	out, err := c.cli(ctx, nil, "info")
	if err != nil {
		return nil, err
	}
	var in dbInfo
	if err := lenientJSON([]byte(out), &in); err != nil {
		return nil, fmt.Errorf("update-db info: неверный ответ: %w", err)
	}
	if !schemaNameRe.MatchString(in.Schema) {
		return nil, errors.New("update-db info: неожиданное имя схемы")
	}
	return &in, nil
}

func (c *composeDB) Applied(ctx context.Context) ([]store.Applied, error) {
	in, err := c.info(ctx)
	if err != nil {
		return nil, fmt.Errorf("список применённых миграций: %w", err)
	}
	out := make([]store.Applied, 0, len(in.Applied))
	for _, a := range in.Applied {
		out = append(out, store.Applied{Version: a.Version, Name: a.Name, Checksum: a.Checksum})
	}
	return out, nil
}

func (c *composeDB) Size(ctx context.Context) (int64, error) {
	in, err := c.info(ctx)
	if err != nil {
		return 0, err
	}
	return in.Size, nil
}

func (c *composeDB) Close() {}

// Audit записывает действие обновления в журнал аудита внутри контейнера.
func (c *composeDB) Audit(ctx context.Context, e audit.Entry) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	data, err := json.Marshal(updateAuditWire{Action: e.Action, Result: string(e.Result), ObjectID: e.Object.ID, Details: detailsMap(e.Details)})
	if err != nil {
		return err
	}
	_, err = c.cli(ctx, bytes.NewReader(data), "audit")
	return err
}

// dbAuthPrologue — начало сценария в контейнере postgres: файл паролей из
// секрета владельца схемы во временном файле 0600 (как в backup.sh).
const dbAuthPrologue = `set -eu; umask 077; f=$(mktemp); trap 'rm -f "$f" /tmp/aisec-update.list /tmp/aisec-update.hdr' EXIT
printf '*:*:*:aisec_owner:%s\n' "$(cat /run/secrets/db-owner-password)" >"$f"
`

const dumpScript = dbAuthPrologue + `PGPASSFILE=$f pg_dump --no-password -h 127.0.0.1 -U aisec_owner -d aisec -Fc --strict-names --schema="$1"
`

// restoreScript: заголовок (удаление и создание схемы) и сценарий pg_restore
// одним потоком в psql одной транзакцией. Сбой pg_restore добавляет
// заведомо ошибочный оператор: транзакция откатывается, а не фиксирует
// обрезанный сценарий.
const restoreScript = dbAuthPrologue + `[ -s /tmp/aisec-update.hdr ] && [ -s /tmp/aisec-update.list ] || { echo 'нет заголовка или списка восстановления' >&2; exit 1; }
{ cat /tmp/aisec-update.hdr || echo 'SELECT 1/0;'; pg_restore --use-list=/tmp/aisec-update.list --file=- || echo 'SELECT 1/0;'; } | PGPASSFILE=$f psql --no-password -h 127.0.0.1 -U aisec_owner -d aisec --no-psqlrc --quiet --single-transaction --set=ON_ERROR_STOP=1 >/dev/null
`

func (c *composeDB) exec(ctx context.Context, call dockerCall, args ...string) (string, error) {
	call.Args = append([]string{"compose", "exec", "-T", composeServiceDB}, args...)
	return c.sys.r.Run(ctx, call)
}

// Dump — pg_dump схемы установки внутри контейнера postgres; поток пишется
// во временный файл 0600, проверяется оглавлением, fsync и переименование.
func (c *composeDB) Dump(ctx context.Context, file string) error {
	in, err := c.info(ctx)
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	h, err := c.p.Hasher()
	if err != nil {
		_ = f.Close()      //nolint:gosec // G104: исходная ошибка важнее
		_ = os.Remove(tmp) //nolint:gosec // G104: копия не начата
		return err
	}
	sumH := h.New()
	_, runErr := c.exec(ctx, dockerCall{Stdout: io.MultiWriter(f, sumH), Timeout: dumpTimeout}, "sh", "-c", dumpScript, "sh", in.Schema)
	syncErr := f.Sync()
	closeErr := f.Close()
	if runErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp) //nolint:gosec // G104: недописанная копия не нужна
		return fmt.Errorf("pg_dump: %w", errors.Join(runErr, syncErr, closeErr))
	}
	if err := c.checkDump(ctx, tmp); err != nil {
		_ = os.Remove(tmp) //nolint:gosec // G104: нечитаемая копия не нужна
		return err
	}
	// Контрольная сумма копии: pg_restore не замечает обрезанных данных
	// (код возврата 0 и неполный сценарий), поэтому целость копии
	// проверяется перед восстановлением по сумме, снятой при записи.
	if err := updWriteAtomic(filepath.Dir(file), filepath.Base(file)+sumSuffix, []byte(hex.EncodeToString(sumH.Sum(nil))+"\n"), 0o600); err != nil {
		_ = os.Remove(tmp) //nolint:gosec // G104: копия без суммы не нужна
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}
	return updSyncDir(filepath.Dir(file))
}

// sumSuffix — суффикс файла контрольной суммы копии БД.
const sumSuffix = ".sha256"

// verifyDump сверяет копию с суммой, снятой при её записи.
func (c *composeDB) verifyDump(file string) error {
	want, err := readSmallFile(file+sumSuffix, 256)
	if err != nil {
		return fmt.Errorf("контрольная сумма копии БД: %w", err)
	}
	h, err := c.p.Hasher()
	if err != nil {
		return err
	}
	f, err := os.Open(file) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	sumH := h.New()
	if _, err := io.Copy(sumH, f); err != nil {
		return err
	}
	if hex.EncodeToString(sumH.Sum(nil)) != strings.TrimSpace(string(want)) {
		return errors.New("копия БД повреждена: контрольная сумма не совпадает; БД не изменена")
	}
	return nil
}

// checkDump: оглавление копии читается — архив не обрезан.
func (c *composeDB) checkDump(ctx context.Context, file string) error {
	f, err := os.Open(file) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	if _, err := c.exec(ctx, dockerCall{Stdin: f, Stdout: io.Discard, Timeout: dumpTimeout}, "pg_restore", "-l"); err != nil {
		return fmt.Errorf("копия БД не читается: %w", err)
	}
	return nil
}

// Restore восстанавливает схему из копии одной транзакцией (как
// pgUpdateDB.Restore): схема со всеми объектами, в том числе созданными
// новыми миграциями, удаляется и создаётся заново с прежними владельцем и
// правами. Сбой — откат транзакции, БД остаётся как была.
func (c *composeDB) Restore(ctx context.Context, file string) error {
	if _, err := os.Lstat(file); err != nil {
		return fmt.Errorf("копия БД %s: %w", file, err)
	}
	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()
	if err := c.verifyDump(file); err != nil {
		return err
	}
	in, err := c.info(ctx)
	if err != nil {
		return err
	}
	header, err := c.cli(ctx, nil, "header")
	if err != nil {
		return err
	}
	f, err := os.Open(file) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	list, err := c.exec(ctx, dockerCall{Stdin: f}, "pg_restore", "-l")
	_ = f.Close() //nolint:gosec // G104: файл только читался
	if err != nil {
		return err
	}
	for name, text := range map[string]string{"/tmp/aisec-update.list": filterTOC(list, in.Schema), "/tmp/aisec-update.hdr": header + "\n"} {
		if _, err := c.exec(ctx, dockerCall{Stdin: strings.NewReader(text)}, "sh", "-c", "umask 077; cat >"+name); err != nil {
			return err
		}
	}
	f, err = os.Open(file) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	if _, err := c.exec(ctx, dockerCall{Stdin: f, Timeout: dumpTimeout}, "sh", "-c", restoreScript, "sh"); err != nil {
		return fmt.Errorf("восстановление не выполнено, БД не изменена: %w", err)
	}
	return nil
}

// ---- aisec-cli update-db: служебная команда внутри контейнера ----

// updateAuditWire — запись аудита обновления на проводе хост → контейнер.
type updateAuditWire struct {
	Action   string         `json:"action"`
	Result   string         `json:"result"`
	ObjectID string         `json:"object_id"`
	Details  map[string]any `json:"details"`
}

const maxUpdateAuditWire = 16 << 10

// updateAuditActions — коды аудита, которые может записать update-db.
var updateAuditActions = map[string]bool{"update.started": true, "update.install": true, "update.rollback": true}

// updateDBCmd — aisec-cli update-db info|header|audit: действия с БД для
// обновления установки в docker compose. Запускается обновлением в
// одноразовом контейнере aisec-cli; строка подключения — владельца схемы
// (AISEC_DATABASE_URL), как у migrate.
func updateDBCmd(args []string, dsn string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "info" && args[0] != "header" && args[0] != "audit") {
		return errors.New("update-db: подкоманда info, header или audit")
	}
	if dsn == "" {
		return errors.New("update-db: задайте AISEC_DATABASE_URL")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, err := openUpdateDB(ctx, p, dsn, dsn, nil, defaultPGTools)
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "info":
		applied, err := db.Applied(ctx)
		if err != nil {
			return err
		}
		size, err := db.Size(ctx)
		if err != nil {
			return err
		}
		in := dbInfo{Schema: db.schema, Size: size, Applied: []dbInfoMigrat{}}
		for _, a := range applied {
			in.Applied = append(in.Applied, dbInfoMigrat{Version: a.Version, Name: a.Name, Checksum: a.Checksum})
		}
		return json.NewEncoder(stdout).Encode(in)
	case "header":
		h, err := db.schemaHeader(ctx)
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, h)
		return err
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxUpdateAuditWire+1))
	if err != nil {
		return err
	}
	if len(data) > maxUpdateAuditWire {
		return errors.New("update-db audit: запись больше предела")
	}
	e, err := parseUpdateAudit(data)
	if err != nil {
		return err
	}
	return db.Audit(ctx, e)
}

// parseUpdateAudit разбирает запись аудита обновления: недоверенный ввод
// (FuzzParseUpdateAudit) — только коды обновления, исходы и выпуски.
func parseUpdateAudit(data []byte) (audit.Entry, error) {
	var w updateAuditWire
	if err := strictJSON(data, &w); err != nil {
		return audit.Entry{}, fmt.Errorf("update-db audit: %w", err)
	}
	switch {
	case !updateAuditActions[w.Action]:
		return audit.Entry{}, errors.New("update-db audit: неизвестный код аудита")
	case w.Result != string(audit.ResultSuccess) && w.Result != string(audit.ResultFailure):
		return audit.Entry{}, errors.New("update-db audit: неизвестный исход")
	case w.ObjectID != "rejected" && !releaseIDRe.MatchString(w.ObjectID):
		return audit.Entry{}, errors.New("update-db audit: неверный выпуск")
	}
	return audit.Entry{OrgID: audit.DefaultOrgID, Actor: cliActor(), Action: w.Action,
		Object: audit.Object{Type: "release", ID: w.ObjectID}, Result: audit.Result(w.Result), Details: w.Details}, nil
}

// detailsMap — подробности записи аудита как карта (так их строит
// updater.entry).
func detailsMap(d any) map[string]any {
	m, _ := d.(map[string]any)
	return m
}
