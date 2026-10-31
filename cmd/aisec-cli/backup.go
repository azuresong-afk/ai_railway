package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/backup"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// backupDBTimeout — предел снятия копии и восстановления целиком.
	backupDBTimeout = 10 * time.Minute
	// maxPassphraseFile — предел файла с парольной фразой.
	maxPassphraseFile = 4 << 10
	// restoreLockID — рекомендательная блокировка: два восстановления не
	// идут одновременно.
	restoreLockID = 0x424B5550 // "BKUP"
)

// errBackupInvalid — файл копии не прошёл проверку (код возврата 3).
var errBackupInvalid = errors.New("копия недействительна")

// backupCmd — aisec-cli backup create | restore: резервная копия
// конфигурации (РВ.1, ADR-0017).
func backupCmd(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("ожидается подкоманда: create, restore")
	}
	switch args[0] {
	case "create":
		return backupCreate(args[1:], dsn, stdout, stderr, now)
	case "restore":
		return backupRestore(args[1:], dsn, stdout, stderr, now)
	}
	return fmt.Errorf("неизвестная подкоманда %q: ожидается create, restore", args[0])
}

// backupCreate — снимок конфигурации в зашифрованный файл.
func backupCreate(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	fset := flag.NewFlagSet("backup create", flag.ContinueOnError)
	fset.SetOutput(stderr)
	keysDir := fset.String("keys", "", "каталог ключей установки (master.key): им расшифровываются секреты (обязательно)")
	out := fset.String("out", "", "файл копии: создаётся с правами 0600, существующий не перезаписывается (обязательно)")
	phraseFile := fset.String("passphrase-file", "", "файл с парольной фразой, права 0400; без него фраза вводится с терминала дважды; "+
		backup.PassphraseHint)
	hmacKey := fset.String("user-hmac-key", "", "ключ псевдонимов пользователей шлюза (права 0600 или 0400) — входит в копию")
	noHMAC := fset.Bool("no-user-hmac-key", false, "не включать ключ псевдонимов (после восстановления псевдонимы не совпадут со старыми событиями)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d (парольная фраза в аргументах не принимается)", fset.NArg())
	}
	switch {
	case *keysDir == "" || *out == "":
		return errors.New("укажите -keys и -out")
	case (*hmacKey == "") == !*noHMAC:
		return errors.New("укажите -user-hmac-key ФАЙЛ или явно -no-user-hmac-key (ТЗ, РВ.1: без ключа псевдонимы после восстановления не совпадут)")
	case dsn == "":
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	var userKey []byte
	if *hmacKey != "" {
		var err error
		if userKey, err = aisecCrypto.ReadKeyFile(*hmacKey); err != nil {
			return fmt.Errorf("ключ псевдонимов: %w", err)
		}
		defer clear(userKey)
		if len(userKey) < aisecCrypto.MinMACKeySize {
			return fmt.Errorf("ключ псевдонимов короче %d байт", aisecCrypto.MinMACKeySize)
		}
	}
	phrase, err := readPassphrase(*phraseFile, true, stderr)
	if err != nil {
		return err
	}
	defer clear(phrase)

	ctx, cancel := context.WithTimeout(context.Background(), backupDBTimeout)
	defer cancel()
	p, db, l, err := openBackupDB(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	actor := cliActor()
	fail := func(err error) error {
		recordQuietly(ctx, l, audit.Entry{OrgID: audit.DefaultOrgID, Actor: actor, Action: "backup.create",
			Object: audit.Object{Type: "backup_file", ID: filepath.Base(*out)}, Result: audit.ResultFailure,
			Details: map[string]any{"reason": shortReason(err)}})
		return err
	}
	box, err := keyring.Load(ctx, db.Pool(), p, *keysDir, audit.DefaultOrgID)
	if err != nil {
		return fail(err)
	}
	// Фраза не совпадает с именем пользователя ОС и названием организации (Н41).
	var orgName string
	if err := db.Pool().QueryRow(ctx, "SELECT name FROM organizations WHERE id = $1", audit.DefaultOrgID).Scan(&orgName); err != nil {
		return fail(err)
	}
	if err := backup.CheckNewPassphrase(phrase, actor.Name, orgName); err != nil {
		return err
	}
	w, err := backup.NewWriter(ctx, p, phrase, now)
	if err != nil {
		return fail(err)
	}
	clear(phrase)
	snap, err := readSnapshot(ctx, db, box, w)
	if err != nil {
		return fail(err)
	}
	if userKey != nil {
		if err := snap.SetUserHMACKey(w.Keys(), userKey); err != nil {
			return fail(err)
		}
		clear(userKey)
	}
	data, err := w.Seal(snap)
	if err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(*out, data); err != nil {
		return fail(err)
	}
	h, err := p.Hasher()
	if err != nil {
		return fail(err)
	}
	details := snap.Counts()
	details["format_version"] = backup.FormatVersion
	details["schema_version"] = snap.SchemaVersion
	details["file_hash"] = hex.EncodeToString(h.Sum(data))
	details["hash_alg"] = h.Name()
	if err := l.Record(ctx, audit.Entry{OrgID: audit.DefaultOrgID, Actor: actor, Action: "backup.create",
		Object: audit.Object{Type: "backup_file", ID: filepath.Base(*out)}, Result: audit.ResultSuccess, Details: details}); err != nil {
		// Файл готов, но без записи аудита копия не считается сделанной (РСБ.2).
		removeQuietly(*out)
		return fmt.Errorf("запись аудита: %w — файл копии удалён", err)
	}
	say(stdout, "Резервная копия конфигурации записана в %s (0600, %s %s).\n", *out, h.Name(), details["file_hash"])
	sayCounts(stdout, details)
	say(stdout, "Храните файл и парольную фразу раздельно: без фразы копию не восстановить, по фразе её не открыть без файла.\n")
	if userKey == nil {
		say(stdout, "Ключ псевдонимов пользователей в копию не включён (-no-user-hmac-key).\n")
	}
	return nil
}

// readSnapshot снимает копию одной транзакцией REPEATABLE READ только для
// чтения: все таблицы — из одного снимка БД.
func readSnapshot(ctx context.Context, db *store.DB, box *keyring.Box, w *backup.Writer) (*backup.Snapshot, error) {
	tx, err := db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer rollbackQuietly(ctx, tx)
	snap, err := backup.Read(ctx, tx, box, w.Keys(), audit.DefaultOrgID)
	if err != nil {
		return nil, err
	}
	return snap, tx.Commit(ctx)
}

// maxCopyAge — копия старше восстанавливается только с -accept-old-copy:
// всё, что отозвали, деактивировали и сменили после её даты, вернётся
// (В21 ревью 2.r4).
const maxCopyAge = 7 * 24 * time.Hour

// backupRestore — восстановление копии в установку после init (H-Р3).
func backupRestore(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	fset := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	fset.SetOutput(stderr)
	keysDir := fset.String("keys", "", "каталог ключей новой установки (master.key): секреты шифруются её ключом данных (обязательно)")
	in := fset.String("in", "", "файл копии (обязательно)")
	phraseFile := fset.String("passphrase-file", "", "файл с парольной фразой, права 0400; без него фраза вводится с терминала")
	hmacOut := fset.String("user-hmac-key-out", "", "куда записать ключ псевдонимов из копии (новый файл, права 0600); обязателен, если ключ в копии есть")
	allowNonEmpty := fset.Bool("allow-nonempty", false, "восстанавливать в установку, где уже есть пользователи, приложения или политики (объекты копии добавляются, совпадения — отказ; настройки установки не меняются)")
	keepTokens := fset.Bool("keep-api-tokens", false, "восстановить токены API как в копии; по умолчанию действующие токены восстанавливаются отозванными и выпускаются заново")
	acceptOld := fset.Bool("accept-old-copy", false, "восстановить копию старше 7 суток")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d (парольная фраза в аргументах не принимается)", fset.NArg())
	}
	if *keysDir == "" || *in == "" {
		return errors.New("укажите -keys и -in")
	}
	if dsn == "" {
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	data, err := readBackupFile(*in)
	if err != nil {
		return err
	}
	phrase, err := readPassphrase(*phraseFile, false, stderr)
	if err != nil {
		return err
	}
	defer clear(phrase)

	ctx, cancel := context.WithTimeout(context.Background(), backupDBTimeout)
	defer cancel()
	p, db, l, err := openBackupDB(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	actor := cliActor()
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	fileHash := hex.EncodeToString(h.Sum(data))
	entry := func(res audit.Result, details map[string]any) audit.Entry {
		details["file_hash"] = fileHash
		details["hash_alg"] = h.Name()
		return audit.Entry{OrgID: audit.DefaultOrgID, Actor: actor, Action: "backup.restore",
			Object: audit.Object{Type: "backup_file", ID: filepath.Base(*in)}, Result: res, Details: details}
	}
	fail := func(res audit.Result, reason string, err error) error {
		recordQuietly(ctx, l, entry(res, map[string]any{"stage": "refused", "reason": reason + ": " + shortReason(err)}))
		return err
	}

	arch, err := backup.Open(ctx, p, phrase, data)
	clear(phrase)
	if err != nil {
		if errors.Is(err, backup.ErrDecrypt) || errors.Is(err, backup.ErrFormat) || errors.Is(err, backup.ErrVersion) {
			return fail(audit.ResultFailure, "invalid", fmt.Errorf("%w: %w", errBackupInvalid, err))
		}
		return fail(audit.ResultFailure, "error", err)
	}
	snap := arch.Snapshot
	age := now.Sub(arch.CreatedAt)
	ageHours := int64(max(age, 0) / time.Hour)
	st, err := backup.Inspect(ctx, db.Pool(), audit.DefaultOrgID)
	switch {
	case age > maxCopyAge && !*acceptOld:
		return fail(audit.ResultDenied, "old_copy", fmt.Errorf("копия от %s старше 7 суток (%d ч): всё, что отозвали, деактивировали "+
			"и сменили после неё, вернётся в силу; восстановить всё равно — флаг -accept-old-copy",
			arch.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), ageHours))
	case snap.OrgID != audit.DefaultOrgID:
		return fail(audit.ResultFailure, "invalid", fmt.Errorf("%w: копия организации %s, установка — %s", errBackupInvalid,
			snap.OrgID, audit.DefaultOrgID))
	case err != nil:
		return fail(audit.ResultFailure, "error", err)
	case !st.DataKey:
		return fail(audit.ResultFailure, "not_initialized", errors.New("в установке нет ключа данных: сначала aisec-cli migrate и aisec-cli init"))
	case st.SchemaVersion < snap.SchemaVersion:
		return fail(audit.ResultFailure, "schema", fmt.Errorf("схема БД старше копии (%d < %d): выполните aisec-cli migrate этим выпуском",
			st.SchemaVersion, snap.SchemaVersion))
	case !st.Empty() && !*allowNonEmpty:
		return fail(audit.ResultDenied, "not_empty", fmt.Errorf("установка не пустая (%s): восстановление выполняется в новую установку после init; "+
			"добавить объекты копии к существующим — флаг -allow-nonempty", describeObjects(st.Objects)))
	case snap.UserHMACKey != nil && *hmacOut == "":
		return fail(audit.ResultFailure, "hmac_out", errors.New("в копии есть ключ псевдонимов пользователей: задайте -user-hmac-key-out ФАЙЛ"))
	case snap.UserHMACKey == nil && *hmacOut != "":
		return fail(audit.ResultFailure, "hmac_out", errors.New("в копии нет ключа псевдонимов пользователей: уберите -user-hmac-key-out"))
	}
	box, err := keyring.Load(ctx, db.Pool(), p, *keysDir, audit.DefaultOrgID)
	if err != nil {
		return fail(audit.ResultFailure, "keys", err)
	}
	prepared, err := backup.Prepare(ctx, arch, box)
	if err != nil {
		return fail(audit.ResultFailure, "invalid", fmt.Errorf("%w: %w", errBackupInvalid, err))
	}
	// Объекты — правилами сервиса этого выпуска, до записи «до» (В22);
	// настройки — только для пустой установки (5Н1 ревью 5.r1).
	settingsChecked := st.Empty()
	if err := checkSnapshot(p, arch, *keepTokens, settingsChecked); err != nil {
		return fail(audit.ResultFailure, "invalid", fmt.Errorf("%w: %w", errBackupInvalid, err))
	}
	details := snap.Counts()
	details["stage"] = "started"
	details["allow_nonempty"] = *allowNonEmpty
	details["copy_created_at"] = arch.CreatedAt.UTC().Format(time.RFC3339)
	details["copy_age_hours"] = ageHours
	details["keep_api_tokens"] = *keepTokens
	details["accept_old_copy"] = *acceptOld
	details["schema_version"] = snap.SchemaVersion
	details["format_version"] = arch.Version
	if err := l.Record(ctx, entry(audit.ResultSuccess, details)); err != nil {
		return fmt.Errorf("запись аудита перед восстановлением: %w — восстановление не начато", err)
	}
	if *hmacOut != "" {
		if err := writeUserHMACKey(arch, *hmacOut); err != nil {
			return fail(audit.ResultFailure, "hmac_out", err)
		}
	}
	verifyDB, err := serviceDBVerifier(p)
	if err != nil {
		return fail(audit.ResultFailure, "error", err)
	}
	opts := restoreOptions{allowNonEmpty: *allowNonEmpty, keepTokens: *keepTokens, now: now, ageHours: ageHours, verifyServiceDB: verifyDB,
		settingsChecked: settingsChecked}
	res, err := restoreTx(ctx, db, l, prepared, snap, opts, entry)
	if err != nil {
		var unknown *commitUnknownError
		if errors.As(err, &unknown) {
			return fmt.Errorf("%w — исход неизвестен: проверьте в журнале аудита запись backup.restore со stage=done "+
				"(файл ключа псевдонимов, если задан, сохранён)", err)
		}
		if *hmacOut != "" {
			removeQuietly(*hmacOut)
		}
		var ce *backup.ConflictError
		if errors.As(err, &ce) {
			return fail(audit.ResultDenied, "conflict", err)
		}
		if errors.Is(err, errNotEmpty) {
			return fail(audit.ResultDenied, "not_empty", err)
		}
		if errors.Is(err, errServerRunning) {
			return fail(audit.ResultDenied, "server_running", err)
		}
		return fail(audit.ResultFailure, "error", err)
	}
	say(stdout, "Конфигурация восстановлена из %s (копия от %s).\n", *in, arch.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
	sayCounts(stdout, snap.Counts())
	if *hmacOut != "" {
		say(stdout, "Ключ псевдонимов пользователей записан в %s (0600): передайте его шлюзам (-user-hmac-key).\n", *hmacOut)
	}
	if res.APITokensRevoked > 0 {
		say(stdout, "Токены API (%d) восстановлены отозванными: владельцы выпускают их заново.\n", res.APITokensRevoked)
	}
	if res.AgentKeysRevoked > 0 {
		say(stdout, "Ключи приложений, закреплённые за агентами (%d), восстановлены отозванными: их агентов в копии нет "+
			"(копия версии 1 или агент пропущен). Создайте агентов заново и выпустите им ключи.\n", res.AgentKeysRevoked)
	}
	if res.AgentKeysUnknown {
		say(stdout, "Внимание: копия снята выпуском, не отмечавшим привязку ключей к агентам. Ключ, закреплённый за агентом, "+
			"восстановлен без привязки и может назваться любым агентом приложения: отзовите ключи агентов и выпустите заново.\n")
	}
	if res.LegacyFormat {
		say(stdout, "Копия формата версии 1: настроек этапов 3 и 4 (оповещения, каналы, отчёты, бюджеты, инструкции, сертификат шлюза, "+
			"OIDC и LDAP, агенты и MCP-серверы, теневой ИИ, лицензия, отметки соответствия) в ней нет — задайте их заново.\n")
	}
	if res.SettingsSkipped {
		say(stdout, "Установка не пустая: настройки этапов 3 и 4 из копии (встроенные правила оповещений, инструкции, сертификат шлюза, "+
			"OIDC и LDAP, исключения теневого ИИ, лицензия, отметки соответствия, режим квот и сроки хранения) не перенесены.\n")
	}
	if len(res.Skipped) > 0 {
		say(stdout, "Пропущены объекты со ссылкой на объект, которого нет в копии (%d):\n", len(res.Skipped))
		for _, line := range res.Skipped {
			say(stdout, "  - %s\n", line)
		}
	}
	if len(res.ServiceDBs) > 0 {
		say(stdout, "Служебные базы:\n")
		for _, line := range res.ServiceDBs {
			say(stdout, "  - %s\n", line)
		}
	}
	say(stdout, "Дальше: зарегистрируйте шлюзы заново (aisec-cli gateway token): ключи шлюзов и УЦ не восстанавливаются. "+
		"Пользователи входят заново со своими паролями и вторым фактором.\n")
	say(stdout, "Обязательно: копия возвращает состояние на %s. По архиву журнала аудита за время после неё "+
		"(aisec-cli audit export -out ФАЙЛ -from %s) повторите отзывы ключей приложений, деактивации, блокировки и сбросы паролей.\n",
		arch.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), arch.CreatedAt.UTC().Format(time.DateOnly))
	return nil
}

// restoreOptions — флаги восстановления для restoreTx.
type restoreOptions struct {
	allowNonEmpty bool
	keepTokens    bool
	now           time.Time
	ageHours      int64
	// verifyServiceDB — проверка файлов служебных баз (serviceDBVerifier).
	verifyServiceDB func(kind string, file []byte) (backup.ServiceDBMeta, error)
	// settingsChecked — настройки копии проверены (checkSnapshot для пустой
	// установки): только тогда их можно записать.
	settingsChecked bool
}

// liveSessionWindow — сессия с активностью в этом окне означает, что
// сервер работает и в консоли есть пользователи.
const liveSessionWindow = 5 * time.Minute

// errServerRunning — в установке есть недавно активные сессии.
var errServerRunning = errors.New("похоже, сервер работает: есть сессии консоли с недавней активностью; остановите сервер (ADR-0017) и повторите")

// errNotEmpty — установка стала непустой между проверкой и восстановлением.
var errNotEmpty = errors.New("установка не пустая: восстановление выполняется в новую установку после init (или с -allow-nonempty)")

// commitUnknownError — ошибка фиксации: транзакция могла и пройти.
type commitUnknownError struct{ err error }

func (e *commitUnknownError) Error() string {
	return "фиксация восстановления: " + e.err.Error()
}
func (e *commitUnknownError) Unwrap() error { return e.err }

// restoreTx записывает копию одной транзакцией: проверка пустоты и
// совпадений под блокировкой, вставка, запись аудита «после» — вместе.
func restoreTx(ctx context.Context, db *store.DB, l *audit.Log, prepared *backup.Prepared, snap *backup.Snapshot,
	opts restoreOptions, entry func(audit.Result, map[string]any) audit.Entry) (backup.RestoreResult, error) {
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		return backup.RestoreResult{}, err
	}
	defer rollbackQuietly(ctx, tx)
	// Блокировка первичной настройки — после своей, в одном порядке: иначе
	// работающий сервер по токену init создал бы второго администратора
	// между проверкой пустоты и вставкой (Н40 ревью 2.r4).
	for _, key := range []int64{restoreLockID, setupLockKey} {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", key); err != nil {
			return backup.RestoreResult{}, err
		}
	}
	// Сессия, активная за последние минуты, — признак работающего сервера:
	// восстановление идёт при остановленном (ADR-0017).
	var live int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL
		AND last_seen_at > now() - make_interval(mins => $1)`, int(liveSessionWindow/time.Minute)).Scan(&live); err != nil {
		return backup.RestoreResult{}, err
	}
	if live > 0 {
		return backup.RestoreResult{}, fmt.Errorf("%w (активных сессий за %d мин: %d)", errServerRunning, int(liveSessionWindow/time.Minute), live)
	}
	st, err := backup.Inspect(ctx, tx, audit.DefaultOrgID)
	if err != nil {
		return backup.RestoreResult{}, err
	}
	if !st.Empty() && !opts.allowNonEmpty {
		return backup.RestoreResult{}, errNotEmpty
	}
	if err := backup.Conflicts(ctx, tx, snap); err != nil {
		return backup.RestoreResult{}, err
	}
	// Настройки и название организации переносятся только в пустую
	// установку; их новые значения — в записи аудита.
	replaceSettings := st.Empty()
	if replaceSettings && !opts.settingsChecked {
		return backup.RestoreResult{}, errors.New("установка стала пустой после проверки копии: настройки копии не проверены — повторите восстановление")
	}
	res, err := backup.Restore(ctx, tx, prepared, backup.RestoreOptions{ReplaceSettings: replaceSettings,
		KeepAPITokens: opts.keepTokens, Now: opts.now, VerifyServiceDB: opts.verifyServiceDB, BuiltinAlertRule: builtinAlertRule})
	if err != nil {
		return backup.RestoreResult{}, err
	}
	details := snap.Counts()
	details["stage"] = "done"
	details["settings_restored"] = replaceSettings
	details["copy_age_hours"] = opts.ageHours
	details["api_tokens_revoked"] = res.APITokensRevoked
	details["agent_keys_revoked"] = res.AgentKeysRevoked
	details["agent_keys_unknown"] = res.AgentKeysUnknown
	details["format_version"] = prepared.Version()
	details["skipped_objects"] = len(res.Skipped)
	if len(res.Skipped) > 0 {
		items := make([]any, 0, min(len(res.Skipped), maxInvalidListed))
		for _, line := range res.Skipped[:min(len(res.Skipped), maxInvalidListed)] {
			items = append(items, line)
		}
		details["skipped"] = items
	}
	if len(res.ServiceDBs) > 0 {
		items := make([]any, 0, len(res.ServiceDBs))
		for _, line := range res.ServiceDBs {
			items = append(items, line)
		}
		details["service_dbs_report"] = items
	}
	if replaceSettings {
		details["settings"] = snap.SettingsDetails()
	}
	if err := l.RecordTx(ctx, tx, entry(audit.ResultSuccess, details)); err != nil {
		return backup.RestoreResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return backup.RestoreResult{}, err
		}
		return backup.RestoreResult{}, &commitUnknownError{err: err}
	}
	return res, nil
}

// writeUserHMACKey пишет ключ псевдонимов из копии в новый файл 0600.
func writeUserHMACKey(arch *backup.Archive, path string) error {
	key, err := arch.UserHMACKey()
	if err != nil {
		return err
	}
	defer clear(key)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer closeQuietly(root)
	name := filepath.Base(path)
	if err := writeNewFile(root, name, key, 0o600); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			_ = root.Remove(name) //nolint:gosec // G104: ошибку удаления скрывает исходная
		}
		return fmt.Errorf("ключ псевдонимов %s: %w", path, err)
	}
	if err := syncDir(root); err != nil {
		_ = root.Remove(name) //nolint:gosec // G104: ошибку удаления скрывает исходная
		return err
	}
	return nil
}

func openBackupDB(ctx context.Context, dsn string) (aisecCrypto.Provider, *store.DB, *audit.Log, error) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return nil, nil, nil, err
	}
	db, err := store.Open(ctx, dsn, 3)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		db.Close()
		return nil, nil, nil, err
	}
	return p, db, l, nil
}

// recordQuietly пишет запись об отказе (РСБ.2). Если журнал недоступен,
// команда всё равно завершается исходной ошибкой: она важнее.
func recordQuietly(ctx context.Context, l *audit.Log, e audit.Entry) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_ = l.Record(rctx, e) //nolint:gosec // G104: исходная ошибка команды важнее ошибки записи об отказе
}

// shortReason — причина отказа для журнала аудита: первая строка, не
// длиннее 300 байт (секретов в ошибках нет; подробности маскирует audit).
func shortReason(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func rollbackQuietly(ctx context.Context, tx pgx.Tx) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
}

func describeObjects(m map[string]int) string {
	var parts []string
	for _, k := range []string{"users", "roles", "api_tokens", "providers", "applications", "policies", "notify_channels",
		"alert_rules", "report_schedules", "model_prices", "incident_instructions", "gateway_tls", "oidc", "ldap", "mcp_servers",
		"agents", "shadow_ai_exclusions", "licenses", "compliance_marks"} {
		if m[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", k, m[k]))
		}
	}
	return strings.Join(parts, ", ")
}

func sayCounts(w io.Writer, c map[string]any) {
	say(w, "  пользователей %v, своих ролей %v, токенов API %v, провайдеров %v, приложений %v (ключей %v), политик %v (версий %v)\n",
		c["users"], c["roles"], c["api_tokens"], c["providers"], c["applications"], c["app_keys"], c["policies"], c["policy_versions"])
	say(w, "  каналов %v, правил оповещений %v (+ встроенных %v), расписаний отчётов %v, цен моделей %v, бюджетов %v, "+
		"инструкций %v, MCP-серверов %v, агентов %v, инструментов %v, эталонов промптов %v, доступов по группам %v, "+
		"исключений теневого ИИ %v, лицензий %v, отметок соответствия %v; сертификат шлюза %s, OIDC %s, LDAP %s\n",
		c["notify_channels"], c["alert_rules"], c["alert_rules_builtin"], c["report_schedules"], c["model_prices"], c["app_budgets"],
		c["incident_instructions"], c["mcp_servers"], c["agents"], c["agent_tools"], c["prompt_baselines"], c["app_user_access"],
		c["shadow_ai_exclusions"], c["licenses"], c["compliance_marks"], yesNo(c["gateway_tls"]), yesNo(c["oidc"]), yesNo(c["ldap"]))
}

func yesNo(v any) string {
	if b, _ := v.(bool); b {
		return "есть"
	}
	return "нет"
}

// writeFileAtomic пишет файл копии: временный файл 0600 в том же каталоге,
// сброс на диск, затем жёсткая ссылка на итоговое имя — существующий файл
// не перезаписывается, а недописанный файл под итоговым именем не появляется.
func writeFileAtomic(path string, data []byte) (err error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer closeQuietly(root)
	name := filepath.Base(path)
	if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: файл уже существует или недоступен — копия не перезаписывается", path)
	}
	tmp := "." + name + ".tmp"
	if err := writeNewFile(root, tmp, data, 0o600); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			_ = root.Remove(tmp) //nolint:gosec // G104: ошибку удаления скрывает исходная
		}
		return fmt.Errorf("%s: %w", tmp, err)
	}
	defer func() {
		_ = root.Remove(tmp) //nolint:gosec // G104: временное имя; файл уже доступен под итоговым
	}()
	if err := root.Link(tmp, name); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return syncDir(root)
}

// readBackupFile читает файл копии: обычный файл не больше предела.
func readBackupFile(path string) (data []byte, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь файла копии задаёт администратор
	if err != nil {
		return nil, err
	}
	defer closeFileQuietly(f)
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if info.Size() > backup.MaxFileSize {
		return nil, fmt.Errorf("%w: %s больше %d байт", errBackupInvalid, path, backup.MaxFileSize)
	}
	data, err = io.ReadAll(io.LimitReader(f, backup.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > backup.MaxFileSize {
		return nil, fmt.Errorf("%w: %s больше %d байт", errBackupInvalid, path, backup.MaxFileSize)
	}
	return data, nil
}

// readPassphrase читает парольную фразу (H-Р1): из файла с правами ровно
// 0400 или с терминала без отображения; при создании копии — дважды.
// В аргументах командной строки фраза не принимается: её видно в списке
// процессов и истории оболочки.
func readPassphrase(file string, confirm bool, prompt io.Writer) ([]byte, error) {
	var phrase []byte
	var err error
	if file != "" {
		phrase, err = readPassphraseFile(file)
	} else {
		phrase, err = readPassphraseTTY(confirm, prompt)
	}
	if err != nil {
		return nil, err
	}
	if err := backup.CheckPassphrase(phrase); err != nil {
		clear(phrase)
		return nil, err
	}
	return phrase, nil
}

func readPassphraseFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь файла фразы задаёт администратор
	if err != nil {
		return nil, err
	}
	defer closeFileQuietly(f)
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if info.Mode().Perm() != 0o400 {
		return nil, fmt.Errorf("%s: права файла с парольной фразой %04o, нужно 0400", path, info.Mode().Perm())
	}
	// Один буфер без роста: io.ReadAll оставил бы в куче незатёртые копии фразы.
	data := make([]byte, maxPassphraseFile+1)
	defer clear(data)
	read, err := io.ReadFull(f, data)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if read > maxPassphraseFile {
		return nil, fmt.Errorf("%s: файл больше %d байт", path, maxPassphraseFile)
	}
	data = data[:read]
	n := len(data)
	if n > 0 && data[n-1] == '\n' {
		n--
		if n > 0 && data[n-1] == '\r' {
			n--
		}
	}
	phrase := make([]byte, n)
	copy(phrase, data)
	for _, c := range phrase {
		if c == '\n' || c == '\r' {
			clear(phrase)
			return nil, fmt.Errorf("%s: парольная фраза — одна строка", path)
		}
	}
	return phrase, nil
}

// readPassphraseTTY читает фразу с терминала (stdin) без отображения через
// golang.org/x/term (ADR-0017, п. 8): без внешних процессов и без stty в
// составе ОС. Stdin не терминал — отказ: фраза из канала легко попадает в
// историю и скрипты, для автоматизации есть -passphrase-file.
func readPassphraseTTY(confirm bool, prompt io.Writer) ([]byte, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: дескриптор stdin — 0, переполнения нет
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin — не терминал: парольная фраза вводится с терминала или из файла -passphrase-file (права 0400)")
	}
	release, err := restoreOnSignal(fd)
	if err != nil {
		return nil, err
	}
	defer release()
	say(prompt, "Парольная фраза копии (не короче %d символов): ", backup.MinPassphraseChars)
	first, err := readHidden(fd)
	say(prompt, "\n")
	if err != nil {
		return nil, err
	}
	if !confirm {
		return first, nil
	}
	say(prompt, "Повторите фразу: ")
	second, err := readHidden(fd)
	say(prompt, "\n")
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, err
	}
	if !aisecCrypto.Equal(first, second) {
		clear(first)
		return nil, errors.New("фразы не совпадают")
	}
	return first, nil
}

// readHidden читает строку с терминала без отображения; длиннее предела —
// ошибка. Буферы term.ReadPassword растут и могут оставить в куче копии
// фразы: это остаточный риск ввода с терминала (для фразы из файла его нет).
func readHidden(fd int) ([]byte, error) {
	line, err := term.ReadPassword(fd)
	if err != nil {
		clear(line)
		return nil, fmt.Errorf("ввод парольной фразы: %w", err)
	}
	if len(line) > aisecCrypto.MaxPasswordLen {
		clear(line)
		return nil, fmt.Errorf("парольная фраза длиннее %d байт", aisecCrypto.MaxPasswordLen)
	}
	return line, nil
}

// restoreOnSignal запоминает состояние терминала и возвращает его при
// SIGINT и SIGTERM во время ввода: term.ReadPassword включает отображение
// сам, но не тогда, когда процесс прерывают посреди ввода. Возвращает
// функцию, которая снимает обработчик.
func restoreOnSignal(fd int) (func(), error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("состояние терминала: %w", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			_ = term.Restore(fd, state) //nolint:gosec // G104: процесс завершается, вернуть отображение — лучшее, что можно сделать
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}, nil
}
