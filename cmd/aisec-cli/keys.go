package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// aisec-cli keys — ротация ключей установки (ADR-0018; задачи 3.2, 3.3
// этапа 3). Команды работают под логином владельца схемы и пишут записи
// аудита; ключей и секретов в выводе нет.

// defaultSettle — пауза перед удалением прежней версии ключа данных:
// работающий сервер успевает заметить новую версию (keyring.WatchInterval)
// и отказаться от остатка резерва прежней.
const defaultSettle = 2 * time.Minute

func keysCmd(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("укажите подкоманду: status, rotate-data, rotate-master")
	}
	if dsn == "" {
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	switch args[0] {
	case "status":
		return keysStatusCmd(args[1:], dsn, stdout, stderr)
	case "rotate-data":
		return keysRotateDataCmd(args[1:], dsn, stdout, stderr, now)
	case "rotate-master":
		return keysRotateMasterCmd(args[1:], dsn, stdout, stderr, now)
	}
	return fmt.Errorf("неизвестная подкоманда keys %q", args[0])
}

// keysEnv — БД, криптопрофиль установки и журнал аудита для команд keys.
type keysEnv struct {
	db  *store.DB
	p   aisecCrypto.Provider
	log *audit.Log
}

func (e *keysEnv) Close() { e.db.Close() }

// openKeysEnv подключается к БД и берёт криптопрофиль из действующего
// ключа данных: команды ротации работают в профиле установки.
func openKeysEnv(ctx context.Context, dsn string) (*keysEnv, error) {
	db, err := store.Open(ctx, dsn, 3)
	if err != nil {
		return nil, err
	}
	var profile string
	qctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	err = db.Pool().QueryRow(qctx, `SELECT profile FROM data_keys WHERE org_id = $1 AND retired_at IS NULL`, audit.DefaultOrgID).Scan(&profile)
	if errors.Is(err, pgx.ErrNoRows) {
		db.Close()
		return nil, errors.New("ключа данных нет: установка не инициализирована — выполните init -dir")
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("ключ данных: %w", err)
	}
	p, err := aisecCrypto.New(profile)
	if err == nil {
		err = aisecCrypto.SelfTest(p)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	l, err := audit.New(db.Pool(), p)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &keysEnv{db: db, p: p, log: l}, nil
}

// keysFlags — разбор флагов подкоманды; dir обязателен, если запрошен.
func keysFlags(name string, args []string, stderr io.Writer, define func(*flag.FlagSet)) error {
	fset := flag.NewFlagSet("keys "+name, flag.ContinueOnError)
	fset.SetOutput(stderr)
	define(fset)
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fset.NArg())
	}
	return nil
}

// checkKeyDir — каталог ключей существует и закрыт для группы и остальных.
func checkKeyDir(dir string) error {
	if dir == "" {
		return errors.New("укажите -dir — каталог ключей установки")
	}
	root, err := keyring.OpenKeyDir(dir)
	if err != nil {
		return err
	}
	closeQuietly(root)
	return nil
}

func keysStatusCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	if err := keysFlags("status", args, stderr, func(*flag.FlagSet) {}); err != nil {
		return err
	}
	ctx := context.Background()
	env, err := openKeysEnv(ctx, dsn)
	if err != nil {
		return err
	}
	defer env.Close()
	versions, err := keyring.Status(ctx, env.db.Pool(), audit.DefaultOrgID)
	if err != nil {
		return err
	}
	say(stdout, "Ключ данных (профиль %s):\n", env.p.Name())
	for _, v := range versions {
		state := "действующая"
		if v.RetiredAt != nil {
			state = "выведена " + v.RetiredAt.UTC().Format(time.DateTime) + " UTC"
		}
		say(stdout, "  версия %d (%s): %s; мастер-ключ №%d; шифрований %d; строк: TOTP %d, провайдеры %d, содержимое событий %d\n",
			v.Version, v.ID, state, v.MasterVersion, v.Sealed, v.Rows.MFA, v.Rows.Providers, v.Rows.Content)
	}
	return nil
}

func keysRotateDataCmd(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	var dir *string
	var resume *bool
	var batch *int
	var settle *time.Duration
	err := keysFlags("rotate-data", args, stderr, func(f *flag.FlagSet) {
		dir = f.String("dir", "", "каталог ключей установки с master.key (обязательно)")
		resume = f.Bool("resume", false, "не создавать новую версию: продолжить перешифрование и удаление прежней")
		batch = f.Int("batch", keyring.DefaultRewrapBatch, "строк в одной транзакции перешифрования (1–10000)")
		settle = f.Duration("settle", defaultSettle, "пауза перед удалением прежней версии: сервер переходит на новую (0–1h)")
	})
	if err != nil {
		return err
	}
	if *batch < 1 || *batch > 10000 {
		return errors.New("batch — от 1 до 10000")
	}
	if *settle < 0 || *settle > time.Hour {
		return errors.New("settle — от 0 до 1h")
	}
	if err := checkKeyDir(*dir); err != nil {
		return err
	}
	ctx := context.Background()
	env, err := openKeysEnv(ctx, dsn)
	if err != nil {
		return err
	}
	defer env.Close()
	return runRotateData(ctx, env, *dir, rotateDataOptions{Resume: *resume, Batch: *batch, Settle: *settle}, cliActor(), now, stdout)
}

// rotateDataOptions — параметры keys rotate-data.
type rotateDataOptions struct {
	Resume bool
	Batch  int
	Settle time.Duration
	// afterBatch — точка остановки для тестов прерывания.
	afterBatch func(keyring.RewrapCounts) error
}

// runRotateData — новая версия ключа данных, перешифрование, опора цепочки
// аудита новым ключом, пауза и удаление прежней версии (ADR-0018, п. 3).
func runRotateData(ctx context.Context, env *keysEnv, dir string, o rotateDataOptions, actor audit.Actor, now time.Time, stdout io.Writer) error {
	pool := env.db.Pool()
	if !o.Resume {
		rot, err := keyring.RotateData(ctx, pool, env.log, env.p, dir, audit.DefaultOrgID, actor, now)
		if err != nil {
			return err
		}
		say(stdout, "Создана версия %d ключа данных (%s); прежняя (%s) выведена: шифровать ею нельзя, расшифровывать можно.\n",
			rot.Version, rot.NewID, rot.OldID)
	}
	box, err := keyring.Load(ctx, pool, env.p, dir, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	rewrap := func() (keyring.RewrapCounts, error) {
		n, err := keyring.Rewrap(ctx, pool, box, keyring.RewrapOptions{Batch: o.Batch, ContentPurpose: events.ContentKeyPurpose,
			AfterBatch: o.afterBatch})
		if n.Total() > 0 {
			rerr := env.log.Record(ctx, audit.Entry{
				OrgID: audit.DefaultOrgID, Actor: actor, Action: "keys.data_rewrapped",
				Object: audit.Object{Type: "data_key", ID: box.KeyID()}, Result: audit.ResultSuccess,
				Details: map[string]any{"version": box.Version(), "mfa": n.MFA, "providers": n.Providers, "content": n.Content, "complete": err == nil},
			})
			err = errors.Join(err, rerr)
		}
		return n, err
	}
	n, err := rewrap()
	if err != nil {
		return fmt.Errorf("перешифрование прервано (%w); перешифровано строк: %d — продолжите keys rotate-data -resume", err, n.Total())
	}
	say(stdout, "Перешифровано строк: TOTP %d, учётные данные провайдеров %d, содержимое событий %d.\n", n.MFA, n.Providers, n.Content)
	// Опора цепочки аудита новым ключом (ADR-0018, п. 3.4): проверка
	// сверяет и опоры прежних версий, затем пишет опору действующей.
	l, err := openAuditLog(env.db, env.p, nil)
	if err != nil {
		return err
	}
	opts, err := audit.HeadMACOptions(box)
	if err != nil {
		return err
	}
	res, err := audit.NewVerifier(l, opts...).VerifyBy(ctx, actor)
	if err != nil {
		return fmt.Errorf("проверка цепочки аудита новым ключом: %w", err)
	}
	if !res.OK() {
		return fmt.Errorf("цепочка аудита нарушена (запись %d, %s): прежняя версия ключа данных не удаляется — разберите нарушение и повторите -resume: %w",
			res.Break.Seq, res.Break.Reason, errChainBroken)
	}
	if o.Settle > 0 {
		say(stdout, "Пауза %s: работающий сервер переходит на новую версию.\n", o.Settle)
		t := time.NewTimer(o.Settle)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if n, err = rewrap(); err != nil {
			return fmt.Errorf("перешифрование прервано (%w) — продолжите keys rotate-data -resume", err)
		}
		if n.Total() > 0 {
			say(stdout, "Дошифровано строк, записанных сервером до перехода: %d.\n", n.Total())
		}
	}
	d, err := keyring.DestroyRetired(ctx, pool, env.log, audit.DefaultOrgID, actor)
	if err != nil {
		return err
	}
	for _, id := range d.Destroyed {
		say(stdout, "Прежняя версия %s удалена.\n", id)
	}
	if len(d.Remaining) > 0 {
		for id, c := range d.Remaining {
			say(stdout, "Версия %s ещё нужна: строк TOTP %d, провайдеров %d, содержимого событий %d.\n", id, c.MFA, c.Providers, c.Content)
		}
		say(stdout, "Повторите keys rotate-data -resume, когда сервер перейдёт на новую версию (до %s).\n", keyring.WatchInterval)
	}
	say(stdout, "Перезапуск сервера не нужен: он переходит на новую версию сам.\n")
	return nil
}

func keysRotateMasterCmd(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	var dir *string
	err := keysFlags("rotate-master", args, stderr, func(f *flag.FlagSet) {
		dir = f.String("dir", "", "каталог ключей установки с master.key (обязательно)")
	})
	if err != nil {
		return err
	}
	if err := checkKeyDir(*dir); err != nil {
		return err
	}
	ctx := context.Background()
	env, err := openKeysEnv(ctx, dsn)
	if err != nil {
		return err
	}
	defer env.Close()
	r, err := keyring.RotateMaster(ctx, env.db.Pool(), env.log, env.p, *dir, audit.DefaultOrgID, cliActor(), now)
	if err != nil {
		return err
	}
	if r.StaleRemoved {
		say(stdout, "Удалён %s от несостоявшейся ротации: им ничего не зашифровано.\n", keyring.MasterKeyNextFile)
	}
	if r.Recovered {
		say(stdout, "Завершена прерванная ротация: новый мастер-ключ — %s, прежний — %s.\n", keyring.MasterKeyFile, r.Retired)
	} else {
		say(stdout, "Мастер-ключ заменён: перешифровано версий ключа данных — %d, номер мастер-ключа — %d.\n", r.DataKeys, r.MasterVersion)
	}
	say(stdout, "Прежний мастер-ключ сохранён как %s: он нужен для восстановления дампа БД, снятого до ротации.\n"+
		"Сделайте резервную копию нового %s отдельно от копии БД, затем удалите прежний файл.\n"+
		"Передайте новый файл пользователю службы (chown). Перезапуск сервера не нужен.\n", r.Retired, keyring.MasterKeyFile)
	return nil
}
