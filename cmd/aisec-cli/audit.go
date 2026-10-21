package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// errChainBroken — цепочка нарушена: код возврата 3 отличает нарушение
// (DM-43) от ошибки выполнения.
var errChainBroken = errors.New("цепочка журнала аудита нарушена")

// auditCmd — операции с журналом аудита: verify — проверка цепочки по
// команде (РСБ.4, DM-43); archive, export, verify-archive — архивация,
// выгрузка и проверка архива (РСБ.4–5, ADR-0008, audit_archive.go).
func auditCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается подкоманда: verify, archive, export, verify-archive")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:], dsn, stdout, stderr)
	case "archive":
		return auditArchive(args[1:], dsn, stdout, stderr)
	case "export":
		return auditExport(args[1:], dsn, stdout, stderr)
	case "verify-archive":
		return auditVerifyArchive(args[1:], stdout, stderr)
	}
	return fmt.Errorf("неизвестная подкоманда %q: ожидается verify, archive, export, verify-archive", args[0])
}

// auditVerify проверяет цепочку; итог пишется в журнал аудита. С -keys
// подписи контрольных точек архивации проверяются открытым ключом аудита,
// без него — только их связность.
func auditVerify(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keys := fs.String("keys", "", "каталог ключей: проверять подписи контрольных точек ключом audit-signing.pub")
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
	var v aisecCrypto.Verifier
	if *keys != "" {
		if v, err = loadAuditVerifier(p, *keys); err != nil {
			return err
		}
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return err
	}
	defer db.Close()
	l, err := openAuditLog(db, p, v)
	if err != nil {
		return err
	}
	res, err := audit.NewVerifier(l).VerifyBy(ctx, cliActor())
	if err != nil {
		return err
	}
	if !res.OK() {
		say(stdout, "Цепочка нарушена: запись %d, причина %s. Проверено записей: %d.\n",
			res.Break.Seq, res.Break.Reason, res.Checked)
		return errChainBroken
	}
	say(stdout, "Цепочка цела. Проверено записей: %d, последняя — %d.\n", res.Checked, res.Head.Seq)
	return nil
}

// openAuditLog — журнал с контрольными точками архивации (v = nil — без
// проверки подписей).
func openAuditLog(db *store.DB, p aisecCrypto.Provider, v aisecCrypto.Verifier) (*audit.Log, error) {
	cps, err := audit.NewPGCheckpoints(db.Pool(), p, v)
	if err != nil {
		return nil, err
	}
	return audit.New(db.Pool(), p, audit.WithCheckpoints(cps))
}

// cliActor — «кто» для записи о ручной проверке (РСБ.1): пользователь ОС,
// запустивший aisec-cli.
func cliActor() audit.Actor {
	a := audit.Actor{Type: audit.ActorCLI, ID: "uid:" + strconv.Itoa(os.Getuid())}
	if u, err := user.Current(); err == nil {
		a.Name = u.Username
	}
	return a
}
