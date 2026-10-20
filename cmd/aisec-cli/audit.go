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

// auditCmd — операции с журналом аудита. verify проверяет цепочку хешей по
// команде (РСБ.4, DM-43); итог пишется в журнал аудита.
func auditCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("ожидается подкоманда: verify")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args[1:]); err != nil {
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
	ctx := context.Background()
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return err
	}
	defer db.Close()
	l, err := audit.New(db.Pool(), p)
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

// cliActor — «кто» для записи о ручной проверке (РСБ.1): пользователь ОС,
// запустивший aisec-cli.
func cliActor() audit.Actor {
	a := audit.Actor{Type: audit.ActorCLI, ID: "uid:" + strconv.Itoa(os.Getuid())}
	if u, err := user.Current(); err == nil {
		a.Name = u.Username
	}
	return a
}
