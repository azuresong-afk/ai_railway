package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// userCmd — аварийные действия с учётной записью консоли (В7 ревью 2.r2):
// unlock — снять блокировку, reset-password — временный пароль,
// reset-mfa — сбросить второй фактор. Нужны, когда в консоли это сделать
// некому: единственный администратор безопасности заблокирован или
// потерял фактор. Выполняются локально с доступом к БД; запись аудита —
// от пользователя ОС с логином СУБД.
func userCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается подкоманда: unlock, reset-password, reset-mfa")
	}
	sub := args[0]
	switch sub {
	case "unlock", "reset-password", "reset-mfa":
	default:
		return fmt.Errorf("неизвестная подкоманда %q: ожидается unlock, reset-password, reset-mfa", sub)
	}
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	login := fs.String("login", "", "логин учётной записи (обязательный)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *login == "" {
		return errors.New("задайте -login")
	}
	ctx := context.Background()
	svc, closeDB, err := openAuth(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	by := cliActor()
	switch sub {
	case "unlock":
		err = svc.LocalUnlock(ctx, by, *login)
	case "reset-password":
		var temp string
		if temp, err = svc.LocalResetPassword(ctx, by, *login); err == nil {
			say(stdout, "Временный пароль %s (показывается один раз; после входа его нужно сменить):\n\n  %s\n\n"+
				"Блокировка снята, сессии завершены, токены API отозваны.\n", *login, temp)
			return nil
		}
	case "reset-mfa":
		err = svc.LocalResetMFA(ctx, by, *login)
	}
	switch {
	case errors.Is(err, auth.ErrNotFound):
		return fmt.Errorf("учётной записи %s нет", *login)
	case errors.Is(err, auth.ErrDeactivated):
		return fmt.Errorf("учётная запись %s деактивирована: активируйте её в консоли", *login)
	case errors.Is(err, auth.ErrMFANotEnabled):
		return fmt.Errorf("у %s нет второго фактора", *login)
	case err != nil:
		var ie *auth.InputError
		if errors.As(err, &ie) {
			return errors.New(ie.Reason)
		}
		return err
	}
	switch sub {
	case "unlock":
		say(stdout, "Блокировка %s снята.\n", *login)
	case "reset-mfa":
		say(stdout, "Второй фактор %s сброшен, сессии завершены. При следующем входе фактор подключается заново.\n", *login)
	}
	return nil
}

// openAuth — сервис входа для аварийных действий: без ключа данных
// (секреты фактора не расшифровываются) и без своих ролей и токенов.
func openAuth(ctx context.Context, dsn string) (*auth.Service, func(), error) {
	if dsn == "" {
		return nil, nil, errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, nil, err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return nil, nil, err
	}
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return nil, nil, err
	}
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	users, err := auth.NewPGStore(db.Pool(), l)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	svc, err := auth.NewService(ctx, users, l, p)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return svc, db.Close, nil
}
