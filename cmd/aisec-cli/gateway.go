package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// gatewayCmd — реестр шлюзов (ИАФ.10, задача 2.14): token — одноразовый
// токен регистрации, list — шлюзы и последний контакт, revoke — отзыв.
// Выполняется под логином владельца схемы: у роли сервера нет прав
// создавать шлюзы и отзывать их (миграция 0007_gateways).
func gatewayCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается подкоманда: token, list, revoke")
	}
	switch args[0] {
	case "token":
		return gatewayToken(args[1:], dsn, stdout, stderr)
	case "list":
		return gatewayList(args[1:], dsn, stdout, stderr)
	case "revoke":
		return gatewayRevoke(args[1:], dsn, stdout, stderr)
	}
	return fmt.Errorf("неизвестная подкоманда %q: ожидается token, list, revoke", args[0])
}

// openRegistry — сервис реестра без УЦ: CLI не выпускает сертификаты.
func openRegistry(ctx context.Context, dsn string) (*gwregistry.Service, func(), error) {
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
	st, err := gwregistry.NewPGStore(db.Pool(), l)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	svc, err := gwregistry.New(gwregistry.Options{Store: st, Provider: p, Audit: l})
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return svc, db.Close, nil
}

func gatewayToken(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "имя шлюза: 1–64 символа a-z, 0-9, «.», «_», «-» (обязательный)")
	ttl := fs.Duration("ttl", gwregistry.DefaultTokenTTL, "срок токена, от 1m до 168h")
	rereg := fs.Bool("reregister", false, "новый токен для уже зарегистрированного шлюза (потерян ключ, истекает сертификат)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if !gwregistry.ValidName(*name) {
		return errors.New("name: 1–64 символа a-z, 0-9, «.», «_», «-», с буквы или цифры")
	}
	ctx := context.Background()
	svc, closeDB, err := openRegistry(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	token, gw, err := svc.IssueToken(ctx, gwregistry.TokenInput{Name: *name, TTL: *ttl, Reregister: *rereg, Actor: cliActor()})
	switch {
	case errors.Is(err, gwregistry.ErrNameTaken):
		return fmt.Errorf("шлюз %s уже есть; для повторной регистрации добавьте -reregister", *name)
	case errors.Is(err, gwregistry.ErrNotFound):
		return fmt.Errorf("шлюза %s нет; уберите -reregister", *name)
	case errors.Is(err, gwregistry.ErrRevoked):
		return fmt.Errorf("шлюз %s отозван; зарегистрируйте шлюз под новым именем", *name)
	case err != nil:
		return err
	}
	say(stdout, "Токен регистрации шлюза %s (ID %s). Показывается один раз, одноразовый, срок — %s:\n\n  %s\n\n"+
		"На хосте шлюза: AISEC_GATEWAY_REGISTRATION_TOKEN=<токен> aisec-gateway register -console https://<сервер>:8444 -console-ca <корень консоли> -out-dir <каталог 0700>\n",
		gw.Name, gw.ID, ttl.String(), token)
	return nil
}

func gatewayList(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	ctx := context.Background()
	svc, closeDB, err := openRegistry(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	list, err := svc.List(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		say(stdout, "Шлюзов нет.\n")
		return nil
	}
	say(stdout, "%-24s %-36s %-8s %-20s %-20s %s\n", "ИМЯ", "ID", "СТАТУС", "СЕРТИФИКАТ ДО", "ПОСЛЕДНИЙ КОНТАКТ", "ВЕРСИЯ")
	for _, g := range list {
		say(stdout, "%-24s %-36s %-8s %-20s %-20s %s\n", g.Name, g.ID, g.Status, fmtTime(g.CertNotAfter), fmtTime(g.LastSeenAt), dash(g.Version))
	}
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func gatewayRevoke(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "имя шлюза (обязательный)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if !gwregistry.ValidName(*name) {
		return errors.New("name: неверное имя шлюза")
	}
	ctx := context.Background()
	svc, closeDB, err := openRegistry(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	gw, err := svc.Revoke(ctx, *name, cliActor())
	switch {
	case errors.Is(err, gwregistry.ErrNotFound):
		return fmt.Errorf("шлюза %s нет", *name)
	case errors.Is(err, gwregistry.ErrRevoked):
		return fmt.Errorf("шлюз %s уже отозван", *name)
	case err != nil:
		return err
	}
	say(stdout, "Шлюз %s (ID %s) отозван: его сертификат больше не принимается, токены погашены.\n", gw.Name, gw.ID)
	return nil
}
