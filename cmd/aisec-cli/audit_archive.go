package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// maxArchiveFile — предел размера проверяемого файла архива (verify-archive).
const maxArchiveFile = 64 << 30

// auditArchive — aisec-cli audit archive (РСБ.4, ADR-0008): проверка
// цепочки, затем выгрузка записей старше срока хранения в файл с
// подписанной контрольной точкой и их удаление под ролью
// aisec_audit_archiver одной транзакцией.
func auditArchive(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit archive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keys := fs.String("keys", "", "каталог ключей с audit-signing.key и audit-signing.pub (обязательно)")
	out := fs.String("out", "", "файл архива: создаётся, права 0600, существующий не перезаписывается (обязательно)")
	before := fs.String("before", "", "архивировать только записи до этой даты, ГГГГ-ММ-ДД (UTC); граница не бывает ближе срока хранения")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *keys == "" || *out == "" {
		return errors.New("укажите -keys и -out")
	}
	var beforeT time.Time
	if *before != "" {
		t, err := time.Parse(time.DateOnly, *before)
		if err != nil {
			return errors.New("before — дата ГГГГ-ММ-ДД")
		}
		beforeT = t
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
	signer, verifier, err := loadAuditSigner(ctx, db, p, *keys)
	if err != nil {
		return err
	}
	l, err := openAuditLog(db, p, verifier)
	if err != nil {
		return err
	}
	// Нарушенную цепочку не архивируем: архив узаконил бы подмену.
	check, err := audit.NewVerifier(l).VerifyBy(ctx, cliActor())
	if err != nil {
		return err
	}
	if !check.OK() {
		say(stdout, "Цепочка нарушена: запись %d, причина %s. Архивация не выполнена.\n", check.Break.Seq, check.Break.Reason)
		return errChainBroken
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь файла архива задаёт администратор
	if err != nil {
		return fmt.Errorf("файл архива: %w", err)
	}
	// Запись каталога о новом файле — на диск до удаления записей из БД.
	if err := syncParent(*out); err != nil {
		closeFileQuietly(f)
		removeQuietly(*out)
		return fmt.Errorf("каталог архива: %w", err)
	}
	res, err := l.Archive(ctx, audit.ArchiveOptions{
		Before: beforeT, Out: f, ArchiveName: filepath.Base(*out),
		Signer: signer, Verifier: verifier, By: cliActor(),
	})
	cerr := f.Close()
	if errors.Is(err, audit.ErrNothingToArchive) {
		removeQuietly(*out)
		say(stdout, "Нет записей старше %s для архивации.\n", res.Cutoff.Format(time.DateOnly))
		return nil
	}
	if err != nil {
		return archiveFailed(ctx, db, p, *out, res, err, stdout)
	}
	if cerr != nil {
		return fmt.Errorf("архивация выполнена, но файл архива не закрыт: %w", cerr)
	}
	sayArchived(stdout, res, *out)
	return nil
}

// sayArchived выводит итог архивации: что архивировано и куда.
func sayArchived(stdout io.Writer, res *audit.ArchiveResult, out string) {
	cp := res.Checkpoint
	say(stdout, "Архивировано записей: %d (номера %d–%d, старше %s) в %s.\nКонтрольная точка: запись %d, хеш %s.\n"+
		"Перенесите архив на внешний носитель; проверка — aisec-cli audit verify-archive.\n",
		cp.Records, cp.PrevSeq+1, cp.Seq, res.Cutoff.Format(time.DateOnly), out, cp.Seq, hex.EncodeToString(cp.Hash))
}

// archiveFailed решает судьбу файла после ошибки. Точка не подписана или
// точно не записана — файл удаляется. Записана (ошибку вернул только ответ
// на COMMIT) — успех с тем же итогом, что и без ошибки (Н6 ревью 2.r1).
// Неизвестно — файл сохраняется: записи могли быть уже удалены, и архив —
// их единственная копия.
func archiveFailed(ctx context.Context, db *store.DB, p aisecCrypto.Provider, out string, res *audit.ArchiveResult, err error,
	stdout io.Writer) error {
	if res == nil || res.Checkpoint == nil {
		removeQuietly(out)
		return err
	}
	cps, cerr := audit.NewPGCheckpoints(db.Pool(), p, nil)
	if cerr != nil {
		return fmt.Errorf("%w; исход неизвестен (%w) — файл %s сохранён", err, cerr, out)
	}
	ok, cerr := cps.Exists(ctx, res.Checkpoint.ID)
	switch {
	case cerr != nil:
		return fmt.Errorf("%w; исход неизвестен (%w) — файл %s сохранён: проверьте, есть ли в audit_checkpoints точка %s",
			err, cerr, out, res.Checkpoint.ID)
	case ok:
		sayArchived(stdout, res, out)
		return nil
	}
	removeQuietly(out)
	return err
}

// auditExport — aisec-cli audit export (РСБ.5): выгрузка журнала в файл для
// переноса на внешний носитель; журнал не меняется.
func auditExport(args []string, dsn string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "файл выгрузки: создаётся, права 0600, существующий не перезаписывается (обязательно)")
	from := fs.String("from", "", "с этой даты, ГГГГ-ММ-ДД (UTC), включительно")
	to := fs.String("to", "", "до этой даты, ГГГГ-ММ-ДД (UTC), не включая её")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *out == "" {
		return errors.New("укажите -out")
	}
	var fromT, toT time.Time
	for _, d := range []struct {
		s *string
		t *time.Time
	}{{from, &fromT}, {to, &toT}} {
		if *d.s == "" {
			continue
		}
		t, err := time.Parse(time.DateOnly, *d.s)
		if err != nil {
			return errors.New("from и to — даты ГГГГ-ММ-ДД")
		}
		*d.t = t
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
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь файла выгрузки задаёт администратор
	if err != nil {
		return fmt.Errorf("файл выгрузки: %w", err)
	}
	n, err := l.Export(ctx, audit.ExportOptions{From: fromT, To: toT, Out: f, By: cliActor()})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// Выгрузка без записи в журнале не остаётся.
		removeQuietly(*out)
		return err
	}
	say(stdout, "Выгружено записей: %d в %s.\n", n, *out)
	return nil
}

// auditVerifyArchive — aisec-cli audit verify-archive: проверка файла
// архива без БД (подпись точки, цепочка, хеш тела).
func auditVerifyArchive(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit verify-archive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keys := fs.String("keys", "", "каталог ключей с audit-signing.pub и ключами смен audit-signing.<id>.pub (обязательно)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keys == "" || fs.NArg() != 1 {
		return errors.New("укажите -keys и один файл архива")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	keyset, err := loadAuditVerifiers(p, *keys)
	if err != nil {
		return err
	}
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	f, err := os.Open(fs.Arg(0)) //nolint:gosec // G304: проверяемый архив указывает администратор
	if err != nil {
		return err
	}
	defer closeFileQuietly(f)
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveFile {
		return fmt.Errorf("%s: не обычный файл или больше %d ГиБ", fs.Arg(0), maxArchiveFile>>30)
	}
	cp, err := audit.VerifyArchive(io.LimitReader(f, maxArchiveFile), h, keyset...)
	if err != nil {
		return err
	}
	say(stdout, "Архив действителен: записи %d–%d (%d), контрольная точка %s от %s, хеш последней записи %s.\n",
		cp.PrevSeq+1, cp.Seq, cp.Records, cp.ID, cp.CreatedAt.UTC().Format(time.DateTime), hex.EncodeToString(cp.Hash))
	return nil
}

// loadAuditVerifier читает открытый ключ-якорь аудита из каталога ключей.
func loadAuditVerifier(p aisecCrypto.Provider, dir string) (aisecCrypto.Verifier, error) {
	return aisecCrypto.LoadVerifierFile(p, filepath.Join(dir, auditPubFile), aisecCrypto.KeyKindAuditSigningPublic)
}

// loadAuditVerifiers — все открытые ключи аудита каталога: якорь и ключи
// смен (audit-signing.<id>.pub, ADR-0018, п. 5.3). verify-archive работает
// без БД и принимает подпись любым из них.
func loadAuditVerifiers(p aisecCrypto.Provider, dir string) ([]aisecCrypto.Verifier, error) {
	anchor, err := loadAuditVerifier(p, dir)
	if err != nil {
		return nil, err
	}
	out := []aisecCrypto.Verifier{anchor}
	names, err := filepath.Glob(filepath.Join(dir, "audit-signing.*.pub"))
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		v, err := aisecCrypto.LoadVerifierFile(p, name, aisecCrypto.KeyKindAuditSigningPublic)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// loadAuditSigner читает якорь и действующий по расписанию смен закрытый
// ключ аудита (audit-signing.key или ключ последней смены) и проверяет пару.
func loadAuditSigner(ctx context.Context, db *store.DB, p aisecCrypto.Provider, dir string) (aisecCrypto.Signer, aisecCrypto.Verifier, error) {
	anchor, err := loadAuditVerifier(p, dir)
	if err != nil {
		return nil, nil, err
	}
	ks, err := audit.LoadKeySchedule(ctx, db.Pool(), p, anchor)
	if err != nil {
		return nil, nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, nil, err
	}
	keyFile, _ := keyring.AuditFiles(ks.LatestID(), audit.KeyID(h, anchor.PublicKey()))
	root, err := keyring.OpenKeyDir(dir)
	if err != nil {
		return nil, nil, err
	}
	defer closeQuietly(root)
	s, err := keyring.ReadSigner(root, p, keyFile, aisecCrypto.KeyKindAuditSigning)
	if err != nil {
		return nil, nil, err
	}
	if !aisecCrypto.Equal(s.PublicKey(), ks.Latest().PublicKey()) {
		return nil, nil, fmt.Errorf("%s — не действующий ключ аудита %s", keyFile, ks.LatestID())
	}
	return s, anchor, nil
}

// syncParent сбрасывает на диск запись каталога с новым файлом.
func syncParent(path string) (err error) {
	d, err := os.Open(filepath.Dir(path)) //nolint:gosec // G304: каталог файла, заданного администратором
	if err != nil {
		return err
	}
	defer func() {
		if cerr := d.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return d.Sync()
}

// removeQuietly удаляет незавершённый файл; ошибка удаления не скрывает
// исходную, а повторный запуск сообщит о существующем файле.
func removeQuietly(path string) {
	_ = os.Remove(path) //nolint:gosec // G104: см. комментарий к функции
}

// closeFileQuietly закрывает файл, открытый только для чтения.
func closeFileQuietly(f *os.File) {
	_ = f.Close() //nolint:gosec // G104: файл открыт только для чтения
}
