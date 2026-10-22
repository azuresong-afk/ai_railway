package keyring

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ротация мастер-ключа (ADR-0018, п. 2; задача 3.2 этапа 3): новый файл
// пишется рядом, все строки data_keys перешифровываются им в одной
// транзакции, затем файлы переименовываются. Прежний файл не удаляется:
// он нужен для восстановления дампа БД, снятого до ротации. Сбой на любом
// шаге исправляет повторный запуск.

// MasterKeyNextFile — новый мастер-ключ до переименования.
const MasterKeyNextFile = MasterKeyFile + ".new"

// retiredSuffix — окончание имени прежнего мастер-ключа.
const retiredSuffix = ".retired"

// MasterRotation — итог ротации мастер-ключа.
type MasterRotation struct {
	// Retired — имя файла прежнего мастер-ключа в каталоге ключей.
	Retired string
	// DataKeys — сколько строк data_keys перешифровано.
	DataKeys int
	// MasterVersion — номер нового мастер-ключа.
	MasterVersion int
	// Recovered — завершена прерванная ротация, нового ключа не создано.
	Recovered bool
	// StaleRemoved — удалён master.key.new от несостоявшейся ротации.
	StaleRemoved bool
}

// RotateMaster меняет мастер-ключ установки в каталоге dir (os.Root).
func RotateMaster(ctx context.Context, db Owner, rec Recorder, p aisecCrypto.Provider, dir, orgID string,
	actor audit.Actor, now time.Time) (MasterRotation, error) {
	root, err := OpenKeyDir(dir)
	if err != nil {
		return MasterRotation{}, err
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: файлы записаны и синхронизированы раньше
	var out MasterRotation
	// Восстановление: какой файл открывает действующий ключ данных.
	state, err := masterState(ctx, db, p, dir, orgID)
	if err != nil {
		return out, err
	}
	switch state {
	case stateNextCommitted:
		// Транзакция прошлого запуска зафиксирована, переименование нет.
		retired, err := swapMaster(root, now)
		if err != nil {
			return out, err
		}
		return MasterRotation{Retired: retired, Recovered: true}, nil
	case stateCurrentWithStale:
		// Транзакция не прошла: .new ничего не защищает.
		if err := root.Remove(MasterKeyNextFile); err != nil {
			return out, fmt.Errorf("%s: %w", MasterKeyNextFile, err)
		}
		if err := syncRoot(root); err != nil {
			return out, err
		}
		out.StaleRemoved = true
	}
	current, err := ReadMaster(dir, p)
	if err != nil {
		return out, err
	}
	defer clear(current)
	oldWrap, err := p.NewAEAD(current)
	if err != nil {
		return out, err
	}
	rnd, err := p.Random()
	if err != nil {
		return out, err
	}
	next, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.AEADKeySize)
	if err != nil {
		return out, err
	}
	defer clear(next)
	newWrap, err := p.NewAEAD(next)
	if err != nil {
		return out, err
	}
	pemData, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), next)
	if err != nil {
		return out, err
	}
	err = WriteNewFile(root, MasterKeyNextFile, pemData, 0o400)
	clear(pemData)
	if err != nil {
		return out, fmt.Errorf("%s: %w", MasterKeyNextFile, err)
	}
	if err := syncRoot(root); err != nil {
		return out, err
	}
	err = InTx(ctx, db, func(tx pgx.Tx) error {
		n, version, err := rewrapDataKeys(ctx, tx, orgID, oldWrap, newWrap)
		if err != nil {
			return err
		}
		out.DataKeys, out.MasterVersion = n, version
		return rec.RecordTx(ctx, tx, audit.Entry{
			OrgID: orgID, Actor: actor, Action: "keys.master_rotated",
			Object: audit.Object{Type: "key_file", ID: MasterKeyFile}, Result: audit.ResultSuccess,
			Details: map[string]any{"data_keys": n, "master_version": version},
		})
	})
	if err != nil {
		// Ошибка могла прийти уже после фиксации: решает, какой файл
		// открывает ключ данных.
		st, serr := masterState(context.WithoutCancel(ctx), db, p, dir, orgID)
		switch {
		case serr != nil:
			return out, fmt.Errorf("%w; исход транзакции неизвестен (%w) — файлы %s и %s сохранены: повторите keys rotate-master",
				err, serr, MasterKeyFile, MasterKeyNextFile)
		case st == stateCurrentWithStale:
			_ = root.Remove(MasterKeyNextFile) //nolint:gosec // G104: повторный запуск удалит его сам
			return out, err
		case st != stateNextCommitted:
			return out, err
		}
	}
	if out.Retired, err = swapMaster(root, now); err != nil {
		return out, fmt.Errorf("мастер-ключ перешифрован, но файлы не переименованы (%w): повторите keys rotate-master", err)
	}
	return out, nil
}

// rewrapDataKeys перешифровывает обёртки всех версий ключа данных.
func rewrapDataKeys(ctx context.Context, tx pgx.Tx, orgID string, oldWrap, newWrap aisecCrypto.AEAD) (int, int, error) {
	type row struct {
		id      string
		mv      int
		wrapped []byte
	}
	rows, err := collect(ctx, tx, `SELECT id::text, master_version, wrapped FROM data_keys WHERE org_id = $1 ORDER BY version FOR UPDATE`,
		[]any{orgID}, func(r pgx.Rows) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.mv, &x.wrapped)
		})
	if err != nil {
		return 0, 0, fmt.Errorf("мастер-ключ: чтение ключей данных: %w", err)
	}
	if len(rows) == 0 {
		return 0, 0, ErrNoDataKey
	}
	version := 0
	for _, x := range rows {
		version = max(version, x.mv+1)
	}
	for _, x := range rows {
		aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", x.id)
		if err != nil {
			return 0, 0, err
		}
		key, err := oldWrap.Open(x.wrapped, aad)
		if err != nil {
			return 0, 0, fmt.Errorf("мастер-ключ: ключ данных %s не расшифрован текущим мастер-ключом: %w", x.id, err)
		}
		wrapped, err := newWrap.Seal(key, aad)
		clear(key)
		if err != nil {
			return 0, 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE data_keys SET wrapped = $2, master_version = $3 WHERE id = $1`, x.id, wrapped, version); err != nil {
			return 0, 0, fmt.Errorf("мастер-ключ: запись ключа данных %s: %w", x.id, err)
		}
	}
	return len(rows), version, nil
}

// Состояние файлов мастер-ключа относительно БД.
type masterFileState int

const (
	stateCurrent          masterFileState = iota // master.key открывает ключ данных, .new нет
	stateCurrentWithStale                        // master.key открывает, .new — от несостоявшейся ротации
	stateNextCommitted                           // открывает только .new: осталось переименовать
)

// masterState выясняет, какой файл открывает действующий ключ данных.
func masterState(ctx context.Context, db Owner, p aisecCrypto.Provider, dir, orgID string) (masterFileState, error) {
	qctx, cancel := dbCtx(ctx)
	defer cancel()
	var r keyRow
	err := db.QueryRow(qctx, `SELECT id::text, version, profile, wrapped FROM data_keys WHERE org_id = $1 AND retired_at IS NULL`, orgID).
		Scan(&r.id, &r.num, &r.profile, &r.wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoDataKey
	}
	if err != nil {
		return 0, fmt.Errorf("мастер-ключ: чтение ключа данных: %w", err)
	}
	opens := func(name string) (bool, error) {
		key, err := readMasterFile(filepath.Join(dir, name), p)
		if errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		if err != nil {
			return false, err
		}
		defer clear(key)
		wrap, err := p.NewAEAD(key)
		if err != nil {
			return false, err
		}
		_, err = r.open(p, wrap)
		return err == nil, nil
	}
	cur, curErr := opens(MasterKeyFile)
	if curErr != nil && !errors.Is(curErr, fs.ErrNotExist) {
		return 0, curErr
	}
	next, nextErr := opens(MasterKeyNextFile)
	if nextErr != nil && !errors.Is(nextErr, fs.ErrNotExist) {
		return 0, nextErr
	}
	haveNext := !errors.Is(nextErr, fs.ErrNotExist)
	switch {
	case cur && haveNext:
		return stateCurrentWithStale, nil
	case cur:
		return stateCurrent, nil
	case next:
		return stateNextCommitted, nil
	}
	return 0, errors.New("мастер-ключ: ни master.key, ни master.key.new не расшифровывают ключ данных — это не каталог ключей установки")
}

// swapMaster переименовывает master.key в master.key.<время>.retired и
// master.key.new в master.key. Возвращает имя прежнего файла.
func swapMaster(root *os.Root, now time.Time) (string, error) {
	retired := MasterKeyFile + "." + now.UTC().Format("20060102T150405Z") + retiredSuffix
	if _, err := root.Lstat(retired); !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%s: файл уже существует", retired)
	}
	if err := root.Rename(MasterKeyFile, retired); err != nil {
		return "", fmt.Errorf("%s: %w", MasterKeyFile, err)
	}
	if err := root.Rename(MasterKeyNextFile, MasterKeyFile); err != nil {
		return "", fmt.Errorf("%s: %w", MasterKeyNextFile, err)
	}
	return retired, syncRoot(root)
}

// OpenKeyDir открывает каталог ключей: существует и закрыт для группы и
// остальных (ADR-0007, п. 1). Файлы дальше открываются через os.Root.
func OpenKeyDir(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог ключей: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close() //nolint:gosec // G104: ошибка Stat важнее
		return nil, fmt.Errorf("каталог ключей: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = root.Close() //nolint:gosec // G104: каталог отклонён
		return nil, fmt.Errorf("%s: каталог ключей доступен группе или остальным (права %04o); нужно 0700", dir, info.Mode().Perm())
	}
	return root, nil
}

// WriteNewFile создаёт файл с O_EXCL (существующий файл или ссылка —
// ошибка) и сбрасывает его на диск.
func WriteNewFile(root *os.Root, name string, data []byte, perm fs.FileMode) (err error) {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// syncRoot сбрасывает на диск записи каталога.
func syncRoot(root *os.Root) (err error) {
	d, err := root.Open(".")
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
