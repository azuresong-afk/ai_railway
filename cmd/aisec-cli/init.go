package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Файлы каталога ключей (ADR-0007). Закрытые — 0400, открытые — 0444.
const (
	masterKeyFile  = "master.key"
	signingKeyFile = "bundle-signing.key"
	signingPubFile = "bundle-signing.pub"
	caKeyFile      = "ca.key"
	caCertFile     = "ca.crt"
	// Ключ подписи контрольных точек архивации журнала аудита (ADR-0008).
	auditKeyFile = "audit-signing.key"
	auditPubFile = "audit-signing.pub"
)

// initFileNames — все файлы, которые создаёт init.
var initFileNames = []string{masterKeyFile, signingKeyFile, signingPubFile, caKeyFile, caCertFile, auditKeyFile, auditPubFile}

const (
	permSecret = 0o400
	permPublic = 0o444
	// caCommonName — имя внутреннего УЦ (Р8); срок — MaxCertValidity.
	caCommonName = "AISec internal CA"
	// setupTokenPrefix отличает токен первичной настройки от ключей
	// приложений (aisec_<8 символов>_…) при поиске утечек.
	setupTokenPrefix = "aisec_setup_"
	setupTokenSize   = 32
	setupTokenTTL    = 24 * time.Hour
	// initDBTimeout — предел каждой операции с БД.
	initDBTimeout    = 30 * time.Second
	dataKeyAADTable  = "data_keys"
	dataKeyAADColumn = "wrapped"
)

// keyFile — файл, который создаёт init.
type keyFile struct {
	name string
	data []byte
	perm fs.FileMode
}

// initRecords — строки БД, которые создаёт init в одной транзакции вместе
// с записью аудита.
type initRecords struct {
	OrgID        string
	DataKeyID    string
	Profile      string
	AEADAlg      string
	Wrapped      []byte
	TokenID      string
	TokenHashAlg string
	TokenHash    []byte
	Created      time.Time
	TokenExpires time.Time
	CANotAfter   time.Time
	Files        []string
}

// initStore — то, что init делает с БД; за интерфейсом, чтобы основную
// логику проверять без PostgreSQL.
type initStore interface {
	// HasDataKey сообщает, создан ли уже ключ данных организации.
	HasDataKey(ctx context.Context, orgID string) (bool, error)
	// Record пишет запись аудита (init -add-audit-key).
	Record(ctx context.Context, e audit.Entry) error
	// Save записывает ключ данных, хеш токена и запись аудита одной транзакцией.
	Save(ctx context.Context, r *initRecords, actor audit.Actor) error
	// DataKeyExists после ошибки Save выясняет, была ли транзакция
	// зафиксирована (ошибка могла прийти уже после фиксации).
	DataKeyExists(ctx context.Context, id string) (bool, error)
}

// initCmd — aisec-cli init: ключи установки (ЗИ.1, ЗИ.4, Р4, Р8, ТЗ 10.4).
// Строка подключения — только из окружения, как у migrate.
func initCmd(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	fset := flag.NewFlagSet("init", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", "", "каталог ключей: существует, права 0700, файлов ключей в нём ещё нет (обязательно)")
	profile := fset.String("profile", aisecCrypto.ProfileStandard, "криптопрофиль установки: standard (gost — с этапа 6, пока отказ)")
	addAuditKey := fset.Bool("add-audit-key", false, "только создать ключ подписи журнала аудита в каталоге уже инициализированной установки")
	reissue := fset.Bool("reissue-setup-token", false, "выпустить новый токен первичной настройки вместо утерянного или истёкшего (только пока настройка не выполнена)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fset.NArg())
	}
	if *reissue {
		// Ключи не нужны: криптопрофиль берётся из ключа данных установки.
		if *dir != "" || *addAuditKey {
			return errors.New("-reissue-setup-token не сочетается с -dir и -add-audit-key")
		}
		if dsn == "" {
			return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
		}
		return reissueCmd(dsn, stdout, now)
	}
	if *dir == "" {
		return errors.New("укажите -dir — каталог ключей")
	}
	if dsn == "" {
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	p, err := aisecCrypto.New(*profile)
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
	st := pgInitStore{pool: db.Pool(), log: l}
	if *addAuditKey {
		return runAddAuditKey(ctx, *dir, p, st, cliActor(), stdout)
	}
	return runInit(ctx, *dir, p, st, cliActor(), now, stdout)
}

// reissueCmd подключается к БД и выпускает новый токен первичной настройки.
func reissueCmd(dsn string, stdout io.Writer, now time.Time) error {
	ctx := context.Background()
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return err
	}
	defer db.Close()
	st := pgReissueStore{pool: db.Pool()}
	profile, ok, err := st.SetupProfile(ctx, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("ключа данных нет: установка не инициализирована — выполните init -dir")
	}
	p, err := aisecCrypto.New(profile)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	if st.log, err = audit.New(db.Pool(), p); err != nil {
		return err
	}
	return runReissueSetupToken(ctx, p, st, cliActor(), now, stdout)
}

// runInit создаёт ключи. Порядок выбран так, чтобы сбой не оставил
// полуготовую установку: сначала все проверки, затем файлы (O_EXCL — ничего
// не перезаписывается), затем одна транзакция в БД. Если транзакция точно не
// зафиксирована, созданные файлы удаляются; если исход неизвестен (обрыв на
// фиксации), файлы сохраняются: без них ключ данных в БД не расшифровать.
func runInit(ctx context.Context, dir string, p aisecCrypto.Provider, st initStore, actor audit.Actor, now time.Time, stdout io.Writer) error {
	root, err := openKeyDir(dir)
	if err != nil {
		return err
	}
	defer closeQuietly(root)
	for _, name := range initFileNames {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: файл уже существует или недоступен — init не перезаписывает ключи (ротация — ADR-0007)", name)
		}
	}
	has, err := st.HasDataKey(ctx, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	if has {
		return errors.New("ключ данных уже создан: установка инициализирована раньше (ротация — ADR-0007)")
	}
	files, rec, token, err := generateInit(p, now)
	if err != nil {
		return err
	}
	created, err := writeKeyFiles(root, files)
	if err != nil {
		removeFiles(root, created)
		return err
	}
	if err := st.Save(ctx, rec, actor); err != nil {
		committed, cerr := st.DataKeyExists(ctx, rec.DataKeyID)
		switch {
		case cerr != nil:
			return fmt.Errorf("%w; исход транзакции неизвестен (%w) — файлы ключей в %s сохранены: проверьте, есть ли в data_keys строка %s; если её нет, удалите файлы и повторите init",
				err, cerr, dir, rec.DataKeyID)
		case !committed:
			removeFiles(root, created)
			return err
		}
		// Фиксация прошла, ошибку вернул только ответ на COMMIT.
	}
	say(stdout, "Ключи установки созданы в %s (профиль %s):\n", dir, rec.Profile)
	for _, f := range files {
		say(stdout, "  %-20s %04o\n", f.name, f.perm)
	}
	say(stdout, "Ключ данных %s зашифрован мастер-ключом и записан в БД. Сертификат УЦ действует до %s.\n"+
		"Файлы принадлежат пользователю, запустившему init: передайте их пользователю службы (chown) до запуска сервера.\n",
		rec.DataKeyID, rec.CANotAfter.UTC().Format(time.DateOnly))
	// Токен выводится с проверкой ошибки записи: если он не дошёл, нужен
	// повторный выпуск (задача 2.7), и код возврата должен это показать.
	if _, err := fmt.Fprintf(stdout, "\nТокен первичной настройки (показывается один раз, действует до %s UTC):\n\n  %s\n\n"+
		"Сохраните резервную копию master.key отдельно от резервной копии БД: без него ключ данных не расшифровать.\n",
		rec.TokenExpires.UTC().Format("2006-01-02 15:04"), token); err != nil {
		return fmt.Errorf("ключи созданы, но токен первичной настройки не выведен (%w): нужен повторный выпуск токена", err)
	}
	return nil
}

// generateInit создаёт все ключи в памяти. Открытые копии мастер-ключа и
// ключа данных затираются после кодирования.
func generateInit(p aisecCrypto.Provider, now time.Time) (files []keyFile, rec *initRecords, token string, err error) {
	rnd, err := p.Random()
	if err != nil {
		return nil, nil, "", err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, nil, "", err
	}
	now = now.UTC().Truncate(time.Microsecond)
	rec = &initRecords{OrgID: audit.DefaultOrgID, Profile: p.Name(), Created: now, TokenExpires: now.Add(setupTokenTTL), TokenHashAlg: h.Name()}

	// Мастер-ключ и ключ данных (Р4).
	master, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.AEADKeySize)
	if err != nil {
		return nil, nil, "", err
	}
	defer clear(master)
	masterPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), master)
	if err != nil {
		return nil, nil, "", err
	}
	wrap, err := p.NewAEAD(master)
	if err != nil {
		return nil, nil, "", err
	}
	dataKey, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.AEADKeySize)
	if err != nil {
		return nil, nil, "", err
	}
	defer clear(dataKey)
	id, err := store.NewUUIDv7(now, rnd)
	if err != nil {
		return nil, nil, "", err
	}
	rec.DataKeyID = string(id)
	aad, err := aisecCrypto.StorageAAD(dataKeyAADTable, dataKeyAADColumn, rec.DataKeyID)
	if err != nil {
		return nil, nil, "", err
	}
	if rec.Wrapped, err = wrap.Seal(dataKey, aad); err != nil {
		return nil, nil, "", err
	}
	rec.AEADAlg = wrap.Name()

	// Ключ подписи пакетов конфигурации (Р7).
	signer, err := p.GenerateSigner()
	if err != nil {
		return nil, nil, "", err
	}
	seed := signer.Seed()
	defer clear(seed)
	signingPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigning, p.Name(), seed)
	if err != nil {
		return nil, nil, "", err
	}
	pubPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigningPublic, p.Name(), signer.PublicKey())
	if err != nil {
		return nil, nil, "", err
	}

	// Ключ подписи контрольных точек журнала аудита (ADR-0008).
	auditFiles, err := generateAuditKey(p)
	if err != nil {
		return nil, nil, "", err
	}

	// Внутренний УЦ для mTLS шлюз — сервер (Р8).
	ca, err := aisecCrypto.NewCA(caCommonName, aisecCrypto.MaxCertValidity, now)
	if err != nil {
		return nil, nil, "", err
	}
	caKeyPEM, err := ca.KeyPEM()
	if err != nil {
		return nil, nil, "", err
	}
	rec.CANotAfter = ca.NotAfter()

	// Одноразовый токен первичной настройки (ЗИ.4): в БД — только хеш.
	raw, err := aisecCrypto.RandomBytes(rnd, setupTokenSize)
	if err != nil {
		return nil, nil, "", err
	}
	token = setupTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	rec.TokenHash = h.Sum([]byte(token))
	tid, err := store.NewUUIDv7(now, rnd)
	if err != nil {
		return nil, nil, "", err
	}
	rec.TokenID = string(tid)

	files = []keyFile{
		{masterKeyFile, masterPEM, permSecret},
		{signingKeyFile, signingPEM, permSecret},
		{signingPubFile, pubPEM, permPublic},
		{caKeyFile, caKeyPEM, permSecret},
		{caCertFile, ca.CertPEM(), permPublic},
	}
	files = append(files, auditFiles...)
	for _, f := range files {
		rec.Files = append(rec.Files, f.name)
	}
	return files, rec, token, nil
}

// generateAuditKey создаёт пару ключей подписи контрольных точек аудита.
// Пара отдельная от ключа пакетов: её компрометация не позволяет подписать
// конфигурацию шлюза, и наоборот.
func generateAuditKey(p aisecCrypto.Provider) ([]keyFile, error) {
	s, err := p.GenerateSigner()
	if err != nil {
		return nil, err
	}
	seed := s.Seed()
	defer clear(seed)
	keyPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindAuditSigning, p.Name(), seed)
	if err != nil {
		return nil, err
	}
	pubPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindAuditSigningPublic, p.Name(), s.PublicKey())
	if err != nil {
		return nil, err
	}
	return []keyFile{{auditKeyFile, keyPEM, permSecret}, {auditPubFile, pubPEM, permPublic}}, nil
}

// runAddAuditKey — init -add-audit-key: ключ аудита для установки,
// инициализированной до ADR-0008. Требует каталог ключей этой установки
// (master.key на месте) и ключ данных в БД; существующий ключ аудита не
// перезаписывается. Если запись аудита не удалась, файлы удаляются: ключ
// без записи о создании не остаётся.
func runAddAuditKey(ctx context.Context, dir string, p aisecCrypto.Provider, st initStore, actor audit.Actor, stdout io.Writer) error {
	root, err := openKeyDir(dir)
	if err != nil {
		return err
	}
	defer closeQuietly(root)
	if info, err := root.Lstat(masterKeyFile); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s: нет в каталоге — это не каталог ключей установки (сначала init)", masterKeyFile)
	}
	for _, name := range []string{auditKeyFile, auditPubFile} {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: файл уже существует или недоступен — ключ аудита не перезаписывается (ротация — ADR-0008)", name)
		}
	}
	has, err := st.HasDataKey(ctx, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	if !has {
		return errors.New("ключа данных нет: установка не инициализирована — выполните init без -add-audit-key")
	}
	files, err := generateAuditKey(p)
	if err != nil {
		return err
	}
	created, err := writeKeyFiles(root, files)
	if err != nil {
		removeFiles(root, created)
		return err
	}
	if err := st.Record(ctx, audit.Entry{
		OrgID: audit.DefaultOrgID, Actor: actor, Action: "system.audit_key",
		Object: audit.Object{Type: "key_file", ID: auditPubFile}, Result: audit.ResultSuccess,
		Details: map[string]any{"profile": p.Name(), "files": []any{auditKeyFile, auditPubFile}},
	}); err != nil {
		removeFiles(root, created)
		return err
	}
	say(stdout, "Ключ подписи журнала аудита создан в %s (профиль %s):\n", dir, p.Name())
	for _, f := range files {
		say(stdout, "  %-20s %04o\n", f.name, f.perm)
	}
	say(stdout, "Передайте файлы пользователю, который запускает aisec-cli audit archive (chown).\n")
	return nil
}

// openKeyDir открывает существующий каталог, закрытый для группы и
// остальных. Каталог не создаётся: его владельца и права задаёт
// администратор. Файлы дальше открываются через os.Root: подмена пути
// после проверки (например, символической ссылкой) не выводит запись за
// пределы проверенного каталога.
func openKeyDir(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог ключей: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		closeQuietly(root)
		return nil, fmt.Errorf("каталог ключей: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		closeQuietly(root)
		return nil, fmt.Errorf("%s: каталог ключей доступен группе или остальным (права %04o); нужно 0700", dir, info.Mode().Perm())
	}
	return root, nil
}

// writeKeyFiles создаёт файлы с O_EXCL (существующий файл или ссылка — ошибка)
// и сбрасывает их на диск. Возвращает имена созданных файлов, даже при ошибке.
// Копии закрытых ключей (файлы без доступа для группы и остальных) в памяти
// затираются после записи, в том числе при ошибке (Н4 ревью 2.r1).
func writeKeyFiles(root *os.Root, files []keyFile) (created []string, err error) {
	defer func() {
		for i := range files {
			if files[i].perm&0o077 == 0 {
				clear(files[i].data)
			}
		}
	}()
	for _, f := range files {
		if err := writeNewFile(root, f.name, f.data, f.perm); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				created = append(created, f.name)
			}
			return created, fmt.Errorf("%s: %w", f.name, err)
		}
		created = append(created, f.name)
	}
	return created, syncDir(root)
}

func writeNewFile(root *os.Root, name string, data []byte, perm fs.FileMode) (err error) {
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

// syncDir сбрасывает на диск записи каталога, чтобы файлы ключей пережили сбой питания.
func syncDir(root *os.Root) (err error) {
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

// removeFiles удаляет файлы, созданные до сбоя. Ошибка удаления не скрывает
// исходную; администратору о ней сообщит повторный init («файл уже существует»).
func removeFiles(root *os.Root, names []string) {
	for _, n := range names {
		_ = root.Remove(n) //nolint:gosec // G104: см. комментарий к функции
	}
}

// closeQuietly закрывает каталог, открытый только для чтения записей: ошибка
// закрытия ни на что не влияет.
func closeQuietly(root *os.Root) {
	_ = root.Close() //nolint:gosec // G104: см. комментарий к функции
}

// pgInitStore — initStore на PostgreSQL.
type pgInitStore struct {
	pool *pgxpool.Pool
	log  *audit.Log
}

func (s pgInitStore) HasDataKey(ctx context.Context, orgID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM data_keys WHERE org_id = $1)", orgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("проверка ключа данных (миграции применены? aisec-cli migrate): %w", err)
	}
	return exists, nil
}

func (s pgInitStore) Record(ctx context.Context, e audit.Entry) error {
	ctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	return s.log.Record(ctx, e)
}

func (s pgInitStore) DataKeyExists(ctx context.Context, id string) (bool, error) {
	// Контекст вызывающего мог истечь вместе с неудачной фиксацией.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), initDBTimeout)
	defer cancel()
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM data_keys WHERE id = $1)", id).Scan(&exists)
	return exists, err
}

func (s pgInitStore) Save(ctx context.Context, r *initRecords, actor audit.Actor) (err error) {
	ctx, cancel := context.WithTimeout(ctx, initDBTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer rcancel()
			_ = tx.Rollback(rctx) //nolint:gosec // G104: ошибку отката скрывает исходная
		}
	}()
	if _, err = tx.Exec(ctx, `INSERT INTO data_keys (id, org_id, version, profile, alg, wrapped, created_at)
		VALUES ($1, $2, 1, $3, $4, $5, $6)`, r.DataKeyID, r.OrgID, r.Profile, r.AEADAlg, r.Wrapped, r.Created); err != nil {
		return fmt.Errorf("запись ключа данных: %w", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO setup_tokens (id, org_id, hash_alg, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, r.TokenID, r.OrgID, r.TokenHashAlg, r.TokenHash, r.Created, r.TokenExpires); err != nil {
		return fmt.Errorf("запись токена первичной настройки: %w", err)
	}
	if err = s.log.RecordTx(ctx, tx, initAuditEntry(r, actor)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// initAuditEntry — запись о создании ключей (РСБ.2): что создано и до
// какого срока, без самих ключей и токена.
func initAuditEntry(r *initRecords, actor audit.Actor) audit.Entry {
	files := make([]any, len(r.Files))
	for i, f := range r.Files {
		files[i] = f
	}
	return audit.Entry{
		OrgID:  r.OrgID,
		Actor:  actor,
		Action: "system.init",
		Object: audit.Object{Type: "data_key", ID: r.DataKeyID},
		Result: audit.ResultSuccess,
		Details: map[string]any{
			"profile":          r.Profile,
			"data_key_version": 1,
			"files":            files,
			"ca_not_after":     r.CANotAfter.UTC().Format(time.RFC3339),
			"setup_expires_at": r.TokenExpires.UTC().Format(time.RFC3339),
			"setup_record_id":  r.TokenID,
		},
	}
}
