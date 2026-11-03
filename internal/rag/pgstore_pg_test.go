package rag

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Манифест коллекций RAG на живой БД (задача 5.24, миграция 0071): версии,
// хранение двух версий, разница, исключения, записи аудита в той же
// транзакции, ограничения таблиц. Переменная AISEC_TEST_DATABASE_URL; без
// неё тесты пропускаются. Каждый тест — в своей схеме; сервер работает под
// ролью aisec_app.

func pgTestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func newPool(t *testing.T, dsn, schema, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 4
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if role != "" {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SELECT set_config('role', $1, false)", role)
			return err
		}
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type poolExec struct{ p *pgxpool.Pool }

func (e poolExec) InTx(ctx context.Context, fn func(store.Tx) error) error {
	tx, err := e.p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после фиксации безвреден
	if err := fn(poolTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type poolTx struct{ tx pgx.Tx }

func (t poolTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t poolTx) Applied(ctx context.Context) ([]store.Applied, error) {
	rows, err := t.tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Applied, error) {
		var a store.Applied
		err := r.Scan(&a.Version, &a.Name, &a.Checksum)
		return a, err
	})
}

type pgEnv struct {
	owner *pgxpool.Pool
	svc   *Service
	st    *PGStore
}

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgTestCtx(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "rag_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	owner := newPool(t, dsn, schema, "")
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: poolExec{owner}, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	app := newPool(t, dsn, schema, "aisec_app")
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	e := &pgEnv{owner: owner, st: st}
	clock := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if e.svc, err = New(Options{Store: st, Provider: p, Clock: func() time.Time { clock = clock.Add(time.Minute); return clock }}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgTestCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *pgEnv) audits(t *testing.T, action string) int {
	t.Helper()
	return e.count(t, "SELECT count(*) FROM audit_log WHERE action = $1", action)
}

func docs(t *testing.T, n int, changed map[int]string) []Document {
	t.Helper()
	out := make([]Document, 0, n)
	for i := range n {
		h := strings.Repeat("ab", 32)
		if c, ok := changed[i]; ok {
			h = strings.Repeat(c, 32)
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Document{ID: fmt.Sprintf("kb/doc-%05d.md", i), SHA256: raw, Size: int64(i)})
	}
	return out
}

// Версии манифеста, хранение текущей и предыдущей, разница и записи аудита
// той же транзакцией; большой манифест (COPY) и страницы документов.
func TestPGRAGManifestVersions(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	by := By{Actor: audit.Actor{Type: audit.ActorAPIToken, ID: "01900000-0000-7000-8000-00000000d001", Name: "indexer"}}
	res, err := e.svc.LoadManifest(ctx, by, "kb-hr", docs(t, 3, nil))
	if err != nil || !res.Created || res.Collection.Version != 1 {
		t.Fatalf("первая версия: %+v %v", res, err)
	}
	// Вторая: документ 1 изменён, 2 пропал, 3 и 4 новые.
	d2 := docs(t, 5, map[int]string{1: "cd"})
	d2 = append(d2[:2], d2[3:]...)
	res, err = e.svc.LoadManifest(ctx, by, "kb-hr", d2)
	if err != nil {
		t.Fatal(err)
	}
	if c := res.Collection; c.Version != 2 || c.Diff.Added != 2 || c.Diff.Changed != 1 || c.Diff.Removed != 1 || c.PrevLoadedAt == nil ||
		c.Diff.ChangedIDs[0] != "kb/doc-00001.md" {
		t.Fatalf("вторая версия: %+v", c)
	}
	if n := e.audits(t, "rag.manifest_loaded"); n != 2 {
		t.Fatalf("rag.manifest_loaded: %d", n)
	}
	if n := e.audits(t, "rag.document_changed"); n != 1 {
		t.Fatalf("rag.document_changed: %d", n)
	}
	// Третья — большой манифест: хранятся только версии 2 и 3.
	big := docs(t, 20000, map[int]string{0: "ef"})
	if res, err = e.svc.LoadManifest(ctx, by, "kb-hr", big); err != nil || res.Collection.Documents != 20000 {
		t.Fatalf("большой манифест: %+v %v", res.Collection, err)
	}
	if n := e.count(t, "SELECT count(DISTINCT version) FROM rag_documents"); n != 2 {
		t.Fatalf("версий в хранилище: %d", n)
	}
	if n := e.count(t, "SELECT count(*) FROM rag_documents WHERE version = 1"); n != 0 {
		t.Fatalf("строк версии 1: %d", n)
	}
	c, err := e.svc.Collection(ctx, "kb-hr")
	if err != nil || c.Version != 3 || c.Diff.Added != 20000-4 || len(c.Diff.AddedIDs) != MaxDiffSample || c.Diff.Changed != 2 {
		t.Fatalf("карточка: %+v %v", c.Diff.Added, err)
	}
	page, err := e.svc.Documents(ctx, "kb-hr", "kb/doc-00009.md", 2)
	if err != nil || len(page) != 2 || page[0].ID != "kb/doc-00010.md" || len(page[0].SHA256) != 32 {
		t.Fatalf("страница: %+v %v", page, err)
	}
	cs, err := e.svc.Collections(ctx)
	if err != nil || len(cs) != 1 || cs[0].Documents != 20000 {
		t.Fatalf("список: %+v %v", cs, err)
	}
	if _, err := e.svc.Documents(ctx, "none", "", 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет коллекции: %v", err)
	}
	// Ограничения таблиц: неверный slug, ID документа длиннее 512 байт,
	// хеш не из 32 байт.
	for _, sql := range []string{
		`INSERT INTO rag_collections (id, org_id, slug, version, documents, size, excluded, loaded_at, loaded_by, diff, created_at)
			VALUES ('01900000-0000-7000-8000-00000000f001', '` + audit.DefaultOrgID + `', 'Bad', 1, 0, 0, 0, now(), 'x', '{}', now())`,
		`INSERT INTO rag_documents (collection_id, version, doc_id, sha256, size, excluded)
			SELECT id, 9, repeat('a', 513), '\x00', 0, false FROM rag_collections LIMIT 1`,
	} {
		if _, err := e.owner.Exec(ctx, sql); err == nil {
			t.Fatalf("ограничение не сработало: %s", sql)
		}
	}
}

func TestPGRAGExclusions(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	by := By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-00000000d002", Name: "admin"}}
	if _, err := e.svc.Exclude(ctx, by, "kb", ExclusionInput{DocumentID: "a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет коллекции: %v", err)
	}
	if _, err := e.svc.LoadManifest(ctx, by, "kb", docs(t, 3, nil)); err != nil {
		t.Fatal(err)
	}
	ex, err := e.svc.Exclude(ctx, by, "kb", ExclusionInput{DocumentID: "kb/doc-00001.md", Reason: "инъекция"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Exclude(ctx, by, "kb", ExclusionInput{DocumentID: "kb/doc-00001.md"}); !errors.Is(err, ErrExists) {
		t.Fatalf("повтор: %v", err)
	}
	res, err := e.svc.LoadManifest(ctx, by, "kb", docs(t, 3, nil))
	if err != nil || len(res.Blocked) != 1 || res.Blocked[0] != "kb/doc-00001.md" || res.Collection.ExclusionCount != 1 {
		t.Fatalf("исключённые в ответе: %+v %v", res, err)
	}
	page, err := e.svc.Documents(ctx, "kb", "", 10)
	if err != nil || page[0].Blocked || !page[1].Blocked {
		t.Fatalf("признак в документах: %+v %v", page, err)
	}
	c, err := e.svc.Collection(ctx, "kb")
	if err != nil || len(c.Exclusions) != 1 || c.Exclusions[0].Reason != "инъекция" || c.ExclusionCount != 1 {
		t.Fatalf("карточка: %+v %v", c, err)
	}
	if err := e.svc.RemoveExclusion(ctx, by, "kb", ex.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveExclusion(ctx, by, "kb", ex.ID); !errors.Is(err, ErrExclusionNotFound) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if n := e.audits(t, "rag.document_excluded") + e.audits(t, "rag.exclusion_removed"); n != 2 {
		t.Fatalf("записей аудита исключений: %d", n)
	}
	if n := e.count(t, "SELECT count(*) FROM audit_log WHERE action = 'rag.exclusion_removed' AND details->>'weakening' = 'true'"); n != 1 {
		t.Fatalf("признак ослабления: %d", n)
	}
}

// Коллекция версии 0 — восстановлена из резервной копии с исключениями без
// манифеста (ревью 5.r2, 5Н15, миграция 0073): исключения действуют до
// первой загрузки, первая загрузка даёт версию 1 без разницы и
// rag.document_changed.
func TestPGRAGRestoredCollection(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	const colID = "01900000-0000-7000-8000-00000000f010"
	if _, err := e.owner.Exec(ctx, `INSERT INTO rag_collections (id, org_id, slug, version, documents, size, excluded, loaded_at, loaded_by,
		diff, created_at) VALUES ($1, $2, 'kb', 0, 0, 0, 0, now(), 'backup_restore', '{}', now())`, colID, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO rag_exclusions (id, collection_id, doc_id, reason, created_at, created_by)
		VALUES ('01900000-0000-7000-8000-00000000f011', $1, 'kb/doc-00002.md', 'инъекция', now(), 'user:admin')`, colID); err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.Collection(ctx, "kb")
	if err != nil || c.Version != 0 || c.ExclusionCount != 1 {
		t.Fatalf("коллекция версии 0: %+v %v", c, err)
	}
	if page, err := e.svc.Documents(ctx, "kb", "", 10); err != nil || len(page) != 0 {
		t.Fatalf("документы версии 0: %+v %v", page, err)
	}
	by := By{Actor: audit.Actor{Type: audit.ActorAPIToken, ID: "01900000-0000-7000-8000-00000000d001", Name: "indexer"}}
	res, err := e.svc.LoadManifest(ctx, by, "kb", docs(t, 3, nil))
	if err != nil || res.Created || res.Collection.Version != 1 || res.Collection.PrevLoadedAt != nil || !res.Collection.Diff.Empty() ||
		len(res.Blocked) != 1 || res.Blocked[0] != "kb/doc-00002.md" {
		t.Fatalf("первая загрузка: %+v %v", res, err)
	}
	if n := e.audits(t, "rag.document_changed"); n != 0 {
		t.Fatalf("rag.document_changed после версии 0: %d", n)
	}
	// Версия 0 без документов; предыдущая версия — только у версий от 2.
	for _, sql := range []string{
		`UPDATE rag_collections SET version = 0, documents = 3, prev_loaded_at = NULL`,
		`UPDATE rag_collections SET version = 0, documents = 0, prev_loaded_at = now()`,
		`UPDATE rag_collections SET version = -1`,
	} {
		if _, err := e.owner.Exec(ctx, sql); err == nil {
			t.Fatalf("ограничение не сработало: %s", sql)
		}
	}
}
