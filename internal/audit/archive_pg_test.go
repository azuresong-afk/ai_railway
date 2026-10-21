package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Тесты архивации на PostgreSQL (AISEC_TEST_DATABASE_URL). В CI БД нет, и
// тесты пропускаются, поэтому префикса TestDMxx_ у них нет: строку DM-43
// покрывают тесты без БД (archive_test.go).

// syncBuffer — файл архива в памяти.
type syncBuffer struct{ bytes.Buffer }

func (*syncBuffer) Sync() error { return nil }

// archiveSetup — журнал с пятью старыми (два года назад) и двумя свежими
// записями и журнал владельца с контрольными точками для архивации.
func archiveSetup(t *testing.T) (*testEnv, *Log, crypto.Signer, crypto.Verifier) {
	t.Helper()
	env := setupDB(t)
	ctx := ctxT(t)
	if _, err := env.owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{env.schema}.Sanitize()+" TO aisec_audit_archiver"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(-2, 0, 0)
	oldLog, err := New(env.app, provider(t), WithClock(func() time.Time { return old }))
	if err != nil {
		t.Fatal(err)
	}
	record(t, oldLog, 5)
	record(t, env.log, 2)
	s, v := signerPair(t)
	l := archiveLog(t, env.owner, v)
	return env, l, s, v
}

func archiveLog(t *testing.T, db *pgxpool.Pool, v crypto.Verifier) *Log {
	t.Helper()
	cps, err := NewPGCheckpoints(db, provider(t), v)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(db, provider(t), WithCheckpoints(cps))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var archiveActor = Actor{Type: ActorCLI, ID: "uid:0", Name: "root"}

func TestArchivePostgres(t *testing.T) {
	env, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	// Есть ли точки — по ним сервер решает, обязателен ли ключ аудита (В5).
	cps, err := NewPGCheckpoints(env.app, provider(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cps.Any(ctx); err != nil || ok {
		t.Fatalf("точки до архивации: %v %v", ok, err)
	}
	var out syncBuffer
	res, err := l.Archive(ctx, ArchiveOptions{Out: &out, ArchiveName: "audit-1.jsonl", Signer: s, Verifier: v, By: archiveActor})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cps.Any(ctx); err != nil || !ok {
		t.Fatalf("точки после архивации: %v %v", ok, err)
	}
	cp := res.Checkpoint
	if cp.Seq != 5 || cp.Records != 5 || cp.PrevSeq != 0 {
		t.Fatalf("точка: %+v", cp)
	}
	h := hasher(t)
	got, err := VerifyArchive(bytes.NewReader(out.Bytes()), h, v)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != cp.ID || !bytes.Equal(got.ArchiveHash, cp.ArchiveHash) {
		t.Fatalf("точка в файле и в БД различаются: %+v", got)
	}
	var minSeq, archived int64
	if err := env.owner.QueryRow(ctx, "SELECT min(seq) FROM audit_log").Scan(&minSeq); err != nil || minSeq != 6 {
		t.Fatalf("начало хранимой части: %d %v", minSeq, err)
	}
	if err := env.owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'audit.archive' AND object_id = $1", cp.ID).
		Scan(&archived); err != nil || archived != 1 {
		t.Fatalf("запись audit.archive: %d %v", archived, err)
	}

	// Цепочка цела от точки: с проверкой подписей, без неё (как у сервера —
	// роль приложения, без открытого ключа) и после новых записей.
	record(t, env.log, 1)
	for name, lg := range map[string]*Log{
		"с ключом":        l,
		"роль сервера":    archiveLog(t, env.app, nil),
		"сервер, ещё раз": archiveLog(t, env.app, nil),
	} {
		if r := verify(t, NewVerifier(lg)); !r.OK() {
			t.Fatalf("%s: %+v", name, r.Break)
		}
	}
	// Без контрольных точек начало хранимой части не подтверждается.
	if r := verify(t, NewVerifier(env.log)); r.OK() {
		t.Fatal("журнал без точек принял цепочку, начинающуюся не с 1")
	}

	// Повторно архивировать нечего: свежие записи моложе срока хранения.
	var again syncBuffer
	if _, err := l.Archive(ctx, ArchiveOptions{Out: &again, ArchiveName: "audit-2.jsonl", Signer: s, Verifier: v, By: archiveActor}); !errors.Is(err, ErrNothingToArchive) {
		t.Fatalf("повторная архивация: %v", err)
	}

	// Чужой ключ подписи: прежняя точка не проверяется, архивация отменена.
	otherS, ov := signerPair(t)
	if _, err := archiveLog(t, env.owner, ov).Archive(ctx, ArchiveOptions{Out: &again, ArchiveName: "x", Signer: otherS, Verifier: ov, By: archiveActor}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("архивация чужим ключом: %v", err)
	}
	if _, err := l.Archive(ctx, ArchiveOptions{Out: &again, ArchiveName: "x", Signer: otherS, Verifier: v, By: archiveActor}); err == nil {
		t.Fatal("принят ключ подписи не в паре с открытым ключом")
	}

	// Выгрузка (РСБ.5): все хранимые записи, журнал не меняется.
	var exp bytes.Buffer
	n, err := l.Export(ctx, ExportOptions{Out: &exp, By: archiveActor})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(exp.String(), "\n"), "\n")
	if int64(len(lines)) != n+1 || !strings.Contains(lines[0], `"format":"aisec-audit-export"`) || !strings.Contains(lines[0], `"from_seq":6`) {
		t.Fatalf("выгрузка: %d записей, %d строк, заголовок %s", n, len(lines), lines[0])
	}
	var exports int64
	if err := env.owner.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'audit.export'").Scan(&exports); err != nil || exports != 1 {
		t.Fatalf("запись audit.export: %d %v", exports, err)
	}
	if _, err := l.Export(ctx, ExportOptions{Out: &exp, From: time.Now(), To: time.Now().Add(-time.Hour)}); err == nil {
		t.Fatal("принят пустой период")
	}
}

// Граница -before: архивируются только записи старше неё, и она не бывает
// ближе срока хранения.
func TestArchiveBeforePostgres(t *testing.T) {
	_, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	var out syncBuffer
	if _, err := l.Archive(ctx, ArchiveOptions{Before: time.Now().AddDate(-3, 0, 0), Out: &out, ArchiveName: "a", Signer: s, Verifier: v}); !errors.Is(err, ErrNothingToArchive) {
		t.Fatalf("граница раньше всех записей: %v", err)
	}
	res, err := l.Archive(ctx, ArchiveOptions{Before: time.Now().AddDate(1, 0, 0), Out: &out, ArchiveName: "a", Signer: s, Verifier: v, By: archiveActor})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checkpoint.Seq != 5 || res.Cutoff.After(time.Now().AddDate(0, 0, -DefaultRetentionDays+1)) {
		t.Fatalf("граница ближе срока хранения: точка %d, граница %v", res.Checkpoint.Seq, res.Cutoff)
	}
}

// Подмена контрольной точки в БД (в обход триггеров — как у владельца СУБД)
// обнаруживается проверкой: с открытым ключом — по подписи, без него — по
// разрыву с первой хранимой записью.
func TestCheckpointTamperedPostgres(t *testing.T) {
	env, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	var out syncBuffer
	if _, err := l.Archive(ctx, ArchiveOptions{Out: &out, ArchiveName: "a", Signer: s, Verifier: v, By: archiveActor}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_no_update",
		"UPDATE audit_checkpoints SET hash = '\\x" + hex.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "'",
		"ALTER TABLE audit_checkpoints ENABLE TRIGGER audit_checkpoints_no_update",
	} {
		if _, err := env.owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if r := verify(t, NewVerifier(l)); r.OK() || r.Break.Reason != ReasonCheckpoint {
		t.Fatalf("с ключом: %+v", r.Break)
	}
	if r := verify(t, NewVerifier(archiveLog(t, env.app, nil))); r.OK() {
		t.Fatal("без ключа подмена не обнаружена")
	}
}

// Права: точки только добавляются и только архиватором; роль приложения не
// становится архиватором и не удаляет записи.
func TestCheckpointPrivilegesPostgres(t *testing.T) {
	env, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	var out syncBuffer
	if _, err := l.Archive(ctx, ArchiveOptions{Out: &out, ArchiveName: "a", Signer: s, Verifier: v, By: archiveActor}); err != nil {
		t.Fatal(err)
	}
	try := func(role, q string) error {
		tx, err := env.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: тест откатывает всё
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, q)
		return err
	}
	for _, c := range []struct{ role, q string }{
		{"aisec_app", "INSERT INTO audit_checkpoints SELECT * FROM audit_checkpoints"},
		{"aisec_app", "DELETE FROM audit_log"},
		{"aisec_audit_archiver", "UPDATE audit_checkpoints SET archive_name = 'x'"},
		{"aisec_audit_archiver", "DELETE FROM audit_checkpoints"},
		{"aisec_audit_archiver", "TRUNCATE audit_checkpoints"},
		{"aisec_audit_archiver", "UPDATE audit_log SET actor_name = 'x'"},
	} {
		if err := try(c.role, c.q); sqlState(err) != "42501" {
			t.Errorf("%s под %s: %v", c.q, c.role, err)
		}
	}
	if err := try("aisec_app", "SELECT count(*) FROM audit_checkpoints"); err != nil {
		t.Errorf("чтение точек ролью приложения: %v", err)
	}
	// Роль приложения не член aisec_audit_archiver.
	var member bool
	if err := env.owner.QueryRow(ctx, "SELECT pg_has_role('aisec_app', 'aisec_audit_archiver', 'MEMBER')").Scan(&member); err != nil || member {
		t.Fatalf("aisec_app — член архиватора: %v %v", member, err)
	}
}

// Пустой журнал без точек принимает только первую запись цепочки.
func TestLinkTriggerEmptyLogPostgres(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	insert := `INSERT INTO audit_log (seq, id, org_id, ts, actor_type, actor_id, actor_name, action,
		object_type, object_id, result, details, hash_alg, prev_hash, hash)
		VALUES ($1, '0192f3a0-0000-7000-8000-0000000000ff', $2, now(), 'user', 'u', 'u', 'auth.login',
		'', '', 'success', '{}', 'SHA-256', $3, $3)`
	for name, args := range map[string][]any{
		"номер не 1":     {int64(7), DefaultOrgID, make([]byte, 32)},
		"ненулевой prev": {int64(1), DefaultOrgID, bytes.Repeat([]byte{1}, 32)},
	} {
		if _, err := env.app.Exec(ctx, insert, args...); err == nil {
			t.Errorf("%s: вставка принята", name)
		}
	}
	record(t, env.log, 1)
	if r := verify(t, NewVerifier(env.log)); !r.OK() {
		t.Fatalf("%+v", r.Break)
	}
}

// Точку, не соответствующую журналу, не вставить и архиватору; удалить
// запись без точки нельзя. Точка с верной связью, но поддельной подписью
// видна при проверке открытым ключом (сервер с -audit-signing-pub,
// aisec-cli audit verify -keys).
func TestCheckpointInsertGuardPostgres(t *testing.T) {
	env, l, _, v := archiveSetup(t)
	ctx := ctxT(t)
	var h5, h7 []byte
	if err := env.owner.QueryRow(ctx, "SELECT hash FROM audit_log WHERE seq = 5").Scan(&h5); err != nil {
		t.Fatal(err)
	}
	if err := env.owner.QueryRow(ctx, "SELECT hash FROM audit_log WHERE seq = 7").Scan(&h7); err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 32)
	insert := `INSERT INTO audit_checkpoints (id, org_id, seq, hash, hash_alg, prev_seq, prev_hash, records,
		archive_name, archive_hash, created_at, sig_alg, signature, public_key)
		VALUES ('0192f3a0-0000-7000-8000-0000000000c1', $1, $2, $3, 'SHA-256', $4, $5, $6, 'x', $7, now(), 'Ed25519', $7, $7)`
	asArchiver := func(fn func(tx pgx.Tx) error) error {
		tx, err := env.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE aisec_audit_archiver"); err != nil {
			t.Fatal(err)
		}
		if err := fn(tx); err != nil {
			_ = tx.Rollback(ctx) //nolint:gosec // G104: откат после ожидаемой ошибки
			return err
		}
		return tx.Commit(ctx)
	}
	for name, args := range map[string][]any{
		"нет такой записи":         {DefaultOrgID, int64(5), zero, int64(0), zero, int64(5), zero},
		"не от нулевой точки":      {DefaultOrgID, int64(5), h5, int64(1), zero, int64(4), zero},
		"последняя запись журнала": {DefaultOrgID, int64(7), h7, int64(0), zero, int64(7), zero},
	} {
		if err := asArchiver(func(tx pgx.Tx) error { _, err := tx.Exec(ctx, insert, args...); return err }); err == nil {
			t.Errorf("%s: точка принята", name)
		}
	}
	if err := asArchiver(func(tx pgx.Tx) error { _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE seq = 1"); return err }); sqlState(err) != "42501" {
		t.Fatalf("удаление без точки: %v", err)
	}
	// Точка с верной связью и поддельной подписью, затем удаление.
	if err := asArchiver(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, insert, DefaultOrgID, int64(5), h5, int64(0), zero, int64(5), zero); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE seq = 6"); sqlState(err) != "42501" {
			t.Errorf("удаление за пределами точки: %v", err)
		}
		return nil
	}); err == nil {
		t.Fatal("транзакция с запрещённым удалением зафиксирована")
	}
	if err := asArchiver(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, insert, DefaultOrgID, int64(5), h5, int64(0), zero, int64(5), zero); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM audit_log WHERE seq <= 5")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := verify(t, NewVerifier(l)); r.OK() || r.Break.Reason != ReasonCheckpoint {
		t.Fatalf("поддельная подпись с ключом: %+v", r.Break)
	}
	if r := verify(t, NewVerifier(archiveLog(t, env.app, v))); r.OK() || r.Break.Reason != ReasonCheckpoint {
		t.Fatalf("поддельная подпись, роль сервера с ключом: %+v", r.Break)
	}
}

// После точки журнал не бывает пустым: удаление всех записей после неё
// (в обход триггеров) — нарушение. Exists ждёт архивацию и видит точку.
func TestCheckpointTailPostgres(t *testing.T) {
	env, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	var out syncBuffer
	res, err := l.Archive(ctx, ArchiveOptions{Out: &out, ArchiveName: "a", Signer: s, Verifier: v, By: archiveActor})
	if err != nil {
		t.Fatal(err)
	}
	cps, err := NewPGCheckpoints(env.owner, provider(t), v)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cps.Exists(ctx, res.Checkpoint.ID); err != nil || !ok {
		t.Fatalf("Exists: %v %v", ok, err)
	}
	if ok, err := cps.Exists(ctx, "0192f3a0-0000-7000-8000-0000000000ee"); err != nil || ok {
		t.Fatalf("Exists чужой точки: %v %v", ok, err)
	}
	for _, q := range []string{
		"ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_delete",
		"DELETE FROM audit_log",
		"ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_delete",
	} {
		if _, err := env.owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Новый Verifier, а журнал проверок записей не видит: нарушение
	// находит правило «после точки есть записи».
	if r := verify(t, NewVerifier(archiveLog(t, env.app, v))); r.OK() || r.Break.Reason != ReasonTailTruncated {
		t.Fatalf("пустой журнал после точки: %+v", r.Break)
	}
}

// staleCheckpoints при первом вызове отдаёт точку, прочитанную до
// архивации, — как проверка, которую архивация обогнала.
type staleCheckpoints struct {
	Checkpoints
	calls int
	stale Anchor
}

func (s *staleCheckpoints) Latest(ctx context.Context) (Anchor, bool, error) {
	s.calls++
	if s.calls == 1 {
		return s.stale, s.stale.Seq > 0, nil
	}
	return s.Checkpoints.Latest(ctx)
}

// Архивация между чтением точки и записей не даёт ложного нарушения:
// проверка видит новую точку и проходит заново.
func TestVerifyRacesArchivePostgres(t *testing.T) {
	env, l, s, v := archiveSetup(t)
	ctx := ctxT(t)
	var out syncBuffer
	if _, err := l.Archive(ctx, ArchiveOptions{Out: &out, ArchiveName: "a", Signer: s, Verifier: v, By: archiveActor}); err != nil {
		t.Fatal(err)
	}
	cps, err := NewPGCheckpoints(env.app, provider(t), v)
	if err != nil {
		t.Fatal(err)
	}
	sc := &staleCheckpoints{Checkpoints: cps, stale: Anchor{Seq: 0, Hash: genesis(hasher(t))}}
	lg, err := New(env.app, provider(t), WithCheckpoints(sc))
	if err != nil {
		t.Fatal(err)
	}
	if r := verify(t, NewVerifier(lg)); !r.OK() || sc.calls != 2 {
		t.Fatalf("ложное нарушение после архивации: %+v, вызовов %d", r.Break, sc.calls)
	}
}
