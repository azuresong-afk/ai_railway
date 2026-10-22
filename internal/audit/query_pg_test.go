package audit

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Выборка для консоли (задача 2.4a) на настоящем SQL: фильтры, группы
// кодов с «_», курсор и порядок от новых к старым.
func TestListPostgres(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	entries := []Entry{
		{Actor: Actor{Type: ActorUser, ID: "u-1", Name: "admin"}, SourceIP: netip.MustParseAddr("192.0.2.1"), Action: "auth.login", Result: ResultSuccess},
		{Actor: Actor{Type: ActorUser, ID: "u-2", Name: "auditor"}, Action: "auth.login_failed", Result: ResultFailure},
		{Actor: Actor{Type: ActorAPIToken, ID: "t-1", Name: "admin (aisec_pat_x)"}, Action: "api_token.used", Result: ResultSuccess},
		{Actor: Actor{Type: ActorUser, ID: "u-1", Name: "admin"}, Action: "user.create", Object: Object{Type: "user", ID: "u-3"}, Result: ResultSuccess},
		{Actor: Actor{Type: ActorUser, ID: "u-2", Name: "auditor"}, Action: "access.denied", Result: ResultDenied},
		// «apiXtoken.used» совпал бы с группой «api_token» через LIKE.
		{Actor: Actor{Type: ActorSystem, ID: "server", Name: "server"}, Action: "audit.chain_verified", Result: ResultSuccess},
	}
	for _, e := range entries {
		if err := env.log.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	base := Query{From: now.Add(-time.Hour), To: now.Add(time.Minute), Limit: 100}
	seqs := func(q Query) []int64 {
		t.Helper()
		rs, err := env.log.List(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		out := []int64{}
		for _, r := range rs {
			out = append(out, r.Seq)
		}
		return out
	}
	eq := func(name string, got []int64, want ...int64) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: %v, ожидалось %v", name, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s: %v, ожидалось %v", name, got, want)
				return
			}
		}
	}
	eq("все", seqs(base), 6, 5, 4, 3, 2, 1)
	q := base
	q.Groups = []string{"auth"}
	eq("группа auth", seqs(q), 2, 1)
	q.Actions = []string{"user.create"}
	eq("группа и код", seqs(q), 4, 2, 1)
	q = base
	q.Actor = "auditor"
	eq("субъект по имени", seqs(q), 5, 2)
	q.Actor = "u-1"
	eq("субъект по ID", seqs(q), 4, 1)
	q = base
	q.ActorType = ActorAPIToken
	eq("тип субъекта", seqs(q), 3)
	q = base
	q.Result = ResultDenied
	eq("результат", seqs(q), 5)
	q = base
	q.ObjectType, q.ObjectID = "user", "u-3"
	eq("объект", seqs(q), 4)
	q = base
	q.Actor = "x' OR '1'='1"
	eq("SQL в значении", seqs(q))
	q = base
	q.Limit, q.BeforeSeq = 2, 4
	eq("курсор", seqs(q), 3, 2)
	q = base
	q.From, q.To = now.Add(-2*time.Hour), now.Add(-time.Hour)
	eq("другой период", seqs(q))

	rs, err := env.log.List(ctx, Query{From: base.From, To: base.To, Limit: 1, BeforeSeq: 2})
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	if r := rs[0]; r.Action != "auth.login" || r.Actor.Name != "admin" || r.SourceIP != netip.MustParseAddr("192.0.2.1") || len(r.Hash) == 0 || r.TS.IsZero() {
		t.Errorf("запись: %+v", r)
	}
	if _, err := env.log.List(ctx, Query{From: base.From, To: base.To}); !errors.Is(err, ErrBadQuery) {
		t.Errorf("выборка без limit: %v", err)
	}

	// Не конечное время, записанное в обход CHECK, не прячет запись из
	// просмотра: она видна в любом периоде с нулевым TS.
	tx, err := env.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"SET LOCAL session_replication_role = replica",
		"ALTER TABLE audit_log DROP CONSTRAINT audit_log_ts_check",
		"UPDATE audit_log SET ts = 'infinity' WHERE seq = 3"} {
		if _, err := tx.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	q = base
	q.From, q.To = now.Add(-2*time.Hour), now.Add(-time.Hour)
	rs, err = env.log.List(ctx, q)
	if err != nil || len(rs) != 1 || rs[0].Seq != 3 || !rs[0].TS.IsZero() {
		t.Errorf("запись с бесконечным временем: %+v, %v", rs, err)
	}
}

// Проверка по команде не ждёт идущую проверку и не идёт параллельно с ней
// (задача 2.4a); адрес субъекта попадает в запись audit.chain_*.
func TestTryVerifyPostgres(t *testing.T) {
	env := setupDB(t)
	ctx := ctxT(t)
	record(t, env.log, 3)
	v := NewVerifier(env.log)
	v.mu.Lock()
	if _, err := v.TryVerifyBy(ctx, Actor{Type: ActorUser, ID: "u-1", Name: "auditor"}, netip.MustParseAddr("192.0.2.7")); !errors.Is(err, ErrVerifyBusy) {
		t.Errorf("при идущей проверке: %v", err)
	}
	v.mu.Unlock()
	res, err := v.TryVerifyBy(ctx, Actor{Type: ActorUser, ID: "u-1", Name: "auditor"}, netip.MustParseAddr("192.0.2.7"))
	if err != nil || !res.OK() || res.Checked != 3 {
		t.Fatalf("проверка: %+v, %v", res, err)
	}
	var ip, actor string
	if err := env.app.QueryRow(ctx, `SELECT host(source_ip), actor_name FROM audit_log
		WHERE action = 'audit.chain_verified' ORDER BY seq DESC LIMIT 1`).Scan(&ip, &actor); err != nil {
		t.Fatal(err)
	}
	if ip != "192.0.2.7" || actor != "auditor" {
		t.Errorf("запись проверки: %s %s", ip, actor)
	}
	// Подмена в обход продукта — разрыв по команде (как DM-43 через API).
	tx, err := env.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE audit_log SET actor_name = 'mallory' WHERE seq = 2"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res, err = v.TryVerifyBy(ctx, Actor{Type: ActorUser, ID: "u-1", Name: "auditor"}, netip.Addr{})
	if err != nil || res.OK() || res.Break.Seq != 2 || res.Break.Reason != ReasonHashMismatch {
		t.Errorf("после подмены: %+v, %v", res, err)
	}
}
