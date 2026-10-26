package notify_test

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// siemReceiver — приёмник syslog по TLS (RFC 5425, octet counting) на
// 127.0.0.1 внутри теста; останавливается и запускается на том же адресе.
type siemReceiver struct {
	t       *testing.T
	listen  func() (net.Listener, error)
	addr    string
	mu      sync.Mutex
	l       net.Listener
	records chan string
}

func newSIEMReceiver(t *testing.T, tp aisecCrypto.TLSProvider, cert, key []byte) *siemReceiver {
	t.Helper()
	cfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	r := &siemReceiver{t: t, records: make(chan string, 1024), addr: "127.0.0.1:0"}
	r.listen = func() (net.Listener, error) {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", r.addr)
		if err != nil {
			return nil, err
		}
		r.addr = l.Addr().String()
		return aisecCrypto.TLSListener(l, cfg), nil
	}
	r.start()
	t.Cleanup(r.stop)
	return r
}

func (r *siemReceiver) start() {
	r.t.Helper()
	l, err := r.listen()
	if err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	r.l = l
	r.mu.Unlock()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()
}

func (r *siemReceiver) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()                    //nolint:gosec // G104: закрытие тестового приёмника
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:gosec // G104: срок соединения тестового приёмника
	br := bufio.NewReader(conn)
	for {
		n, err := br.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSuffix(n, " "))
		if err != nil || size <= 0 || size > 1<<20 {
			r.records <- "BAD FRAME"
			return
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		r.records <- string(buf)
	}
}

func (r *siemReceiver) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.l != nil {
		_ = r.l.Close() //nolint:gosec // G104: закрытие тестового приёмника
		r.l = nil
	}
}

func (r *siemReceiver) hostPort() (string, int) {
	h, p, _ := net.SplitHostPort(r.addr) //nolint:gosec // G104: адрес тестового приёмника корректен
	n, _ := strconv.Atoi(p)              //nolint:gosec // G104: адрес тестового приёмника корректен
	return h, n
}

// siemRecord — запись журнала из сообщения syslog (MSGID audit, тело JSON):
// каноническая форма и хеш.
type siemRecord struct {
	Seq      int64
	Action   string
	PrevHash string
	Hash     string
	raw      []byte
}

func (r *siemReceiver) next(t *testing.T) siemRecord {
	t.Helper()
	select {
	case rec := <-r.records:
		const marker = " aisec - audit - "
		i := strings.Index(rec, marker)
		var msg struct {
			Record json.RawMessage `json:"record"`
			Hash   string          `json:"hash"`
		}
		var c struct {
			Seq    int64  `json:"seq"`
			Action string `json:"action"`
			Prev   string `json:"prev"`
		}
		if i < 0 || json.Unmarshal([]byte(rec[i+len(marker):]), &msg) != nil || json.Unmarshal(msg.Record, &c) != nil {
			t.Fatalf("сообщение syslog: %q", rec)
		}
		return siemRecord{Seq: c.Seq, Action: c.Action, PrevHash: c.Prev, Hash: msg.Hash, raw: msg.Record}
	case <-time.After(10 * time.Second):
		t.Fatal("syslog: запись не пришла")
		return siemRecord{}
	}
}

// Передача журнала аудита в SIEM на PostgreSQL по TLS (РСБ.6, задача 3.14):
// порядок и непрерывность seq с цепочкой хешей, недоступность приёмника
// без потерь, отставание поднимает system.alert и оповещение DM-44, догон
// после восстановления, курсор не берут два экземпляра, права роли сервера.
func TestPGAuditStreamSIEM(t *testing.T) {
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(rnd, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "ns_test_" + hex.EncodeToString(b)
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
	dir, _ := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	alStore, err := alerting.NewPGStore(app, log, rnd, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := alerting.New(alerting.Options{Store: alStore, Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.EnsureBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	log.SetRecordHook(alStore.OnAudit)
	st, err := notify.NewPGStore(app, log, rnd, "")
	if err != nil {
		t.Fatal(err)
	}
	// Новое оповещение ставится в очередь доставки той же транзакцией.
	alStore.SetEnqueue(st.EnqueueAlertTx)
	tr, err := notify.NewTransport(p, "test", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Приёмники тестов слушают loopback: сеть разрешена явно (3Н31 ревью 3.r2).
	tr.AllowNetworks(loopbackNets)
	svc, err := notify.New(notify.Options{Store: st, Box: box, Provider: p, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	siem := newSIEMReceiver(t, tp, cert, key)
	host, port := siem.hostPort()
	by := notify.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000b1", Name: "admin"},
		Confirm: func(context.Context) error { return nil }}
	login := func(n int) {
		for range n {
			if err := log.Record(ctx, audit.Entry{OrgID: audit.DefaultOrgID, Actor: by.Actor, Action: "auth.login",
				Object: audit.Object{Type: "user", ID: by.Actor.ID}, Result: audit.ResultSuccess,
				Details: map[string]any{"method": "password"}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	login(3)
	c, err := svc.CreateChannel(ctx, by, notify.ChannelInput{Name: "SIEM", Type: notify.TypeSyslog, AuditStream: ptr(true),
		Settings: notify.Settings{Host: host, Port: port, Format: notify.FormatJSON, CAPEM: string(ca.CertPEM())}})
	if err != nil {
		t.Fatal(err)
	}
	status := func() notify.StreamStatus {
		t.Helper()
		s, err := svc.StreamStatus(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Передача с момента подписки: первая — запись о создании канала.
	s0 := status()
	if !s0.Active || s0.Backlog.Pending != 1 || s0.Cursor.LastSeq != s0.Backlog.Head-1 {
		t.Fatalf("подписка: %+v", s0)
	}
	login(4)
	if n, err := svc.StreamAuditOnce(ctx); err != nil || n != 5 {
		t.Fatalf("передача: %d %v", n, err)
	}
	var last siemRecord
	for i := range 5 {
		r := siem.next(t)
		if r.Seq != s0.Cursor.LastSeq+int64(i)+1 || (i > 0 && r.PrevHash != last.Hash) {
			t.Fatalf("порядок или цепочка: %+v после %+v", r, last)
		}
		if (i == 0 && r.Action != "notify_channel.create") || (i > 0 && r.Action != "auth.login") {
			t.Fatalf("запись %d: %s", i, r.Action)
		}
		last = r
	}
	// SIEM проверяет запись сам: хеш профиля от канонической формы.
	var dbHash []byte
	if err := owner.QueryRow(ctx, `SELECT hash FROM audit_log WHERE seq = $1`, last.Seq).Scan(&dbHash); err != nil ||
		hex.EncodeToString(dbHash) != last.Hash || hex.EncodeToString(h.Sum(last.raw)) != last.Hash {
		t.Fatalf("хеш записи: %v", err)
	}

	// Приёмник недоступен: ошибка в курсоре, записи остаются в журнале.
	siem.stop()
	login(2)
	if n, err := svc.StreamAuditOnce(ctx); err != nil || n != 0 {
		t.Fatalf("передача без приёмника: %d %v", n, err)
	}
	s1 := status()
	if s1.Cursor.LastSeq != last.Seq || s1.Cursor.Attempts != 1 || s1.Cursor.Error != notify.ErrCodeDial || s1.Backlog.Pending != 2 ||
		s1.Lagging {
		t.Fatalf("после отказа: %+v", s1)
	}

	// Отставание дольше 15 минут: system.alert и оповещение DM-44 в
	// очереди доставки; повторный проход условие не дублирует.
	later, err := notify.New(notify.Options{Store: st, Box: box, Provider: p, Transport: tr,
		Now: func() time.Time { return time.Now().Add(notify.StreamLagAge + time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := later.StreamAuditOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cond := "audit_stream_lag:" + c.ID
	var raised, cleared int
	countLag := func() {
		t.Helper()
		if err := owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE details->>'state' = 'raised'),
			count(*) FILTER (WHERE details->>'state' = 'cleared') FROM audit_log
			WHERE action = 'system.alert' AND object_id = $1 AND details->>'requirement' = 'РСБ.6'`, cond).Scan(&raised, &cleared); err != nil {
			t.Fatal(err)
		}
	}
	countLag()
	if raised != 1 || cleared != 0 {
		t.Fatalf("system.alert: возникло %d, снято %d", raised, cleared)
	}
	got, err := alerts.Alerts(ctx, alerting.AlertQuery{RuleID: builtinID(t, alerts, alerting.BuiltinAuditStream), Limit: 10})
	if err != nil || len(got) != 1 || got[0].Values["channel"] != "SIEM" {
		t.Fatalf("DM-44: %+v %v", got, err)
	}
	var queued int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM alert_deliveries WHERE alert_id = $1`, got[0].ID).Scan(&queued); err != nil ||
		queued != 1 {
		t.Fatalf("оповещение не в очереди доставки: %d %v", queued, err)
	}

	// Приёмник восстановлен: догон без потерь, отставание снято.
	siem.start()
	if _, err := owner.Exec(ctx, `UPDATE audit_stream_cursors SET next_at = now() - interval '1 second' WHERE channel_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	pending := status().Backlog.Pending
	if n, err := svc.StreamAuditOnce(ctx); err != nil || int64(n) != pending {
		t.Fatalf("догон: %d из %d %v", n, pending, err)
	}
	for range pending {
		r := siem.next(t)
		if r.Seq != last.Seq+1 || r.PrevHash != last.Hash || hex.EncodeToString(h.Sum(r.raw)) != r.Hash {
			t.Fatalf("разрыв при догоне: %+v после %+v", r, last)
		}
		last = r
	}
	countLag()
	if s := status(); raised != 1 || cleared != 1 || s.Cursor.Attempts != 0 || s.Cursor.Error != "" || s.Cursor.LagRaised {
		t.Fatalf("после догона: возникло %d, снято %d, %+v", raised, cleared, s)
	}

	// Курсор берёт один экземпляр: второй ждёт lease.
	if _, err := owner.Exec(ctx, `UPDATE audit_stream_cursors SET next_at = now() - interval '1 second' WHERE channel_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.ClaimStream(ctx, c.ID, time.Minute); err != nil || !ok {
		t.Fatalf("захват: %v %v", ok, err)
	}
	if _, ok, err := st.ClaimStream(ctx, c.ID, time.Minute); err != nil || ok {
		t.Fatalf("повторный захват: %v %v", ok, err)
	}

	// Отсрочка истекла: курсор взял второй экземпляр и сдвинул; итог первого
	// (сдвиг дальше, запись о разрыве) не сохраняется.
	login(2)
	past := func() {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE audit_stream_cursors SET next_at = now() - interval '1 second' WHERE channel_id = $1`, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	past()
	a, ok, err := st.ClaimStream(ctx, c.ID, time.Minute)
	if err != nil || !ok {
		t.Fatalf("захват A: %v %v", ok, err)
	}
	past()
	b2, ok, err := st.ClaimStream(ctx, c.ID, time.Minute)
	if err != nil || !ok {
		t.Fatalf("захват B: %v %v", ok, err)
	}
	prev := a.LastSeq
	b2.LastSeq, b2.UpdatedAt, b2.NextAt = prev+1, time.Now(), time.Now()
	if err := st.FinishStream(ctx, prev, b2, nil); err != nil {
		t.Fatal(err)
	}
	a.LastSeq, a.UpdatedAt, a.NextAt = prev+2, time.Now(), time.Now()
	stale := audit.Entry{OrgID: audit.DefaultOrgID, Actor: by.Actor, Action: "notify.audit_stream_gap",
		Object: audit.Object{Type: "notify_channel", ID: c.ID}, Result: audit.ResultFailure, Details: map[string]any{"reason": "stale_test"}}
	if err := st.FinishStream(ctx, prev, a, []audit.Entry{stale}); err != nil {
		t.Fatal(err)
	}
	var staleN int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE details->>'reason' = 'stale_test'`).Scan(&staleN); err != nil ||
		staleN != 0 || status().Cursor.LastSeq != prev+1 {
		t.Fatalf("итог устаревшей попытки сохранён: %d %+v %v", staleN, status().Cursor, err)
	}

	// Курсор потерян (каналы восстановлены без курсоров): ставится на конец
	// журнала следующим проходом.
	if _, err := owner.Exec(ctx, `DELETE FROM audit_stream_cursors WHERE channel_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StreamAuditOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var lostN int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'notify.audit_stream_gap'
		AND object_id = $1 AND details->>'reason' = 'cursor_lost'`, c.ID).Scan(&lostN); err != nil || lostN != 1 {
		t.Fatalf("запись о потере курсора: %d %v", lostN, err)
	}
	// Курсор — на конце журнала до записи о потере: она передаётся первой.
	if s := status(); !s.Active || s.Cursor.LastSeq != s.Backlog.Head {
		t.Fatalf("курсор не восстановлен: %+v", s)
	}
	if r := siem.next(t); r.Action != "notify.audit_stream_gap" {
		t.Fatalf("после потери курсора: %+v", r)
	}

	// Снятие подписки — ослабление.
	cur, err := svc.Channel(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	noConfirm := by
	noConfirm.Confirm = nil
	if _, err := svc.UpdateChannel(ctx, noConfirm, c.ID, notify.ChannelInput{Name: cur.Name, Enabled: ptr(true), MinSeverity: cur.MinSeverity,
		AuditStream: ptr(false), Settings: cur.Settings, Version: cur.Version}); !errors.Is(err, notify.ErrConfirmRequired) {
		t.Fatalf("снятие подписки без проверки: %v", err)
	}

	// Роль сервера не переносит курсор в другую организацию или канал и не
	// удаляет его; подписка — только у syslog и webhook общего формата.
	for _, q := range []string{
		`UPDATE audit_stream_cursors SET org_id = org_id`,
		`UPDATE audit_stream_cursors SET channel_id = channel_id`,
		`DELETE FROM audit_stream_cursors`,
	} {
		_, err := app.Exec(ctx, q)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_, err = owner.Exec(ctx, `UPDATE notify_channels SET type = 'email' WHERE id = $1`, c.ID)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatalf("подписка канала почты: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
