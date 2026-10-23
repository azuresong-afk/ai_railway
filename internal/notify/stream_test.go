package notify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Передача журнала аудита в SIEM (РСБ.6, задача 3.14) на хранилище Memory:
// порядок, повторы без потерь, разрыв после архивации, отставание DM-44.

// journal добавляет n записей журнала с временем e.now, сцепленных
// хешами профиля, как в internal/audit.
func (e *env) journal(n int) {
	h, err := e.p.Hasher()
	if err != nil {
		panic(err)
	}
	for range n {
		e.ids++
		prev := e.lastHash
		if prev == nil {
			prev = make([]byte, h.New().Size())
		}
		r := audit.Record{Seq: e.mem.headSeq() + 1, ID: fmt.Sprintf("01900000-0000-7000-8000-%012d", e.ids),
			OrgID: audit.DefaultOrgID, TS: e.now, Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "ivanova"},
			SourceIP: netip.MustParseAddr("192.0.2.10"), Action: "auth.login", Object: audit.Object{Type: "user", ID: "u1"},
			Result: audit.ResultSuccess, Details: json.RawMessage(`{"method":"password"}`), HashAlg: "test", PrevHash: prev}
		if r.Hash, err = r.ComputeHash(h); err != nil {
			panic(err)
		}
		e.lastHash = r.Hash
		e.mem.AddAudit(r)
	}
}

// canonical — поля канонической формы записи журнала, нужные тестам.
type canonical struct {
	Seq     int64           `json:"seq"`
	Action  string          `json:"action"`
	IP      string          `json:"ip"`
	Details json.RawMessage `json:"details"`
	Alg     string          `json:"alg"`
	Prev    string          `json:"prev"`
}

// checkSIEM проверяет запись так, как это сделает SIEM: хеш профиля от
// байтов record совпадает с hash.
func (e *env) checkSIEM(t *testing.T, rec siemRecord) canonical {
	t.Helper()
	h, err := e.p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	var c canonical
	if err := json.Unmarshal(rec.Record, &c); err != nil {
		t.Fatalf("record: %s %v", rec.Record, err)
	}
	if hex.EncodeToString(h.Sum(rec.Record)) != rec.Hash {
		t.Fatalf("хеш записи %d не сходится: %s", c.Seq, rec.Record)
	}
	if c.Action != "auth.login" || c.IP != "192.0.2.10" || c.Alg != "test" || string(c.Details) != `{"method":"password"}` {
		t.Fatalf("запись: %s", rec.Record)
	}
	return c
}

func (s *syslogServer) host() string { h, _ := hostPortStr(s.addr); return h }
func (s *syslogServer) port() int    { _, p := hostPortStr(s.addr); return p }

// deadAddr — адрес 127.0.0.1, на котором никто не слушает.
func deadAddr(t *testing.T) (string, int) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(testCtx(t), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return hostPortStr(addr)
}

func (e *env) siemChannel(t *testing.T, host string, port int, format string) Channel {
	t.Helper()
	c, err := e.svc.CreateChannel(testCtx(t), e.by, ChannelInput{Name: "SIEM " + format, Type: TypeSyslog, AuditStream: ptr(true),
		Settings: Settings{Host: host, Port: port, Format: format, CAPEM: e.caPEM}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) streamOnce(t *testing.T) int {
	t.Helper()
	n, err := e.svc.StreamAuditOnce(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) streamStatus(t *testing.T, id string) StreamStatus {
	t.Helper()
	st, err := e.svc.StreamStatus(testCtx(t), id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// auditSeq — seq записи журнала из сообщения syslog (тело JSON) после
// проверки хеша.
func (e *env) auditSeq(t *testing.T, rec string) int64 {
	t.Helper()
	prefix := "aisec-server aisec - audit - "
	i := strings.Index(rec, prefix)
	if i < 0 {
		t.Fatalf("заголовок RFC 5424: %q", rec)
	}
	var got siemMessage
	if err := json.Unmarshal([]byte(rec[i+len(prefix):]), &got); err != nil {
		t.Fatalf("JSON: %q %v", rec, err)
	}
	if got.Product != "AISec" || got.Type != "audit" || got.Version != "1.2.3" {
		t.Fatalf("сообщение: %q", rec)
	}
	return e.checkSIEM(t, got.siemRecord).Seq
}

// Syslog: передача с конца журнала на момент подписки, по порядку seq;
// недоступный приёмник — повторы с задержкой, записи не теряются; догон
// пакетами больше одного.
func TestAuditStreamSyslog(t *testing.T) {
	e := newEnv(t)
	e.journal(2)
	h, p := deadAddr(t)
	c := e.siemChannel(t, h, p, FormatJSON)
	if st := e.streamStatus(t, c.ID); !st.Active || st.Cursor.LastSeq != 2 || st.Backlog.Pending != 0 {
		t.Fatalf("подписка: %+v", st)
	}
	e.journal(3)
	if n := e.streamOnce(t); n != 0 {
		t.Fatalf("передано на недоступный приёмник: %d", n)
	}
	st := e.streamStatus(t, c.ID)
	if st.Cursor.LastSeq != 2 || st.Cursor.Attempts != 1 || st.Cursor.Error != ErrCodeDial || !st.Cursor.NextAt.Equal(e.now.Add(Backoff(1))) ||
		st.Backlog.Pending != 3 {
		t.Fatalf("после отказа: %+v", st)
	}
	// До срока повтора канал не берётся.
	e.streamOnce(t)
	if st := e.streamStatus(t, c.ID); st.Cursor.Attempts != 1 {
		t.Fatalf("повтор раньше срока: %+v", st)
	}
	e.now = e.now.Add(Backoff(1))
	e.streamOnce(t)
	if st := e.streamStatus(t, c.ID); st.Cursor.Attempts != 2 || !st.Cursor.NextAt.Equal(e.now.Add(Backoff(2))) {
		t.Fatalf("второй отказ: %+v", st)
	}

	// Приёмник восстановлен: догон без потерь и по порядку.
	srv := newSyslogServer(t, e.tp, e.cert, e.key)
	h, p = hostPortStr(srv.addr)
	cur, err := e.svc.Channel(testCtx(t), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateChannel(testCtx(t), e.by, c.ID, ChannelInput{Name: cur.Name, Enabled: ptr(true), MinSeverity: cur.MinSeverity,
		Settings: Settings{Host: h, Port: p, Format: FormatJSON, CAPEM: e.caPEM}, Version: cur.Version}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(maxBackoff)
	if n := e.streamOnce(t); n != 3 {
		t.Fatalf("догон: %d", n)
	}
	for want := int64(3); want <= 5; want++ {
		if got := e.auditSeq(t, srv.next(t)); got != want {
			t.Fatalf("порядок: seq %d вместо %d", got, want)
		}
	}
	st = e.streamStatus(t, c.ID)
	if st.Cursor.LastSeq != 5 || st.Cursor.Attempts != 0 || st.Cursor.Error != "" || !st.Cursor.SentAt.Equal(e.now) ||
		st.Backlog.Pending != 0 || st.Lagging {
		t.Fatalf("после догона: %+v", st)
	}

	// Больше одного пакета за проход: записи идут подряд.
	total := streamBatch + 50
	e.journal(total)
	done := make(chan int, 1)
	go func() {
		n, _ := e.svc.StreamAuditOnce(testCtx(t)) //nolint:gosec // G104: число записей проверяется ниже
		done <- n
	}()
	// Пакеты идут разными соединениями одно за другим; приёмник читает
	// соединения параллельно, поэтому порядок проверяется внутри пакета, а
	// между пакетами — полнота без повторов (SIEM упорядочивает по seq).
	seen := map[int64]bool{}
	prev := map[bool]int64{}
	for range total {
		got := e.auditSeq(t, srv.next(t))
		first := got < int64(6+streamBatch)
		if seen[got] || got < 6 || got >= int64(6+total) || (prev[first] != 0 && got != prev[first]+1) {
			t.Fatalf("seq %d: повтор, чужая запись или нарушен порядок пакета", got)
		}
		seen[got], prev[first] = true, got
	}
	if n := <-done; n != total {
		t.Fatalf("передано %d из %d", n, total)
	}
}

// Webhook (общий формат): пакет записей одним подписанным запросом; ответ
// не 2xx — повтор того же пакета.
func TestAuditStreamWebhook(t *testing.T) {
	e := newEnv(t)
	e.tr.now = func() time.Time { return e.now }
	ws := newWebhookServer(t, e.tp, e.cert, e.key)
	c, err := e.svc.CreateChannel(testCtx(t), e.by, ChannelInput{Name: "SIEM HTTP", Type: TypeWebhook, AuditStream: ptr(true),
		Settings: Settings{Format: FormatGeneric, CAPEM: e.caPEM},
		Secrets:  SecretsInput{URL: ptr(ws.srv.URL + "/siem/secret-token"), SigningKey: ptr(testSigningKey)}})
	if err != nil {
		t.Fatal(err)
	}
	e.journal(3)
	ws.setStatus(500)
	if n := e.streamOnce(t); n != 0 {
		t.Fatalf("передано при ответе 500: %d", n)
	}
	if st := e.streamStatus(t, c.ID); st.Cursor.Error != "http_500" || st.Cursor.Attempts != 1 || st.Cursor.LastSeq != 0 {
		t.Fatalf("после отказа: %+v", st)
	}
	ws.setStatus(200)
	e.now = e.now.Add(Backoff(1))
	if n := e.streamOnce(t); n != 3 {
		t.Fatalf("повтор: %d", n)
	}
	bodies, sigs := ws.received()
	if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) {
		t.Fatalf("повтор не того же пакета: %d", len(bodies))
	}
	ts, mac, ok := strings.Cut(strings.TrimPrefix(sigs[1], "t="), ",v1=")
	if !ok || ts != strconv.FormatInt(e.now.Unix(), 10) {
		t.Fatalf("заголовок подписи: %q", sigs[1])
	}
	m, err := e.p.NewMAC([]byte(testSigningKey))
	if err != nil {
		t.Fatal(err)
	}
	tag, err := hex.DecodeString(mac)
	if err != nil || !m.Verify(append([]byte(ts+"."), bodies[1]...), tag) {
		t.Fatalf("подпись не сходится: %q", sigs[1])
	}
	var got struct {
		Product string       `json:"product"`
		Version string       `json:"version"`
		Type    string       `json:"type"`
		Records []siemRecord `json:"records"`
	}
	if err := json.Unmarshal(bodies[1], &got); err != nil {
		t.Fatal(err)
	}
	if got.Product != "AISec" || got.Version != "1.2.3" || got.Type != "audit" || len(got.Records) != 3 {
		t.Fatalf("тело: %+v", got)
	}
	prev := strings.Repeat("00", 32)
	for i, r := range got.Records {
		// Цепочка: prev записи — хеш предыдущей.
		if c := e.checkSIEM(t, r); c.Seq != int64(i+1) || c.Prev != prev {
			t.Fatalf("запись %d: %+v", i, c)
		}
		prev = r.Hash
	}
}

// Пакет webhook не больше 1 МиБ: лишние записи уходят следующим запросом,
// одна запись входит всегда.
func TestAuditBatchLimit(t *testing.T) {
	big := json.RawMessage(`{"x":"` + strings.Repeat("a", 300_000) + `"}`)
	recs := make([]audit.Record, 5)
	for i := range recs {
		recs[i] = audit.Record{Seq: int64(i + 1), Details: big}
	}
	body, n, err := auditBatch(recs, "1")
	if err != nil || n != 3 || len(body) > maxStreamBody || !json.Valid(body) {
		t.Fatalf("пакет: %d записей, %d байт, %v", n, len(body), err)
	}
	huge := []audit.Record{{Seq: 1, Details: json.RawMessage(`{"x":"` + strings.Repeat("a", maxStreamBody) + `"}`)}}
	if _, n, err := auditBatch(huge, "1"); err != nil || n != 1 {
		t.Fatalf("одна запись: %d %v", n, err)
	}
	// Недопустимые подробности не ломают тело.
	if body, _, err := auditBatch([]audit.Record{{Seq: 1, Details: json.RawMessage(`{`)}}, "1"); err != nil || !json.Valid(body) {
		t.Fatalf("подробности: %s %v", body, err)
	}
}

// Разрыв: записи между курсором и журналом удалены архивацией раньше, чем
// переданы, — запись notify.audit_stream_gap с диапазоном.
func TestAuditStreamGap(t *testing.T) {
	e := newEnv(t)
	srv := newSyslogServer(t, e.tp, e.cert, e.key)
	e.journal(2)
	c := e.siemChannel(t, srv.host(), srv.port(), FormatJSON)
	e.journal(3)
	e.mem.DropAudit(4)
	if n := e.streamOnce(t); n != 1 {
		t.Fatalf("передано: %d", n)
	}
	if got := e.auditSeq(t, srv.next(t)); got != 5 {
		t.Fatalf("seq %d", got)
	}
	var gap *audit.Entry
	for _, r := range e.mem.Audited() {
		if r.Action == "notify.audit_stream_gap" {
			gap = &r
		}
	}
	if gap == nil || gap.Object.ID != c.ID || gap.Result != audit.ResultFailure {
		t.Fatalf("нет записи о разрыве: %+v", gap)
	}
	d := gap.Details.(map[string]any)
	if d["from_seq"] != int64(3) || d["to_seq"] != int64(4) || d["channel_name"] != c.Name {
		t.Fatalf("разрыв: %v", d)
	}
}

// DM-44: отставание передачи (самая старая не переданная запись старше 15
// минут или больше 10 000 записей) пишет system.alert при возникновении и
// снятии, без повторов.
func TestDM44_AuditStreamLag(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		b    Backlog
		want bool
	}{
		{Backlog{}, false},
		{Backlog{Pending: StreamLagRecords, Oldest: now}, false},
		{Backlog{Pending: StreamLagRecords + 1, Oldest: now}, true},
		{Backlog{Pending: 1, Oldest: now.Add(-StreamLagAge)}, false},
		{Backlog{Pending: 1, Oldest: now.Add(-StreamLagAge - time.Second)}, true},
	} {
		if got := tc.b.lagging(now); got != tc.want {
			t.Fatalf("%+v: %v", tc.b, got)
		}
	}

	e := newEnv(t)
	h, p := deadAddr(t)
	c := e.siemChannel(t, h, p, FormatCEF)
	lagEntries := func() []audit.Entry {
		var out []audit.Entry
		for _, r := range e.mem.Audited() {
			if r.Action == "system.alert" && r.Object.ID == "audit_stream_lag:"+c.ID {
				out = append(out, r)
			}
		}
		return out
	}
	e.journal(1)
	e.streamOnce(t)
	if len(lagEntries()) != 0 || e.streamStatus(t, c.ID).Lagging {
		t.Fatal("отставание раньше порога")
	}
	e.now = e.now.Add(StreamLagAge + time.Minute)
	e.streamOnce(t)
	e.streamOnce(t)
	got := lagEntries()
	if len(got) != 1 || got[0].Result != audit.ResultFailure || got[0].Object.Type != "system" {
		t.Fatalf("возникновение: %+v", got)
	}
	d := got[0].Details.(map[string]any)
	if d["state"] != "raised" || d["requirement"] != "РСБ.6" || d["channel_name"] != c.Name || d["pending"] != int64(1) ||
		d["error"] != ErrCodeDial || d["oldest_pending_seconds"] != int64((StreamLagAge+time.Minute)/time.Second) {
		t.Fatalf("подробности: %v", d)
	}
	if st := e.streamStatus(t, c.ID); !st.Lagging || !st.Cursor.LagRaised {
		t.Fatalf("состояние: %+v", st)
	}

	srv := newSyslogServer(t, e.tp, e.cert, e.key)
	cur, err := e.svc.Channel(testCtx(t), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateChannel(testCtx(t), e.by, c.ID, ChannelInput{Name: cur.Name, Enabled: ptr(true), MinSeverity: cur.MinSeverity,
		Settings: Settings{Host: srv.host(), Port: srv.port(), Format: FormatCEF, CAPEM: e.caPEM}, Version: cur.Version}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(maxBackoff)
	if n := e.streamOnce(t); n != 1 {
		t.Fatalf("догон: %d", n)
	}
	if rec := srv.next(t); !strings.Contains(rec, " aisec - audit - CEF:0|AISec|AISec|1.2.3|auth.login|auth.login|3|") ||
		!strings.Contains(rec, "cs1=1") || !strings.Contains(rec, "src=192.0.2.10") {
		t.Fatalf("CEF: %q", rec)
	}
	got = lagEntries()
	if len(got) != 2 || got[1].Details.(map[string]any)["state"] != "cleared" || got[1].Result != audit.ResultSuccess {
		t.Fatalf("снятие: %+v", got)
	}
}

// Подписка — только syslog и webhook общего формата; снятие — ослабление
// (DM-40), повторная подписка начинает с конца журнала.
func TestAuditStreamChannelRules(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	in := e.emailInput("smtp.example.ru:587", "")
	in.AuditStream = ptr(true)
	var ie *InputError
	if _, err := e.svc.CreateChannel(ctx, e.by, in); !errors.As(err, &ie) || !strings.Contains(err.Error(), "audit_stream") {
		t.Fatalf("почта с подпиской: %v", err)
	}
	if _, err := e.svc.CreateChannel(ctx, e.by, ChannelInput{Name: "MM", Type: TypeWebhook, AuditStream: ptr(true),
		Settings: Settings{Format: FormatMattermost, CAPEM: e.caPEM},
		Secrets:  SecretsInput{URL: ptr("https://127.0.0.1:1/hooks/x"), SigningKey: ptr(testSigningKey)}}); !errors.As(err, &ie) {
		t.Fatalf("Mattermost с подпиской: %v", err)
	}

	e.journal(2)
	c := e.siemChannel(t, "127.0.0.1", 1, FormatJSON)
	upd := func(by By, stream *bool) (Channel, error) {
		cur, err := e.svc.Channel(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return e.svc.UpdateChannel(ctx, by, c.ID, ChannelInput{Name: cur.Name, Enabled: ptr(true), MinSeverity: cur.MinSeverity,
			AuditStream: stream, Settings: cur.Settings, Version: cur.Version})
	}
	noConfirm := e.by
	noConfirm.Confirm = nil
	// Не передано — прежнее значение, не ослабление.
	if got, err := upd(noConfirm, nil); err != nil || !got.AuditStream {
		t.Fatalf("без поля: %+v %v", got, err)
	}
	if _, err := upd(noConfirm, ptr(false)); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("снятие без проверки: %v", err)
	}
	if got, err := upd(e.by, ptr(false)); err != nil || got.AuditStream {
		t.Fatalf("снятие: %+v %v", got, err)
	}
	last := e.mem.Audited()[len(e.mem.Audited())-1]
	raw, _ := json.Marshal(last.Details) //nolint:gosec // G104: значение всегда сериализуется
	if !strings.Contains(string(raw), `"audit_stream_disabled"`) {
		t.Fatalf("аудит снятия: %s", raw)
	}
	if st := e.streamStatus(t, c.ID); st.Subscribed || st.Active {
		t.Fatalf("без подписки: %+v", st)
	}
	if chans, err := e.mem.StreamChannels(ctx); err != nil || len(chans) != 0 {
		t.Fatalf("каналы передачи: %d %v", len(chans), err)
	}
	e.journal(3)
	if _, err := upd(noConfirm, ptr(true)); err != nil {
		t.Fatal(err)
	}
	if st := e.streamStatus(t, c.ID); st.Cursor.LastSeq != 5 || st.Backlog.Pending != 0 {
		t.Fatalf("повторная подписка не с конца журнала: %+v", st)
	}
}

// Экранирование CEF записи журнала: «|» в заголовке, «=» и переводы строк в
// расширении.
func TestAuditCEFEscaping(t *testing.T) {
	r := audit.Record{Seq: 7, ID: "id=1", Action: `a|b\c`, Result: audit.ResultDenied,
		Actor:   audit.Actor{Type: audit.ActorUser, ID: "u", Name: "x=y\nz"},
		Object:  audit.Object{Type: "route", ID: "/a|b"},
		Details: json.RawMessage(`{"k":"v=1\r\n"}`)}
	got := string(auditCEF(&r, "1|0"))
	if !strings.HasPrefix(got, `CEF:0|AISec|AISec|1\|0|a\|b\\c|a\|b\\c|6|`) || !strings.Contains(got, `suser=x\=y z`) ||
		!strings.Contains(got, `externalId=id\=1`) || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CEF: %q", got)
	}
}

// Отсрочка курсора истекла (экземпляр A завис): курсор берёт экземпляр B,
// итог A не сохраняется — ни сдвиг, ни ошибка, ни запись о разрыве. Если
// B не передал, успех A сдвигает курсор.
func TestAuditStreamStaleFinish(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	e.journal(1)
	c := e.siemChannel(t, "127.0.0.1", 1, FormatJSON)
	e.journal(3)
	gap := []audit.Entry{{Action: "notify.audit_stream_gap"}}
	claim := func() StreamCursor {
		t.Helper()
		cur, ok, err := e.mem.ClaimStream(ctx, c.ID, streamLease)
		if err != nil || !ok {
			t.Fatalf("захват: %v %v", ok, err)
		}
		return cur
	}
	a := claim()
	if _, ok, _ := e.mem.ClaimStream(ctx, c.ID, streamLease); ok { //nolint:gosec // G104: проверяется ok
		t.Fatal("курсор взят дважды")
	}
	e.now = e.now.Add(streamLease)
	b := claim()
	b.LastSeq, b.UpdatedAt, b.NextAt = 3, e.now, e.now
	if err := e.mem.FinishStream(ctx, 1, b, nil); err != nil {
		t.Fatal(err)
	}
	before := len(e.mem.Audited())
	for _, res := range []StreamCursor{
		{ChannelID: c.ID, LastSeq: 4, UpdatedAt: e.now, NextAt: e.now},
		{ChannelID: c.ID, LastSeq: a.LastSeq, Attempts: 1, Error: ErrCodeDial, UpdatedAt: e.now, NextAt: e.now.Add(time.Hour)},
	} {
		if err := e.mem.FinishStream(ctx, a.LastSeq, res, gap); err != nil {
			t.Fatal(err)
		}
	}
	st := e.streamStatus(t, c.ID)
	if st.Cursor.LastSeq != 3 || st.Cursor.Attempts != 0 || st.Cursor.Error != "" || len(e.mem.Audited()) != before {
		t.Fatalf("итог устаревшей попытки сохранён: %+v", st.Cursor)
	}

	// B неудачен, затем A успешен: курсор сдвигает A.
	e.now = e.now.Add(streamLease)
	a = claim()
	e.now = e.now.Add(streamLease)
	b = claim()
	b.Attempts, b.Error, b.UpdatedAt, b.NextAt = 1, ErrCodeDial, e.now, e.now.Add(Backoff(1))
	if err := e.mem.FinishStream(ctx, 3, b, nil); err != nil {
		t.Fatal(err)
	}
	a.LastSeq, a.UpdatedAt, a.NextAt = 4, e.now, e.now
	if err := e.mem.FinishStream(ctx, 3, a, nil); err != nil {
		t.Fatal(err)
	}
	if st := e.streamStatus(t, c.ID); st.Cursor.LastSeq != 4 || st.Cursor.Attempts != 0 || st.Backlog.Pending != 0 {
		t.Fatalf("успех после неудачи: %+v", st.Cursor)
	}
}

// Курсор потерян (каналы восстановлены без курсоров): новый — с конца
// журнала и записью notify.audit_stream_gap (cursor_lost); снятие подписки
// снимает поднятое отставание.
func TestAuditStreamCursorLostAndLagCleared(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	c := e.siemChannel(t, "127.0.0.1", 1, FormatJSON)
	e.journal(2)
	e.mem.mu.Lock()
	delete(e.mem.cursors, c.ID)
	e.mem.mu.Unlock()
	e.streamOnce(t)
	var lost bool
	for _, r := range e.mem.Audited() {
		if d, ok := r.Details.(map[string]any); ok && r.Action == "notify.audit_stream_gap" && d["reason"] == "cursor_lost" {
			lost = d["to_seq"] == int64(2)
		}
	}
	if st := e.streamStatus(t, c.ID); !lost || st.Cursor.LastSeq != 2 {
		t.Fatalf("потеря курсора: %v %+v", lost, st.Cursor)
	}

	e.journal(1)
	e.now = e.now.Add(StreamLagAge + time.Minute)
	e.streamOnce(t)
	if !e.streamStatus(t, c.ID).Cursor.LagRaised {
		t.Fatal("отставание не поднято")
	}
	cur, err := e.svc.Channel(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateChannel(ctx, e.by, c.ID, ChannelInput{Name: cur.Name, Enabled: ptr(true), MinSeverity: cur.MinSeverity,
		AuditStream: ptr(false), Settings: cur.Settings, Version: cur.Version}); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, r := range e.mem.Audited() {
		if d, ok := r.Details.(map[string]any); ok && r.Action == "system.alert" && d["state"] == "cleared" {
			cleared = d["reason"] == "stream_disabled" && r.Object.ID == "audit_stream_lag:"+c.ID
		}
	}
	if !cleared {
		t.Fatal("отставание не снято при снятии подписки")
	}
}
