package quotalease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

const tReq = "0192a000-0000-7000-8000-0000000000a1"

func body(apps ...string) string { return `{"apps":[` + strings.Join(apps, ",") + `]}` }

func TestParseValid(t *testing.T) {
	r, err := Parse([]byte(body(`{"app":"crm","quotas":[{"quota":"budget","request_id":"` + tReq + `","want":5,"offline":3,
		"reports":[{"lease":"0192a000-0000-7000-8000-0000000000b1","used":0}]}]}`)))
	if err != nil || len(r.Apps) != 1 || r.Apps[0].Quotas[0].Want != 5 || r.Apps[0].Quotas[0].Offline != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	// Граница: 2 000 приложений, 2^62 единиц.
	var apps []string
	for i := range MaxApps {
		apps = append(apps, fmt.Sprintf(`{"app":"a%d","quotas":[{"quota":"budget","request_id":"%08x-0000-7000-8000-000000000000","want":%d}]}`,
			i, i, int64(MaxUnits)))
	}
	if b := body(apps...); len(b) > MaxBody {
		t.Logf("2 000 приложений не помещаются в 64 КиБ (%d байт): проверяется Validate", len(b))
		var r Request
		if err := json.Unmarshal([]byte(b), &r); err != nil {
			t.Fatal(err)
		}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	} else if _, err := Parse([]byte(b)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejects(t *testing.T) {
	q := func(s string) string { return body(`{"app":"crm","quotas":[` + s + `]}`) }
	ok := `{"quota":"budget","request_id":"` + tReq + `","want":1}`
	cases := map[string]string{
		"не JSON":               `{`,
		"пусто":                 `{"apps":[]}`,
		"неизвестное поле":      `{"apps":[],"x":1}`,
		"данные после":          q(ok) + `{}`,
		"нет квот":              body(`{"app":"crm","quotas":[]}`),
		"ID приложения":         body(`{"app":"CRM","quotas":[` + ok + `]}`),
		"повтор приложения":     body(`{"app":"crm","quotas":[`+ok+`]}`, `{"app":"crm","quotas":[{"quota":"tokens_per_day","request_id":"0192a000-0000-7000-8000-0000000000a2","want":1}]}`),
		"неизвестная квота":     q(`{"quota":"rpm","request_id":"` + tReq + `","want":1}`),
		"повтор квоты":          q(ok + `,{"quota":"budget","request_id":"0192a000-0000-7000-8000-0000000000a2","want":1}`),
		"повтор ID запроса":     q(ok + `,{"quota":"tokens_per_day","request_id":"` + tReq + `","want":1}`),
		"ID запроса не UUID":    q(`{"quota":"budget","request_id":"x","want":1}`),
		"ID запроса прописные":  q(`{"quota":"budget","request_id":"0192A000-0000-7000-8000-0000000000A1","want":1}`),
		"отрицательное want":    q(`{"quota":"budget","request_id":"` + tReq + `","want":-1}`),
		"want больше 2^62":      q(`{"quota":"budget","request_id":"` + tReq + `","want":4611686018427387905}`),
		"дробное want":          q(`{"quota":"budget","request_id":"` + tReq + `","want":1.5}`),
		"отрицательное offline": q(`{"quota":"budget","request_id":"` + tReq + `","want":1,"offline":-1}`),
		"used отрицательное":    q(`{"quota":"budget","request_id":"` + tReq + `","want":1,"reports":[{"lease":"` + tReq + `","used":-1}]}`),
		"повтор аренды":         q(`{"quota":"budget","request_id":"` + tReq + `","want":1,"reports":[{"lease":"0192a000-0000-7000-8000-0000000000b1","used":1},{"lease":"0192a000-0000-7000-8000-0000000000b1","used":1}]}`),
		"больше 8 отчётов":      q(`{"quota":"budget","request_id":"` + tReq + `","want":1,"reports":[` + reports(MaxReports+1) + `]}`),
		"тело больше 64 КиБ":    body(strings.Repeat(" ", MaxBody)),
	}
	for name, b := range cases {
		if _, err := Parse([]byte(b)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 2 001 приложение — отказ и без предела тела.
	r := Request{}
	for i := range MaxApps + 1 {
		r.Apps = append(r.Apps, AppRequest{App: fmt.Sprintf("a%d", i), Quotas: []QuotaRequest{{Quota: QuotaBudget,
			RequestID: fmt.Sprintf("%08x-0000-7000-8000-000000000000", i), Want: 1}}})
	}
	if err := r.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("2 001 приложение: %v", err)
	}
}

func reports(n int) string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf(`{"lease":"0192a000-0000-7000-8000-%012x","used":1}`, i))
	}
	return strings.Join(out, ",")
}

// FuzzParse — разбор запроса аренды: без паники, принятый запрос проходит
// Validate и укладывается в пределы.
func FuzzParse(f *testing.F) {
	f.Add([]byte(body(`{"app":"crm","quotas":[{"quota":"budget","request_id":"` + tReq + `","want":5}]}`)))
	f.Add([]byte(`{"apps":[{"app":"crm","quotas":[{"quota":"requests_per_minute","request_id":"` + tReq +
		`","want":0,"reports":[{"lease":"0192a000-0000-7000-8000-0000000000b1","used":3}],"offline":7}]}]}`))
	f.Add([]byte(`{"apps":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("ошибка без ErrInvalid: %v", err)
			}
			return
		}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		if len(r.Apps) == 0 || len(r.Apps) > MaxApps || len(data) > MaxBody {
			t.Fatalf("пределы: %d приложений, %d байт", len(r.Apps), len(data))
		}
		for _, a := range r.Apps {
			for _, q := range a.Quotas {
				if q.Want < 0 || q.Want > MaxUnits || q.Offline < 0 || len(q.Reports) > MaxReports {
					t.Fatalf("%+v", q)
				}
			}
		}
	})
}

func TestWindowOf(t *testing.T) {
	msk, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Fatal(err)
	}
	// 31.10.2026 23:58 МСК.
	now := time.Date(2026, 10, 31, 20, 58, 0, 0, time.UTC)
	if w := windowOf(QuotaRPM, now, msk); w.key != minuteKey || w.ttl != MinuteTTL || !w.end.IsZero() {
		t.Fatalf("минута: %+v", w)
	}
	d := windowOf(QuotaTPD, now, msk)
	if d.key != "2026-10-31" || d.ttl != 2*time.Minute || d.length != 24*time.Hour {
		t.Fatalf("сутки: %+v", d)
	}
	m := windowOf(QuotaBudget, now, msk)
	if m.key != "2026-10" || m.ttl != 2*time.Minute || m.length != 31*24*time.Hour {
		t.Fatalf("месяц: %+v", m)
	}
	// Полдень — срок 5 минут; UTC не влияет на ключ суток МСК.
	noon := time.Date(2026, 10, 31, 21, 30, 0, 0, time.UTC)
	if d := windowOf(QuotaTPD, noon, msk); d.key != "2026-11-01" || d.ttl != LongTTL {
		t.Fatalf("сутки после полуночи МСК: %+v", d)
	}
}

func TestShare(t *testing.T) {
	minute := window{key: minuteKey, ttl: MinuteTTL, length: MinuteWindow}
	day := window{key: "2026-10-28", ttl: LongTTL, length: 24 * time.Hour, end: time.Now()}
	used := func(n int64) *int64 { return &n }
	for _, c := range []struct {
		name        string
		limit, want int64
		gw          int
		w           window
		prev        *prevGrant
		expect      int64
	}{
		{"один шлюз — весь лимит", 100, 1, 1, minute, nil, 100},
		{"три шлюза", 100, 1, 3, minute, nil, 34},
		{"шлюзов больше лимита — 1", 3, 1, 10, minute, nil, 1},
		{"не меньше want", 100, 60, 3, minute, nil, 60},
		{"нет шлюзов на связи — как один", 100, 1, 0, minute, nil, 100},
		{"сутки — 1 % лимита", 10000, 1, 1, day, nil, 100},
		{"нагруженный — удвоение", 100, 1, 3, minute, &prevGrant{granted: 34, recent: true}, 68},
		{"использовано наполовину", 100, 1, 3, minute, &prevGrant{granted: 34, used: used(17), recent: true}, 68},
		{"мало использовано", 100, 1, 3, minute, &prevGrant{granted: 34, used: used(16), recent: true}, 34},
		{"давняя", 100, 1, 3, minute, &prevGrant{granted: 34, recent: false}, 34},
		{"удвоение не больше лимита", 100, 1, 3, minute, &prevGrant{granted: 80, recent: true}, 100},
		{"предел чисел", MaxUnits, 1, 1, minute, &prevGrant{granted: MaxUnits, recent: true}, MaxUnits},
	} {
		if got := share(c.limit, c.want, c.gw, c.w, c.prev); got != c.expect {
			t.Errorf("%s: %d, ожидается %d", c.name, got, c.expect)
		}
	}
	if got := msPart(MaxUnits, LongTTL, 31*24*time.Hour); got <= 0 || got > MaxUnits/8000 {
		t.Fatalf("msPart без переполнения: %d", got)
	}
}

// memStore — Store в памяти для проверки ограничителя и смены режима.
type memStore struct {
	mode   string
	online int
	recs   []audit.Entry
	leases int
}

func (m *memStore) Settings(context.Context, string, time.Time) (Settings, error) {
	return Settings{Mode: m.mode, GatewaysOnline: m.online}, nil
}

func (m *memStore) SetMode(_ context.Context, _, mode string, _ time.Time, fn func(Settings) (audit.Entry, error)) error {
	if mode == m.mode {
		return nil
	}
	rec, err := fn(Settings{Mode: m.mode, GatewaysOnline: m.online})
	if err != nil {
		return err
	}
	m.mode, m.recs = mode, append(m.recs, rec)
	return nil
}

func (m *memStore) Lease(context.Context, LeaseInput) (Response, error) {
	m.leases++
	return Response{}, nil
}

func (m *memStore) Observe(context.Context, string, string, bool, time.Time) error { return nil }
func (m *memStore) Health(context.Context, string, time.Time) (Health, error)      { return Health{}, nil }
func (m *memStore) Purge(context.Context, string, time.Time) (int64, error)        { return 0, nil }
func (m *memStore) Record(_ context.Context, e audit.Entry) error {
	m.recs = append(m.recs, e)
	return nil
}

func testService(t *testing.T, st Store, clock func() time.Time) *Service {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Store: st, IDs: ids.NewGenerator(r), OrgID: audit.DefaultOrgID, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Ограничитель — 10 запросов в секунду на ID шлюза; другой шлюз и
// следующая секунда не затронуты.
func TestServiceRateLimitPerGateway(t *testing.T) {
	st := &memStore{mode: ModeLeased}
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	s := testService(t, st, func() time.Time { return now })
	req := Request{Apps: []AppRequest{{App: "crm", Quotas: []QuotaRequest{{Quota: QuotaRPM, RequestID: tReq, Want: 1}}}}}
	ctx := context.Background()
	for i := range RatePerSecond {
		if _, err := s.Lease(ctx, "g1", netip.Addr{}, req); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, err := s.Lease(ctx, "g1", netip.Addr{}, req); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("11-й запрос: %v", err)
	}
	if _, err := s.Lease(ctx, "g2", netip.Addr{}, req); err != nil {
		t.Fatalf("другой шлюз: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := s.Lease(ctx, "g1", netip.Addr{}, req); err != nil {
		t.Fatalf("через секунду: %v", err)
	}
	if st.leases != RatePerSecond+2 {
		t.Fatalf("до хранилища дошло %d", st.leases)
	}
	// Неверный запрос до хранилища не доходит.
	if _, err := s.Lease(ctx, "g3", netip.Addr{}, Request{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("пустой запрос: %v", err)
	}
	if _, err := s.SetMode(ctx, By{}, "cluster"); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("неизвестный режим: %v", err)
	}
}
