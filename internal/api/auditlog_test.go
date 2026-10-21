package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// memJournal — журнал аудита в памяти для тестов API 2.4a: цепочка
// настоящих хешей, выборка от новых к старым по номеру и курсору; прочие
// фильтры только запоминаются (их SQL проверяет TestListPostgres).
type memJournal struct {
	mu      sync.Mutex
	h       aisecCrypto.Hasher
	anchor  audit.Anchor
	records []audit.Record
	entries []audit.Entry
	lastQ   audit.Query
	busy    bool
}

func newMemJournal(t testing.TB, n int) *memJournal {
	t.Helper()
	h := testHasher(t)
	j := &memJournal{h: h, anchor: audit.Anchor{Seq: 0, Hash: make([]byte, h.New().Size())}}
	for i := range n {
		j.append(t, audit.Entry{
			Actor:  audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-00000000000" + strconv.Itoa(i%10), Name: "user" + strconv.Itoa(i)},
			Action: "auth.login", Result: audit.ResultSuccess, SourceIP: netip.MustParseAddr("192.0.2.10"),
			Details: map[string]any{"i": i, "reason": "[скрыто]"},
		})
	}
	return j
}

func (j *memJournal) append(t testing.TB, e audit.Entry) {
	t.Helper()
	d, err := audit.CanonicalDetails(e.Details)
	if err != nil {
		t.Fatal(err)
	}
	prev := j.anchor.Hash
	if n := len(j.records); n > 0 {
		prev = j.records[n-1].Hash
	}
	seq := int64(len(j.records) + 1)
	r := audit.Record{
		Seq: seq, ID: "01900000-0000-7000-8000-" + strings.Repeat("0", 12-len(strconv.FormatInt(seq, 10))) + strconv.FormatInt(seq, 10),
		OrgID: audit.DefaultOrgID, TS: time.Date(2026, 10, 21, 12, 0, int(seq), 0, time.UTC),
		Actor: e.Actor, SourceIP: e.SourceIP, Action: e.Action, Object: e.Object, Result: e.Result,
		Details: d, HashAlg: j.h.Name(), PrevHash: prev,
	}
	if r.Hash, err = r.ComputeHash(j.h); err != nil {
		t.Fatal(err)
	}
	j.records = append(j.records, r)
}

func (j *memJournal) Record(_ context.Context, e audit.Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, e)
	return nil
}

func (j *memJournal) List(_ context.Context, q audit.Query) ([]audit.Record, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lastQ = q
	var out []audit.Record
	for i := len(j.records) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if q.BeforeSeq == 0 || j.records[i].Seq < q.BeforeSeq {
			out = append(out, j.records[i])
		}
	}
	return out, nil
}

// TryVerifyBy — проверка всей цепочки той же функцией, что у Verifier
// (audit.VerifyRecords), с записью итога, как Verifier.save.
func (j *memJournal) TryVerifyBy(_ context.Context, by audit.Actor, ip netip.Addr) (audit.Verification, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.busy {
		return audit.Verification{}, audit.ErrVerifyBusy
	}
	checked, brk := audit.VerifyRecords(j.h, j.anchor, nil, j.records)
	res := audit.Verification{At: time.Now().UTC(), Checked: checked, Break: brk}
	if checked > 0 {
		res.Head = audit.Anchor{Seq: j.records[checked-1].Seq, Hash: j.records[checked-1].Hash}
	}
	action := "audit.chain_verified"
	if brk != nil {
		action = "audit.chain_broken"
	}
	j.entries = append(j.entries, audit.Entry{Actor: by, SourceIP: ip, Action: action, Object: audit.Object{Type: "audit_log"}})
	return res, nil
}

func (j *memJournal) actions() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []string
	for _, e := range j.entries {
		out = append(out, e.Action)
	}
	return out
}

func auditHandler(t *testing.T, j *memJournal, perms ...string) http.Handler {
	t.Helper()
	allow := allowPerm{}
	for _, p := range perms {
		allow[p] = true
	}
	h, _ := newHandler(t, Options{Authorizer: allow, AuditLog: j, AuditVerifier: j})
	return h
}

func getQuery(t *testing.T, raw string) auditListParams {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/audit?"+raw, nil)
	lp, p := parseAuditList(r, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	if p != nil {
		t.Fatalf("%s: %s %+v", raw, p.Detail, p.Errors)
	}
	return lp
}

func TestParseAuditList(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	lp := getQuery(t, "")
	if !lp.query.To.Equal(now) || !lp.query.From.Equal(now.Add(-DefaultAuditRange)) || lp.page.Limit != DefaultPageLimit || lp.query.Limit != DefaultPageLimit+1 {
		t.Errorf("умолчания: %+v", lp)
	}
	lp = getQuery(t, "action=auth.*&action=user.create&action=api_token.*&actor_type=user&actor=admin&object_type=user&object_id=x&result=denied&limit=10")
	q := lp.query
	if strings.Join(q.Groups, ",") != "auth,api_token" || strings.Join(q.Actions, ",") != "user.create" ||
		q.ActorType != audit.ActorUser || q.Actor != "admin" || q.ObjectType != "user" || q.ObjectID != "x" || q.Result != audit.ResultDenied || q.Limit != 11 {
		t.Errorf("фильтр: %+v", q)
	}
	// Граница: ровно 31 сутки и 20 кодов.
	from := now.Add(-audit.MaxQueryRange).Format(time.RFC3339)
	getQuery(t, "from="+url.QueryEscape(from)+"&to="+url.QueryEscape(now.Format(time.RFC3339))+strings.Repeat("&action=auth.login", 20))

	bad := map[string]string{
		"неизвестный параметр":    "filter=x",
		"период длиннее 31 суток": "from=2026-09-01T00:00:00Z&to=2026-10-21T00:00:00Z",
		"from позже to":           "from=2026-10-21T00:00:00Z&to=2026-10-20T00:00:00Z",
		"from не RFC 3339":        "from=вчера",
		"21 код":                  strings.Repeat("action=auth.login&", 21),
		"код без группы":          "action=login",
		"код с шаблоном внутри":   "action=auth.*.x",
		"код с LIKE-шаблоном":     "action=auth.%25",
		"SQL в коде":              "action=" + url.QueryEscape("auth.login' OR 1=1--"),
		"пустой субъект":          "actor=",
		"два субъекта":            "actor=a&actor=b",
		"длинный субъект":         "actor=" + strings.Repeat("я", 257),
		"не UTF-8":                "actor=%FF",
		"тип субъекта":            "actor_type=root",
		"результат":               "result=ok",
		"limit":                   "limit=201",
		"курсор":                  "cursor=xyz",
		"курсор не номер":         "cursor=" + Cursor{TimeMicro: 1, ID: "abc"}.Encode(),
		"курсор ноль":             "cursor=" + Cursor{TimeMicro: 1, ID: "0"}.Encode(),
		"длинная строка":          "actor=" + strings.Repeat("a", auditQueryMax),
	}
	for name, raw := range bad {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/audit?"+raw, nil)
		if _, p := parseAuditList(r, now); p == nil || p.Status != http.StatusBadRequest {
			t.Errorf("%s: принят запрос %q", name, raw)
		}
	}
}

func TestListAudit(t *testing.T) {
	j := newMemJournal(t, 5)
	h := auditHandler(t, j, auth.PermAuditRead)
	w := do(h, "GET", "/api/v1/audit?limit=2&actor=admin&action=auth.*", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var page struct {
		Items      []AuditRecordView `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Seq != 5 || page.Items[1].Seq != 4 || page.NextCursor == "" {
		t.Fatalf("страница: %+v", page)
	}
	it := page.Items[0]
	if it.Action != "auth.login" || it.ActionTitle != "Вход в консоль" || it.TS == nil || it.SourceIP == nil || *it.SourceIP != "192.0.2.10" ||
		it.Actor.Type != "user" || it.Hash == "" || !strings.Contains(string(it.Details), `"reason":"[скрыто]"`) {
		t.Errorf("запись: %+v", it)
	}
	if j.lastQ.Actor != "admin" || len(j.lastQ.Groups) != 1 {
		t.Errorf("фильтр не дошёл до журнала: %+v", j.lastQ)
	}
	// Вторая страница — по курсору, до первой записи.
	w = do(h, "GET", "/api/v1/audit?limit=2&cursor="+page.NextCursor, "")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 {
		t.Fatal(w.Code, err)
	}
	if len(page.Items) != 2 || page.Items[0].Seq != 3 || j.lastQ.BeforeSeq != 4 {
		t.Errorf("вторая страница: %+v, курсор %d", page.Items, j.lastQ.BeforeSeq)
	}
	// Каждый просмотр — audit.list; в саму выдачу запись не попадает.
	if got := j.actions(); len(got) != 2 || got[0] != "audit.list" {
		t.Errorf("записи аудита: %v", got)
	}
	if e := j.entries[0]; e.Actor.ID == "" || !e.SourceIP.IsValid() || e.Object.Type != "audit_log" {
		t.Errorf("запись просмотра: %+v", e)
	}
	mustProblem(t, do(h, "GET", "/api/v1/audit?sort=ts", ""), 400, CodeInvalidRequest)
}

func TestAuditRecordViewUnreadable(t *testing.T) {
	v := auditRecordView(&audit.Record{Seq: 1, Action: "legacy.event", Details: json.RawMessage(`{`)})
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if v.TS != nil || v.SourceIP != nil || v.ActionTitle != "" || string(v.Details) != "null" || !strings.Contains(string(b), `"ts":null`) {
		t.Errorf("нечитаемая запись: %s", b)
	}
}

func TestAuditRoutesUnavailable(t *testing.T) {
	h, _ := newHandler(t, Options{Authorizer: allowPerm{auth.PermAuditRead: true, auth.PermAuditVerify: true}})
	mustProblem(t, do(h, "GET", "/api/v1/audit", ""), 503, CodeUnavailable)
	mustProblem(t, do(h, "POST", "/api/v1/audit/verify", ""), 503, CodeUnavailable)
}

// Отказ в доступе: аналитик и администратор системы журнал не видят и не
// проверяют (ТЗ 1.3, УПД.2); аудитор проходит проверку прав.
func TestAuditAccessDenied(t *testing.T) {
	j := newMemJournal(t, 1)
	h := auditHandler(t, j, auth.PermEventsRead, auth.PermSystemRead)
	mustProblem(t, do(h, "GET", "/api/v1/audit", ""), 403, CodeForbidden)
	mustProblem(t, do(h, "POST", "/api/v1/audit/verify", ""), 403, CodeForbidden)
	h = auditHandler(t, j, auth.PermAuditRead)
	mustProblem(t, do(h, "POST", "/api/v1/audit/verify", ""), 403, CodeForbidden)
	if len(j.actions()) != 0 {
		t.Errorf("после отказа есть записи: %v", j.actions())
	}

	roles := map[auth.Role]auth.RoleDef{}
	for _, r := range auth.BuiltinRoles() {
		roles[r.ID] = r
	}
	for _, perm := range []string{auth.PermAuditRead, auth.PermAuditVerify} {
		for id, want := range map[auth.Role]bool{auth.RoleSecurityAdmin: true, auth.RoleAuditor: true,
			auth.RoleSystemAdmin: false, auth.RoleAnalyst: false, auth.RoleAppOwner: false} {
			if roles[id].Grants.Allows(perm) != want {
				t.Errorf("%s у %s: %v", perm, id, !want)
			}
		}
	}
}

func TestVerifyAudit(t *testing.T) {
	j := newMemJournal(t, 4)
	h := auditHandler(t, j, auth.PermAuditVerify)
	w := do(h, "POST", "/api/v1/audit/verify", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var v AuditVerifyView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Checked != 4 || v.LastSeq != 4 || v.Reason != "ok" || v.BrokenSeq != nil || !strings.Contains(w.Body.String(), `"broken_seq":null`) {
		t.Errorf("итог: %s", w.Body)
	}
	if got := j.actions(); len(got) != 1 || got[0] != "audit.chain_verified" || !j.entries[0].SourceIP.IsValid() {
		t.Errorf("записи аудита: %v", j.entries)
	}

	// Идёт другая проверка — 409 с Retry-After, без ожидания.
	j.busy = true
	w = do(h, "POST", "/api/v1/audit/verify", "")
	mustProblem(t, w, 409, CodeConflict)
	if w.Header().Get("Retry-After") == "" {
		t.Error("нет Retry-After")
	}
}

// ЗИ.6: проверка читает весь журнал — не чаще 5 раз в минуту с адреса.
func TestVerifyAuditRateLimited(t *testing.T) {
	j := newMemJournal(t, 1)
	h := auditHandler(t, j, auth.PermAuditVerify)
	for i := range 5 {
		if w := do(h, "POST", "/api/v1/audit/verify", ""); w.Code != 200 {
			t.Fatalf("запрос %d: %d", i+1, w.Code)
		}
	}
	mustProblem(t, do(h, "POST", "/api/v1/audit/verify", ""), 429, CodeRateLimited)
	if w := do(h, "GET", "/api/v1/audit", ""); w.Code == 429 {
		t.Error("предел проверки задел просмотр журнала")
	}
}

// DM-43: запись журнала изменена в обход продукта; проверка по команде
// через API находит разрыв, называет причину и номер записи и пишет
// audit.chain_broken от имени субъекта.
func TestDM43_ChainBrokenViaAPI(t *testing.T) {
	j := newMemJournal(t, 6)
	h := auditHandler(t, j, auth.PermAuditVerify)
	if w := do(h, "POST", "/api/v1/audit/verify", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("до подмены: %d %s", w.Code, w.Body)
	}
	// Подмена, как UPDATE под суперпользователем СУБД: хеш не пересчитан.
	j.records[2].Actor.Name = "mallory"

	w := do(h, "POST", "/api/v1/audit/verify", "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var v AuditVerifyView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.OK || v.Reason != string(audit.ReasonHashMismatch) || v.BrokenSeq == nil || *v.BrokenSeq != 3 || v.LastSeq != 2 {
		t.Errorf("разрыв не найден: %s", w.Body)
	}
	if got := j.actions(); len(got) != 2 || got[1] != "audit.chain_broken" || j.entries[1].Actor.ID == "" {
		t.Errorf("записи аудита: %v", j.entries)
	}
}

func FuzzParseAuditList(f *testing.F) {
	for _, s := range []string{"", "action=auth.*&actor=admin", "from=2026-10-20T00:00:00Z&to=2026-10-21T00:00:00Z",
		"cursor=" + Cursor{TimeMicro: 5, ID: "17"}.Encode(), "result=denied&actor_type=cli&limit=200", "action=a.b.*&action=%FF"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/audit", nil)
		r.URL.RawQuery = raw
		lp, p := parseAuditList(r, now)
		if p != nil {
			if p.Status != http.StatusBadRequest {
				t.Fatalf("статус %d", p.Status)
			}
			return
		}
		// Принятый запрос проходит проверку журнала: разбор не шире выборки.
		if err := lp.query.Validate(); err != nil {
			t.Fatalf("принят неверный запрос %q: %v", raw, err)
		}
	})
}
