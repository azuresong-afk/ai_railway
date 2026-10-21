package gwregistry_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

var testIP = netip.MustParseAddr("192.0.2.10")

// recAuditor — журнал отказов (записи без изменения данных).
type recAuditor struct {
	mu   sync.Mutex
	recs []audit.Entry
}

func (a *recAuditor) Record(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recs = append(a.recs, e)
	return nil
}

func (a *recAuditor) all() []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Entry(nil), a.recs...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	mem   *gwregistry.Memory
	aud   *recAuditor
	clock *clock
	ca    *aisecCrypto.CA
	svc   *gwregistry.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Second)
	ca, err := aisecCrypto.NewCA("AISec test CA", 400*24*time.Hour, start)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{mem: gwregistry.NewMemory(), aud: &recAuditor{}, clock: &clock{t: start}, ca: ca}
	e.svc, err = gwregistry.New(gwregistry.Options{
		Store: e.mem, Provider: p, CA: ca, Audit: e.aud, Clock: e.clock.now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { checkNoSecrets(t, append(e.mem.Records, e.aud.all()...)) })
	return e
}

var cliActor = audit.Actor{Type: audit.ActorCLI, ID: "uid:1000", Name: "admin"}

// checkNoSecrets: токен регистрации не попадает в аудит; все коды — из перечня.
func checkNoSecrets(t *testing.T, recs []audit.Entry) {
	t.Helper()
	for _, r := range recs {
		if _, ok := audit.Lookup(r.Action); !ok {
			t.Errorf("код %q вне перечня аудита", r.Action)
		}
		if s := fmt.Sprintf("%+v", r); strings.Contains(s, gwregistry.TokenPrefix) {
			t.Errorf("токен регистрации в записи аудита: %s", r.Action)
		}
	}
}

func (e *env) token(t *testing.T, name string, rereg bool) string {
	t.Helper()
	tok, gw, err := e.svc.IssueToken(context.Background(), gwregistry.TokenInput{Name: name, Reregister: rereg, Actor: cliActor})
	if err != nil {
		t.Fatal(err)
	}
	if gw.Name != name || len(tok) != gwregistry.TokenLen || !strings.HasPrefix(tok, gwregistry.TokenPrefix) {
		t.Fatalf("токен %q для %+v", tok, gw)
	}
	return tok
}

func (e *env) register(t *testing.T, token string) (gwregistry.Registration, []byte) {
	t.Helper()
	key, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.svc.Register(context.Background(), gwregistry.RegisterInput{Token: token, CSR: csr, SourceIP: testIP})
	if err != nil {
		t.Fatal(err)
	}
	return reg, key
}

func peerOf(t *testing.T, certPEM []byte) aisecCrypto.PeerIdentity {
	t.Helper()
	id, err := aisecCrypto.ParseCertInfo(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ИАФ.10: токен → сертификат с ID шлюза → проверка сертификата → heartbeat.
func TestRegisterAuthenticateHeartbeat(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok := e.token(t, "gw-1", false)
	reg, _ := e.register(t, tok)
	gw := reg.Gateway
	if gw.Status != gwregistry.StatusActive || gw.CertSerial == "" || string(reg.CAPEM) != string(e.ca.CertPEM()) {
		t.Fatalf("после регистрации: %+v", gw)
	}
	peer := peerOf(t, reg.CertPEM)
	if peer.CommonName != gw.ID || peer.Serial != gw.CertSerial {
		t.Fatalf("сертификат %+v не соответствует шлюзу %+v", peer, gw)
	}
	got, err := e.svc.Authenticate(ctx, peer, testIP)
	if err != nil || got.ID != gw.ID {
		t.Fatalf("Authenticate: %+v %v", got, err)
	}
	at, err := e.svc.Heartbeat(ctx, gw.ID, gwregistry.HeartbeatInput{Version: "2.0.0-dev", BundleETag: `"sha256:ab"`}, testIP)
	if err != nil || !at.Equal(e.clock.now()) {
		t.Fatalf("Heartbeat: %v %v", at, err)
	}
	list, err := e.svc.List(ctx)
	if err != nil || len(list) != 1 || list[0].Version != "2.0.0-dev" || !list[0].LastSeenAt.Equal(at) || list[0].LastAddr != testIP {
		t.Fatalf("после heartbeat: %+v %v", list, err)
	}
	var actions []string
	for _, r := range e.mem.Records {
		actions = append(actions, r.Action)
	}
	if strings.Join(actions, ",") != "gateway.token_issue,gateway.register" {
		t.Fatalf("записи аудита: %v", actions)
	}
}

// Любой отказ по токену — одна и та же ошибка и запись аудита без токена;
// неверный CSR отклоняется до токена и его не тратит.
func TestRegisterRejectsTokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	reg := func(tok string, c []byte) error {
		_, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: tok, CSR: c, SourceIP: testIP})
		return err
	}
	tok := e.token(t, "gw-1", false)
	if err := reg(tok, []byte("не CSR")); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("неверный CSR: %v", err)
	}
	other := gwregistry.TokenPrefix + strings.Repeat("A", gwregistry.TokenLen-len(gwregistry.TokenPrefix))
	for name, bad := range map[string]string{
		"пусто":         "",
		"без префикса":  strings.TrimPrefix(tok, gwregistry.TokenPrefix),
		"чужой префикс": "aisec_setup_" + strings.TrimPrefix(tok, gwregistry.TokenPrefix),
		"не base64url":  gwregistry.TokenPrefix + strings.Repeat("!", gwregistry.TokenLen-len(gwregistry.TokenPrefix)),
		"короче":        tok[:len(tok)-1],
		"неизвестный":   other,
	} {
		if err := reg(bad, csr); !errors.Is(err, gwregistry.ErrTokenInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := reg(tok, csr); err != nil {
		t.Fatalf("неверный CSR потратил токен: %v", err)
	}
	if err := reg(tok, csr); !errors.Is(err, gwregistry.ErrTokenInvalid) {
		t.Fatalf("повтор токена: %v", err)
	}
	// Истёкший токен.
	tok2 := e.token(t, "gw-2", false)
	e.clock.add(gwregistry.DefaultTokenTTL)
	if err := reg(tok2, csr); !errors.Is(err, gwregistry.ErrTokenInvalid) {
		t.Fatalf("истёкший токен: %v", err)
	}
	denied := 0
	for _, r := range e.aud.all() {
		if r.Action == "gateway.register" && r.Result == audit.ResultDenied {
			denied++
		}
	}
	if denied != 8 {
		t.Fatalf("записей об отказе регистрации: %d, ожидается 8", denied)
	}
}

// Параллельные регистрации с одним токеном: проходит ровно одна.
func TestRegisterTokenOnce(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, "gw-1", false)
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	var ok, fail int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Register(context.Background(), gwregistry.RegisterInput{Token: tok, CSR: csr})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else if errors.Is(err, gwregistry.ErrTokenInvalid) {
				fail++
			}
		}()
	}
	wg.Wait()
	if ok != 1 || fail != 7 {
		t.Fatalf("успешных %d, отказов %d", ok, fail)
	}
}

// Отзыв и перерегистрация действуют сразу: прежний сертификат отклоняется.
func TestRevokeAndReregister(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg1, _ := e.register(t, e.token(t, "gw-1", false))
	old := peerOf(t, reg1.CertPEM)
	if _, _, err := e.svc.IssueToken(ctx, gwregistry.TokenInput{Name: "gw-1", Actor: cliActor}); !errors.Is(err, gwregistry.ErrNameTaken) {
		t.Fatalf("повторное имя без -reregister: %v", err)
	}
	if _, _, err := e.svc.IssueToken(ctx, gwregistry.TokenInput{Name: "gw-new", Reregister: true, Actor: cliActor}); !errors.Is(err, gwregistry.ErrNotFound) {
		t.Fatalf("-reregister для неизвестного шлюза: %v", err)
	}
	// Новый токен гасит прежний непогашенный.
	stale := e.token(t, "gw-1", true)
	reg2, _ := e.register(t, e.token(t, "gw-1", true))
	if reg2.Gateway.ID != reg1.Gateway.ID || reg2.Gateway.CertSerial == reg1.Gateway.CertSerial {
		t.Fatalf("перерегистрация: %+v → %+v", reg1.Gateway, reg2.Gateway)
	}
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: stale, CSR: csr}); !errors.Is(err, gwregistry.ErrTokenInvalid) {
		t.Fatalf("прежний токен после выпуска нового: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, old, testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("прежний сертификат после перерегистрации: %v", err)
	}
	cur := peerOf(t, reg2.CertPEM)
	if _, err := e.svc.Authenticate(ctx, cur, testIP); err != nil {
		t.Fatal(err)
	}
	pending := e.token(t, "gw-1", true)
	if _, err := e.svc.Revoke(ctx, "gw-1", cliActor); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, cur, testIP); !errors.Is(err, gwregistry.ErrRevoked) {
		t.Fatalf("отозванный шлюз: %v", err)
	}
	if _, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: pending, CSR: csr}); !errors.Is(err, gwregistry.ErrTokenInvalid) {
		t.Fatalf("токен отозванного шлюза: %v", err)
	}
	if _, err := e.svc.Revoke(ctx, "gw-1", cliActor); !errors.Is(err, gwregistry.ErrRevoked) {
		t.Fatalf("повторный отзыв: %v", err)
	}
	if _, _, err := e.svc.IssueToken(ctx, gwregistry.TokenInput{Name: "gw-1", Reregister: true, Actor: cliActor}); !errors.Is(err, gwregistry.ErrRevoked) {
		t.Fatalf("токен для отозванного шлюза: %v", err)
	}
	if _, err := e.svc.Heartbeat(ctx, reg2.Gateway.ID, gwregistry.HeartbeatInput{Version: "1"}, testIP); !errors.Is(err, gwregistry.ErrNotFound) {
		t.Fatalf("heartbeat отозванного: %v", err)
	}
}

// Отказ по сертификату пишется в аудит не чаще раза в минуту.
func TestAuthenticateDeniedAuditThrottled(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	unknown := aisecCrypto.PeerIdentity{CommonName: "0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", Serial: "abc"}
	for range 5 {
		if _, err := e.svc.Authenticate(ctx, unknown, testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
			t.Fatal(err)
		}
	}
	e.clock.add(time.Minute)
	if _, err := e.svc.Authenticate(ctx, unknown, testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatal(err)
	}
	n := 0
	for _, r := range e.aud.all() {
		if r.Action == "gateway.mtls_denied" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("записей об отказе: %d, ожидается 2", n)
	}
	// Сертификат с серийным номером шлюза, но чужим CN — отказ.
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	forged := peerOf(t, reg.CertPEM)
	forged.CommonName = "other"
	if _, err := e.svc.Authenticate(ctx, forged, testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("чужое имя: %v", err)
	}
	// Истёкший сертификат.
	e.clock.add(366 * 24 * time.Hour)
	if _, err := e.svc.Authenticate(ctx, peerOf(t, reg.CertPEM), testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("истёкший сертификат: %v", err)
	}
}

func TestHeartbeatValidationAndRate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	for name, in := range map[string]gwregistry.HeartbeatInput{
		"пустая версия":     {},
		"длинная версия":    {Version: strings.Repeat("1", 65)},
		"пробел в версии":   {Version: "1 0"},
		"кириллица":         {Version: "версия"},
		"длинный ETag":      {Version: "1", BundleETag: strings.Repeat("a", 129)},
		"управляющий ETag":  {Version: "1", BundleETag: "a\nb"},
		"пробел в ETag":     {Version: "1", BundleETag: "a b"},
		"не-ASCII в ETag":   {Version: "1", BundleETag: "é"},
		"перевод в версии":  {Version: "1\n"},
		"нулевой байт ETag": {Version: "1", BundleETag: "\x00"},
	} {
		if _, err := e.svc.Heartbeat(ctx, id, in, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1.0"}, testIP); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1.0"}, testIP); !errors.Is(err, gwregistry.ErrTooFrequent) {
		t.Fatalf("второй heartbeat сразу: %v", err)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1.0"}, testIP); err != nil {
		t.Fatalf("heartbeat через интервал: %v", err)
	}
}

func TestIssueTokenValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, in := range map[string]gwregistry.TokenInput{
		"пустое имя":     {Name: ""},
		"заглавные":      {Name: "GW"},
		"с дефиса":       {Name: "-gw"},
		"длинное":        {Name: strings.Repeat("a", 65)},
		"кириллица":      {Name: "шлюз"},
		"срок мал":       {Name: "gw", TTL: time.Second},
		"срок велик":     {Name: "gw", TTL: gwregistry.MaxTokenTTL + time.Hour},
		"отрицательный":  {Name: "gw", TTL: -time.Hour},
		"слэш в имени":   {Name: "gw/1"},
		"пробел в имени": {Name: "gw 1"},
	} {
		if _, _, err := e.svc.IssueToken(ctx, in); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Revoke(ctx, "Нет", cliActor); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("отзыв с неверным именем: %v", err)
	}
	if _, err := e.svc.Revoke(ctx, "nope", cliActor); !errors.Is(err, gwregistry.ErrNotFound) {
		t.Fatalf("отзыв неизвестного: %v", err)
	}
}

// Без УЦ (aisec-cli) регистрация недоступна.
func TestRegisterWithoutCA(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := gwregistry.New(gwregistry.Options{Store: gwregistry.NewMemory(), Provider: p, Audit: &recAuditor{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(context.Background(), gwregistry.RegisterInput{}); !errors.Is(err, gwregistry.ErrNoCA) {
		t.Fatalf("без УЦ: %v", err)
	}
	if _, err := gwregistry.New(gwregistry.Options{Provider: p}); err == nil {
		t.Fatal("сервис без хранилища")
	}
}
