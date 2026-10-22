package gwregistry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// rootID — ID корня УЦ, как у сервиса.
func rootID(t *testing.T, ca *aisecCrypto.CA) string {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return gwregistry.RootID(h, ca.CertDER())
}

// rotateCA — перезапуск сервера после aisec-cli keys rotate-ca: новый корень
// выпускает сертификаты, прежний принимается до overlapEnd.
func (e *env) rotateCA(t *testing.T, overlapEnd time.Time) *aisecCrypto.CA {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := aisecCrypto.NewCA("AISec test CA 2", 400*24*time.Hour, e.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	anchor := rootID(t, e.ca)
	e.svc, err = gwregistry.New(gwregistry.Options{
		Store: e.mem, Provider: p, CA: ca2, Audit: e.aud, Clock: e.clock.now, AnchorRoot: anchor,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetRoots(gwregistry.RootSet{Active: rootID(t, ca2), NotAfter: map[string]time.Time{anchor: overlapEnd, rootID(t, ca2): {}}})
	return ca2
}

func peerFrom(t *testing.T, certPEM []byte, ca *aisecCrypto.CA) aisecCrypto.PeerIdentity {
	t.Helper()
	id := peerOf(t, certPEM)
	id.RootDER = ca.CertDER()
	return id
}

func countAction(recs []string, action string) int {
	n := 0
	for _, r := range recs {
		if r == action {
			n++
		}
	}
	return n
}

func (e *env) actions() []string {
	var out []string
	for _, r := range e.mem.Records {
		out = append(out, r.Action)
	}
	for _, r := range e.aud.all() {
		out = append(out, r.Action)
	}
	return out
}

// ИАФ.10, ADR-0018, п. 6: после ротации корня heartbeat требует перевыпуск,
// новый сертификат становится действующим при первом запросе с ним, прежний
// после этого не принимается; сертификат прежнего корня после конца
// перекрытия и сертификат неизвестного корня — отказ.
func TestCARotationReissue(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	gw := reg.Gateway
	other, _ := e.register(t, e.token(t, "gw-2", false))
	if gw.CertCA != rootID(t, e.ca) {
		t.Fatalf("корень при регистрации: %q", gw.CertCA)
	}
	hb, err := e.svc.Heartbeat(ctx, gw.ID, gwregistry.HeartbeatInput{Version: "1"}, testIP)
	if err != nil || hb.Reissue {
		t.Fatalf("до ротации перевыпуск не нужен: %+v %v", hb, err)
	}

	overlapEnd := e.clock.now().Add(30 * 24 * time.Hour)
	oldCA := e.ca
	ca2 := e.rotateCA(t, overlapEnd)
	e.clock.add(time.Minute)
	if _, err := e.svc.Authenticate(ctx, peerFrom(t, reg.CertPEM, oldCA), testIP); err != nil {
		t.Fatalf("прежний корень в перекрытии: %v", err)
	}
	hb, err = e.svc.Heartbeat(ctx, gw.ID, gwregistry.HeartbeatInput{Version: "1"}, testIP)
	if err != nil || !hb.Reissue {
		t.Fatalf("после ротации нужен перевыпуск: %+v %v", hb, err)
	}

	key, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Reissue(ctx, gw.ID, []byte("not a csr"), testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("неверный CSR: %v", err)
	}
	certPEM, info, err := e.svc.Reissue(ctx, gw.ID, csr, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if err := aisecCrypto.VerifyClientCert(certPEM, key, gw.ID, [][]byte{ca2.CertDER()}, e.clock.now()); err != nil {
		t.Fatalf("новый сертификат не от нового корня: %v", err)
	}
	if _, _, err := e.svc.Reissue(ctx, gw.ID, csr, testIP); !errors.Is(err, gwregistry.ErrTooFrequent) {
		t.Fatalf("второй перевыпуск за минуту: %v", err)
	}
	// До первого запроса с новым сертификатом действуют оба.
	if _, err := e.svc.Authenticate(ctx, peerFrom(t, reg.CertPEM, oldCA), testIP); err != nil {
		t.Fatalf("прежний сертификат до перехода: %v", err)
	}
	got, err := e.svc.Authenticate(ctx, peerFrom(t, certPEM, ca2), testIP)
	if err != nil || got.CertSerial != info.Serial || got.CertCA != rootID(t, ca2) || got.NextCertSerial != "" {
		t.Fatalf("переход на новый сертификат: %+v %v", got, err)
	}
	if _, err := e.svc.Authenticate(ctx, peerFrom(t, reg.CertPEM, oldCA), testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("прежний сертификат после перехода: %v", err)
	}
	e.clock.add(11 * time.Second)
	if hb, err = e.svc.Heartbeat(ctx, gw.ID, gwregistry.HeartbeatInput{Version: "1"}, testIP); err != nil || hb.Reissue {
		t.Fatalf("после перехода перевыпуск не нужен: %+v %v", hb, err)
	}
	if n := countAction(e.actions(), "gateway.cert_reissue"); n != 2 {
		t.Fatalf("записей gateway.cert_reissue: %d, ожидается 2 (issued, activated)", n)
	}

	// Шлюз, не перешедший до конца перекрытия, получает отказ ca_expired.
	e.clock.add(31 * 24 * time.Hour)
	if _, err := e.svc.Authenticate(ctx, peerFrom(t, other.CertPEM, oldCA), testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("сертификат прежнего корня после перекрытия: %v", err)
	}
	stranger, err := aisecCrypto.NewCA("stranger", 400*24*time.Hour, e.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, peerFrom(t, certPEM, stranger), testIP); !errors.Is(err, gwregistry.ErrUnknownCert) {
		t.Fatalf("корень вне заявления: %v", err)
	}
	reasons := map[string]bool{}
	for _, r := range e.aud.all() {
		if r.Action == "gateway.mtls_denied" {
			reasons[r.Details.(map[string]any)["reason"].(string)] = true
		}
	}
	if !reasons["ca_expired"] || !reasons["ca_unknown"] {
		t.Fatalf("причины отказа в аудите: %v", reasons)
	}
}

// Сертификат, который истекает через 30 суток и меньше, перевыпускается и
// без ротации; без УЦ перевыпуск недоступен.
func TestReissueBeforeExpiry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	e.clock.add(aisecCrypto.ClientCertValidity - gwregistry.ReissueBefore + time.Hour)
	hb, err := e.svc.Heartbeat(ctx, reg.Gateway.ID, gwregistry.HeartbeatInput{Version: "1"}, testIP)
	if err != nil || !hb.Reissue {
		t.Fatalf("за 30 суток до истечения нужен перевыпуск: %+v %v", hb, err)
	}
	if _, _, err := e.svc.Reissue(ctx, "0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", mustCSR(t), testIP); !errors.Is(err, gwregistry.ErrNotFound) {
		t.Fatalf("неизвестный шлюз: %v", err)
	}

	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	noCA, err := gwregistry.New(gwregistry.Options{Store: e.mem, Provider: p, Audit: e.aud, Clock: e.clock.now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := noCA.Reissue(ctx, reg.Gateway.ID, mustCSR(t), testIP); !errors.Is(err, gwregistry.ErrNoCA) {
		t.Fatalf("без УЦ: %v", err)
	}
}

func mustCSR(t *testing.T) []byte {
	t.Helper()
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func recipientKey(t *testing.T) []byte {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return r.PublicKey()
}

// Н27, ADR-0018, п. 7: ключ получателя закрепляется при регистрации или при
// первом запросе пакета; другой ключ — отказ с записью не чаще раза в
// минуту; перерегистрация закрепляет новый ключ.
func TestBundleKeyPinning(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	k1, k2 := recipientKey(t), recipientKey(t)

	reg, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: e.token(t, "gw-1", false), CSR: mustCSR(t), SourceIP: testIP, BundleKey: k1})
	if err != nil {
		t.Fatal(err)
	}
	id := reg.Gateway.ID
	if err := e.svc.CheckBundleKey(ctx, id, k1, testIP); err != nil {
		t.Fatalf("закреплённый ключ: %v", err)
	}
	for range 3 {
		if err := e.svc.CheckBundleKey(ctx, id, k2, testIP); !errors.Is(err, gwregistry.ErrBundleKeyMismatch) {
			t.Fatalf("чужой ключ: %v", err)
		}
	}
	if n := countAction(e.actions(), "gateway.bundle_key_mismatch"); n != 1 {
		t.Fatalf("записей о чужом ключе за минуту: %d, ожидается 1", n)
	}
	e.clock.add(time.Minute)
	_ = e.svc.CheckBundleKey(ctx, id, k2, testIP) //nolint:gosec // G104: ошибка ожидаема, проверяется запись аудита
	if n := countAction(e.actions(), "gateway.bundle_key_mismatch"); n != 2 {
		t.Fatalf("записей о чужом ключе через минуту: %d, ожидается 2", n)
	}
	if err := e.svc.CheckBundleKey(ctx, id, k1[:16], testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("ключ не 32 байта: %v", err)
	}
	if _, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: e.token(t, "gw-2", false), CSR: mustCSR(t), BundleKey: k1[:31]}); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("регистрация с ключом не 32 байта: %v", err)
	}

	// Без ключа при регистрации — закрепление при первом запросе пакета.
	reg2, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: e.token(t, "gw-3", false), CSR: mustCSR(t), SourceIP: testIP})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckBundleKey(ctx, reg2.Gateway.ID, k2, testIP); err != nil {
		t.Fatalf("первый запрос пакета: %v", err)
	}
	if n := countAction(e.actions(), "gateway.bundle_key_pinned"); n != 1 {
		t.Fatalf("записей о закреплении: %d", n)
	}
	if err := e.svc.CheckBundleKey(ctx, reg2.Gateway.ID, k1, testIP); !errors.Is(err, gwregistry.ErrBundleKeyMismatch) {
		t.Fatalf("ключ после закрепления при первом запросе: %v", err)
	}

	// Перерегистрация с новым ключом заменяет закреплённый.
	if _, err := e.svc.Register(ctx, gwregistry.RegisterInput{Token: e.token(t, "gw-1", true), CSR: mustCSR(t), BundleKey: k2}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckBundleKey(ctx, id, k2, testIP); err != nil {
		t.Fatalf("ключ после перерегистрации: %v", err)
	}
	if err := e.svc.CheckBundleKey(ctx, id, k1, testIP); !errors.Is(err, gwregistry.ErrBundleKeyMismatch) {
		t.Fatalf("прежний ключ после перерегистрации: %v", err)
	}
}
