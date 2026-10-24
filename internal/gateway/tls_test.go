package gateway_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

const tlsHost = "aisec-gw.example.ru"

// tlsSection — раздел gateway_tls по синтетической цепочке.
func tlsSection(t *testing.T, c cryptotest.Chain) *bundle.GatewayTLS {
	t.Helper()
	sc, key, err := aisecCrypto.ParseServerCert(c.Full(), c.Key, tlsHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	return &bundle.GatewayTLS{Host: tlsHost, ChainPEM: string(sc.ChainPEM), Fingerprint: sc.Fingerprint, NotAfter: sc.NotAfter}
}

// Сертификат заказчика из пакета (задача 3.27): шлюз переключает TLS
// адреса приложений без перезапуска; неверный раздел gateway_tls отклоняет
// пакет целиком, и шлюз остаётся на прежних пакете и сертификате; без
// раздела — сертификат шлюза.
func TestGatewayTLSFromBundle(t *testing.T) {
	e := newBundleEnv(t)
	ca, err := aisecCrypto.NewCA("Внутренний УЦ", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defCert, defKey, err := ca.IssueServer([]string{"localhost"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certSw, err := aisecCrypto.NewServerCertSwitch(defCert, defKey)
	if err != nil {
		t.Fatal(err)
	}
	logBuf := &bytes.Buffer{}
	appTLS, err := gateway.NewTLSSwitch(certSw, slog.New(slog.NewJSONHandler(logBuf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := e.fx.Provider.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(e.dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() }) //nolint:gosec // G104: закрытие хранилища в очистке теста
	c, err := gateway.NewBundleClient(gateway.BundleConfig{Client: http.DefaultClient, Server: e.url, Opener: e.fx.Opener(t),
		RecipientKey: e.fx.Recipient.PublicKey(), State: st,
		Apply: func(b *bundle.Bundle) error {
			p, err := appTLS.Prepare(b.Content.GatewayTLS, b.TLSKey, time.Now())
			clear(b.TLSKey)
			if err != nil {
				return err
			}
			e.applied = append(e.applied, b.Header.Version)
			appTLS.Use(p)
			return nil
		},
		Logger: slog.New(slog.NewJSONHandler(e.log, nil))})
	if err != nil {
		t.Fatal(err)
	}

	good, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{tlsHost}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{tlsHost}})
	if err != nil {
		t.Fatal(err)
	}
	content := e.fx.Content(t)
	content.GatewayTLS = tlsSection(t, good)
	e.srv.set(e.fx.SealTLS(t, content, 100, good.Key), "100")
	e.poll(t, c)
	if appTLS.Current() != content.GatewayTLS.Fingerprint || len(e.applied) != 1 {
		t.Fatalf("сертификат заказчика не включён: %q %v", appTLS.Current(), e.applied)
	}
	want := appTLS.Current()

	// Ключ не от сертификата — пакет отклонён, сертификат прежний.
	e.srv.set(e.fx.SealTLS(t, content, 200, other.Key), "200")
	e.poll(t, c)
	if appTLS.Current() != want || len(e.applied) != 1 || c.ETag() != `"100"` {
		t.Fatalf("неверный раздел применён: %q %v %s", appTLS.Current(), e.applied, c.ETag())
	}
	wantReport(t, e.srv.lastReport(), "rejected", 200, bundle.ReasonInvalidContent)

	// Чужое имя адреса — тоже отказ.
	bad := e.fx.Content(t)
	bad.GatewayTLS = tlsSection(t, good)
	bad.GatewayTLS.Host = "other.example.ru"
	e.srv.set(e.fx.SealTLS(t, bad, 300, good.Key), "300")
	e.poll(t, c)
	if appTLS.Current() != want || len(e.applied) != 1 {
		t.Fatalf("чужое имя применено: %q %v", appTLS.Current(), e.applied)
	}

	// Раздел без ключа в секретах — отказ при открытии пакета.
	e.srv.set(e.fx.Seal(t, content, 400), "400")
	e.poll(t, c)
	if appTLS.Current() != want || len(e.applied) != 1 {
		t.Fatalf("раздел без ключа применён: %q %v", appTLS.Current(), e.applied)
	}
	wantReport(t, e.srv.lastReport(), "rejected", 400, bundle.ReasonInvalidContent)

	// Замена сертификата — переключение на новый без перезапуска.
	next := e.fx.Content(t)
	next.GatewayTLS = tlsSection(t, other)
	e.srv.set(e.fx.SealTLS(t, next, 500, other.Key), "500")
	e.poll(t, c)
	if appTLS.Current() != next.GatewayTLS.Fingerprint || len(e.applied) != 2 {
		t.Fatalf("замена не применена: %q %v", appTLS.Current(), e.applied)
	}

	// Без раздела — возврат к сертификату шлюза.
	e.srv.set(e.fx.Seal(t, e.fx.Content(t), 600), "600")
	e.poll(t, c)
	if appTLS.Current() != "" || len(e.applied) != 3 {
		t.Fatalf("возврат к сертификату шлюза: %q %v", appTLS.Current(), e.applied)
	}
	for _, l := range []string{e.log.String(), logBuf.String()} {
		if strings.Contains(l, "PRIVATE KEY") {
			t.Fatal("ключ сертификата в техническом журнале")
		}
	}
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestGatewayTLSExpiredFallsBack: сертификат, истёкший по часам шлюза
// (например, в сохранённом пакете после перезапуска), не отклоняет пакет:
// адрес приложений обслуживается сертификатом шлюза.
func TestGatewayTLSExpiredFallsBack(t *testing.T) {
	good, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{tlsHost}})
	if err != nil {
		t.Fatal(err)
	}
	sec := tlsSection(t, good)
	ca, err := aisecCrypto.NewCA("Внутренний УЦ", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defCert, defKey, err := ca.IssueServer([]string{"localhost"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certSw, err := aisecCrypto.NewServerCertSwitch(defCert, defKey)
	if err != nil {
		t.Fatal(err)
	}
	logBuf := &bytes.Buffer{}
	appTLS, err := gateway.NewTLSSwitch(certSw, slog.New(slog.NewJSONHandler(logBuf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := appTLS.Prepare(sec, bundle.KeyPEM(good.Key), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	appTLS.Use(p)
	if appTLS.Current() != sec.Fingerprint {
		t.Fatal("сертификат не включён")
	}
	p, err = appTLS.Prepare(sec, bundle.KeyPEM(good.Key), time.Now().Add(2*365*24*time.Hour))
	if err != nil {
		t.Fatalf("истёкший сертификат отклонил пакет: %v", err)
	}
	appTLS.Use(p)
	if appTLS.Current() != "" || !strings.Contains(logBuf.String(), "не действует по часам шлюза") {
		t.Fatalf("нет возврата к сертификату шлюза: %q %s", appTLS.Current(), logBuf)
	}
	// Отпечаток не совпадает с цепочкой — отказ.
	sec.Fingerprint = strings.Repeat("0", 64)
	if _, err := appTLS.Prepare(sec, bundle.KeyPEM(good.Key), time.Now()); err == nil {
		t.Fatal("отпечаток не сверен")
	}
}
