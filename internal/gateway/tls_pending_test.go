package gateway

import (
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// pendingSection — раздел gateway_tls по цепочке, которая начинает
// действовать в notBefore.
func pendingSection(t *testing.T, notBefore time.Time) (*bundle.GatewayTLS, bundle.KeyPEM) {
	t.Helper()
	const host = "aisec-gw.example.ru"
	c, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}, NotBefore: notBefore, NotAfter: notBefore.Add(365 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sc, key, err := aisecCrypto.ParseServerCert(c.Full(), c.Key, host, notBefore.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	return &bundle.GatewayTLS{Host: host, ChainPEM: string(sc.ChainPEM), Fingerprint: sc.Fingerprint, NotAfter: sc.NotAfter}, bundle.KeyPEM(c.Key)
}

func newTestTLSSwitch(t *testing.T) *TLSSwitch {
	t.Helper()
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
	s, err := NewTLSSwitch(certSw, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 3Н43 ревью 3.r3: сертификат заказчика, который по часам шлюза ещё не
// действует, не оставляет шлюз на своём сертификате до перезапуска: в
// пределах допуска часов включается сразу, иначе — когда начнёт
// действовать; новый пакет отменяет ожидание прежнего.
func TestTLSSwitchNotYetValid(t *testing.T) {
	old := tlsPendingRetry
	tlsPendingRetry = 10 * time.Millisecond
	t.Cleanup(func() { tlsPendingRetry = old })
	now := time.Now()

	// Часы шлюза отстают на 2 минуты — включается сразу.
	s := newTestTLSSwitch(t)
	sec, key := pendingSection(t, now.Add(2*time.Minute))
	p, err := s.Prepare(sec, key, now)
	if err != nil {
		t.Fatal(err)
	}
	s.Use(p)
	if s.Current() != sec.Fingerprint {
		t.Fatalf("сертификат в пределах допуска часов не включён: %q", s.Current())
	}

	// Начнёт действовать через час — включается по повторной проверке.
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	s = newTestTLSSwitch(t)
	s.clock = func() time.Time { return time.Unix(0, clock.Load()) }
	sec, key = pendingSection(t, now.Add(time.Hour))
	if p, err = s.Prepare(sec, key, now); err != nil {
		t.Fatal(err)
	}
	s.Use(p)
	time.Sleep(50 * time.Millisecond)
	if s.Current() != "" {
		t.Fatalf("ещё не действующий сертификат включён: %q", s.Current())
	}
	clock.Store(now.Add(time.Hour + time.Minute).UnixNano())
	deadline := time.Now().Add(5 * time.Second)
	for s.Current() != sec.Fingerprint {
		if time.Now().After(deadline) {
			t.Fatal("сертификат не включён, когда начал действовать")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Неверный ещё не действующий раздел отклоняется сразу, а не при повторе.
	bad := *sec
	bad.Fingerprint = strings.Repeat("0", 64)
	if _, err := newTestTLSSwitch(t).Prepare(&bad, key, now); err == nil {
		t.Fatal("отпечаток ещё не действующего раздела не сверен")
	}

	// Новый пакет без раздела отменяет ожидание прежнего.
	clock.Store(now.UnixNano())
	s = newTestTLSSwitch(t)
	s.clock = func() time.Time { return time.Unix(0, clock.Load()) }
	if p, err = s.Prepare(sec, key, now); err != nil {
		t.Fatal(err)
	}
	s.Use(p)
	s.Use(nil)
	clock.Store(now.Add(time.Hour + time.Minute).UnixNano())
	time.Sleep(50 * time.Millisecond)
	if s.Current() != "" {
		t.Fatalf("ожидание прежнего раздела включило сертификат: %q", s.Current())
	}
}
