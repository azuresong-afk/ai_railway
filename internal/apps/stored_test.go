package apps_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Сохранённая настройка доступа по группам проверяется правилами API для
// моделей и псевдонимов приложения (остаток 5.8, остатки волны A этапа 5).
func TestCheckStoredUserAccess(t *testing.T) {
	models, aliases := []string{"gpt-x", "gpt-y"}, map[string]string{"fast": "gpt-x"}
	in := userInput(apps.UserTokenRequired, map[string][]string{"fast": {"sales", "support", "sales"}})
	u, err := apps.CleanUserAccess(models, aliases, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := apps.CheckStoredUserAccess(models, aliases, u); err != nil {
		t.Fatalf("сохранённая сервисом настройка отклонена: %v", err)
	}
	for _, tc := range []struct {
		name, field string
		change      func(u *apps.UserAccess)
	}{
		{"модель не из приложения", "model_groups", func(u *apps.UserAccess) { u.ModelGroups = map[string][]string{"gpt-z": {"sales"}} }},
		{"группы под псевдонимом", "user_access", func(u *apps.UserAccess) { u.ModelGroups = map[string][]string{"fast": {"sales"}} }},
		{"группы не по возрастанию", "user_access", func(u *apps.UserAccess) {
			u.ModelGroups = map[string][]string{"gpt-x": {"support", "sales"}}
		}},
		{"группы без JWT", "model_groups", func(u *apps.UserAccess) { u.Mode = apps.UserTokenOff }},
		{"неизвестный режим", "mode", func(u *apps.UserAccess) { u.Mode = "always" }},
		{"допуск часов", "leeway", func(u *apps.UserAccess) { u.Leeway = -1 }},
	} {
		c := u
		c.ModelGroups = map[string][]string{"gpt-x": {"sales", "support"}}
		tc.change(&c)
		err := apps.CheckStoredUserAccess(models, aliases, c)
		var ie *apps.InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// Сохранённый сертификат шлюза: ключ — пара цепочке, имя и отпечаток те же;
// истёкший после снятия копии — не отказ (остатки волны A этапа 5).
func TestCheckStoredGatewayTLS(t *testing.T) {
	const host = "aisec-gw.example.ru"
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	h, cert, key, err := apps.ParseGatewayTLS(apps.GatewayTLSInput{Host: host, ChainPEM: chain.Full(), KeyPEM: chain.Key}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := apps.CheckStoredGatewayTLS(h, cert.ChainPEM, key, cert.Fingerprint, cert.NotAfter); err != nil {
		t.Fatalf("сохранённый сервисом сертификат отклонён: %v", err)
	}
	past := time.Now().Add(-12 * time.Hour)
	expired, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}, NotBefore: past.Add(-time.Hour), NotAfter: past})
	if err != nil {
		t.Fatal(err)
	}
	_, ec, ek, err := apps.ParseGatewayTLS(apps.GatewayTLSInput{Host: host, ChainPEM: expired.Full(), KeyPEM: expired.Key}, past.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := apps.CheckStoredGatewayTLS(host, ec.ChainPEM, ek, ec.Fingerprint, ec.NotAfter); err != nil {
		t.Fatalf("истёкший после копии сертификат отклонён: %v", err)
	}
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want  string
		host        string
		key         []byte
		fingerprint string
		notAfter    time.Time
	}{
		{"ключ другой цепочки", "закрытый ключ не подходит", host, other.Key, cert.Fingerprint, cert.NotAfter},
		{"имя не из SAN", "не на имя", "other.example.ru", key, cert.Fingerprint, cert.NotAfter},
		{"чужой отпечаток", "не совпадают", host, key, strings.Repeat("0", 64), cert.NotAfter},
		{"другой срок", "не совпадают", host, key, cert.Fingerprint, cert.NotAfter.Add(-time.Hour)},
		{"имя в верхнем регистре", "не совпадают", strings.ToUpper(host), key, cert.Fingerprint, cert.NotAfter},
	} {
		err := apps.CheckStoredGatewayTLS(tc.host, cert.ChainPEM, tc.key, tc.fingerprint, tc.notAfter)
		var ie *apps.InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
