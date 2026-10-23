package apps_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Хранение сертификата заказчика на живой БД (задача 3.27, миграция
// 0038): ключ только шифротекстом ключа данных с AAD места хранения,
// счётчик изменений конфигурации растёт, записи аудита без цепочки и
// ключа, замена, перешифрование при ротации ключа данных и удаление.
func TestPGGatewayTLSStorage(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"aisec-gw.example.ru"}, LeafRSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GatewayTLS(ctx); !errors.Is(err, apps.ErrNoGatewayTLS) {
		t.Fatalf("без сертификата: %v", err)
	}
	revision := func() int64 {
		var r int64
		if err := e.owner.QueryRow(ctx, `SELECT coalesce(max(revision), 0) FROM config_revisions`).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rev0 := revision()
	got, err := e.svc.SetGatewayTLS(ctx, e.by, apps.GatewayTLSInput{Host: "aisec-gw.example.ru", ChainPEM: chain.Full(), KeyPEM: chain.Key})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert.KeyAlg != "RSA 2048" || got.Cert.ChainLen != 3 || got.Key.KeyID != e.keyID {
		t.Fatalf("сведения: %+v", got.Cert)
	}
	if revision() <= rev0 {
		t.Fatal("счётчик изменений конфигурации не вырос")
	}
	var sealed []byte
	var chainPEM string
	if err := e.owner.QueryRow(ctx, `SELECT key_sealed, chain_pem FROM gateway_tls WHERE org_id = $1`, audit.DefaultOrgID).
		Scan(&sealed, &chainPEM); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) || chainPEM != string(chain.Full()) {
		t.Fatal("ключ хранится открыто или цепочка не каноническая")
	}
	stored, err := e.svc.GatewayTLS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Cert.Fingerprint != got.Cert.Fingerprint || !stored.Cert.NotAfter.Equal(got.Cert.NotAfter) ||
		strings.Join(stored.Cert.DNSNames, ",") != "aisec-gw.example.ru" {
		t.Fatalf("прочитано: %+v", stored.Cert)
	}
	key, err := e.svc.OpenGatewayTLSKey(ctx, stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := aisecCrypto.ParseServerCert(stored.Cert.ChainPEM, key, stored.Host, time.Now()); err != nil {
		t.Fatalf("расшифрованный ключ не подходит: %v", err)
	}
	// Шифротекст не переносится в чужое место хранения (AAD).
	moved := stored
	moved.OrgID = "01900000-0000-7000-8000-0000000000ff"
	if _, err := e.svc.OpenGatewayTLSKey(ctx, moved); err == nil {
		t.Fatal("шифротекст расшифрован с чужим AAD")
	}
	// Роль сервера не меняет организацию и автора первой загрузки.
	if _, err := e.app.Exec(ctx, `UPDATE gateway_tls SET created_by = 'x'`); sqlState(err) != "42501" {
		t.Fatalf("изменение created_by ролью сервера: %v", err)
	}

	// Замена: другой сертификат того же адреса.
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"aisec-gw.example.ru"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetGatewayTLS(ctx, e.by, apps.GatewayTLSInput{Host: "aisec-gw.example.ru", ChainPEM: other.Full(), KeyPEM: other.Key}); err != nil {
		t.Fatal(err)
	}
	// Неверные данные не меняют сохранённое.
	if _, err := e.svc.SetGatewayTLS(ctx, e.by, apps.GatewayTLSInput{Host: "other.example.ru", ChainPEM: other.Full(), KeyPEM: other.Key}); err == nil {
		t.Fatal("чужое имя принято")
	}

	// Ротация ключа данных: ключ сертификата перешифрован и читается.
	ownerLog, err := audit.New(e.owner, mustProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := keyring.RotateData(ctx, e.owner, ownerLog, mustProfile(t), e.dir, audit.DefaultOrgID, actor, time.Now()); err != nil {
		t.Fatal(err)
	}
	full, err := keyring.Load(ctx, e.owner, mustProfile(t), e.dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := keyring.Rewrap(ctx, e.owner, full, keyring.RewrapOptions{ContentPurpose: "event-content"})
	if err != nil || n.GatewayTLS != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if res, err := keyring.DestroyRetired(ctx, e.owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := e.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	stored, err = e.svc.GatewayTLS(ctx)
	if err != nil || stored.Key.KeyID == e.keyID {
		t.Fatalf("после ротации: %v", err)
	}
	if key, err = e.svc.OpenGatewayTLSKey(ctx, stored); err != nil {
		t.Fatalf("ключ после ротации: %v", err)
	}
	clear(key)

	if _, err := e.svc.DeleteGatewayTLS(ctx, e.by); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeleteGatewayTLS(ctx, e.by); !errors.Is(err, apps.ErrNoGatewayTLS) {
		t.Fatalf("повторное удаление: %v", err)
	}
	acts := e.actions(t)
	if acts["gateway_tls.set"] != 2 || acts["gateway_tls.delete"] != 1 {
		t.Fatalf("аудит: %v", acts)
	}
	var details string
	if err := e.owner.QueryRow(ctx, "SELECT string_agg(details::text, ' ') FROM audit_log").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "PRIVATE KEY") || strings.Contains(details, "BEGIN CERTIFICATE") {
		t.Fatal("ключ или цепочка попали в журнал аудита")
	}
}

func mustProfile(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
