package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Перевыпуск сертификата, закрепление ключа получателя и номер цепочки
// доверия на внутреннем порту (задача 3.3, ADR-0018, п. 4, 6, 7).

func TestReissueCertificateHandler(t *testing.T) {
	svc, gw := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway(gw.ID)})
	if err != nil {
		t.Fatal(err)
	}
	// УЦ теста действует час: сертификат истекает раньше 30 суток.
	w := do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1"}`, "Content-Type", "application/json")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"reissue":true`) {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body)
	}
	const path = "/internal/v1/certificate"
	for name, body := range map[string]string{
		"не CSR":        `{"csr":"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}`,
		"пусто":         `{"csr":""}`,
		"лишнее поле":   `{"csr":"x","cn":"other"}`,
		"не JSON":       `csr`,
		"больше 16 КиБ": `{"csr":"` + strings.Repeat("A", 17<<10) + `"}`,
	} {
		if w := do(h, http.MethodPost, path, body, "Content-Type", "application/json"); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	key, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"csr":` + jsonString(string(csr)) + `}`
	w = do(h, http.MethodPost, path, body, "Content-Type", "application/json")
	if w.Code != http.StatusOK {
		t.Fatalf("перевыпуск: %d %s", w.Code, w.Body)
	}
	var resp CertificateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if err := aisecCrypto.VerifyClientCert([]byte(resp.Certificate), key, gw.ID, nil, time.Now()); err != nil {
		t.Fatalf("сертификат не к ключу CSR: %v", err)
	}
	peer, err := aisecCrypto.ParseCertInfo([]byte(resp.Certificate))
	if err != nil || peer.CommonName != gw.ID || resp.NotAfter.IsZero() {
		t.Fatalf("сертификат: %+v %v", peer, err)
	}
	if w := do(h, http.MethodPost, path, body, "Content-Type", "application/json"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("второй перевыпуск за минуту: %d", w.Code)
	}
	// Неизвестный шлюз и запрос без сертификата — 401.
	h2, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway("nope")})
	if err != nil {
		t.Fatal(err)
	}
	if w := do(h2, http.MethodPost, path, body, "Content-Type", "application/json"); w.Code != http.StatusUnauthorized {
		t.Fatalf("неизвестный шлюз: %d", w.Code)
	}
	h3, _ := newInternalHandler(t, nil)
	if w := do(h3, http.MethodPost, path, body, "Content-Type", "application/json"); w.Code != http.StatusUnauthorized {
		t.Fatalf("без сертификата: %d", w.Code)
	}
}

// Н27: пакет выдаётся только для закреплённого ключа получателя.
func TestBundleKeyMismatchRejected(t *testing.T) {
	e := newBundleEnv(t, true)
	svc, gw := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway(gw.ID),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Extra: BundleRoutes(e.svc, svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/internal/v1/policies/bundle"
	pinned := base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey())
	if w := do(h, http.MethodGet, path, "", BundleKeyHeader, pinned); w.Code != http.StatusOK {
		t.Fatalf("первый запрос закрепляет ключ: %d %s", w.Code, w.Body)
	}
	other, err := e.fx.Provider.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	w := do(h, http.MethodGet, path, "", BundleKeyHeader, base64.RawURLEncoding.EncodeToString(other.PublicKey()))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"bundle_key_mismatch"`) {
		t.Fatalf("чужой ключ: %d %s", w.Code, w.Body)
	}
	if w := do(h, http.MethodGet, path, "", BundleKeyHeader, pinned); w.Code != http.StatusOK {
		t.Fatalf("закреплённый ключ: %d", w.Code)
	}
}

// ADR-0018, п. 4.3: шлюз со старым номером цепочки получает пакет с
// заявлениями и при совпавшем ETag.
func TestBundleTrustSeqHeader(t *testing.T) {
	e := newBundleEnv(t, true)
	p := e.fx.Provider
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	next, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	anchor := e.fx.Verifier(t)
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	raw, err := bundle.SignTrust(p, e.fx.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: time.Now(), Keys: []bundle.TrustKey{
		{ID: bundle.KeyID(h, anchor.PublicKey()), PublicKey: anchor.PublicKey(), NotAfter: &until},
		{ID: bundle.KeyID(h, next.PublicKey()), PublicKey: next.PublicKey()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := bundle.NewTrustChain(p, []aisecCrypto.Verifier{anchor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Append(raw); err != nil {
		t.Fatal(err)
	}
	e.fx.Sealer.SetTrust(server)
	hh := e.handler(t, asGateway(bundletest.GatewayID))
	key := base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey())
	const path = "/internal/v1/policies/bundle"
	w := do(hh, http.MethodGet, path, "", BundleKeyHeader, key, TrustSeqHeader, "0")
	if w.Code != http.StatusOK {
		t.Fatalf("пакет: %d %s", w.Code, w.Body)
	}
	o := e.fx.Opener(t)
	gwChain, err := bundle.NewTrustChain(p, []aisecCrypto.Verifier{anchor})
	if err != nil {
		t.Fatal(err)
	}
	o.SetTrust(gwChain, nil)
	b, err := o.Open(w.Body.Bytes(), 0)
	if err != nil || o.TrustSeq() != 1 {
		t.Fatalf("пакет с заявлением: %v, номер %d", err, o.TrustSeq())
	}
	etag := b.ETag()
	for name, tc := range map[string]struct {
		hdr  []string
		code int
	}{
		"шлюз отстал по цепочке": {[]string{TrustSeqHeader, "0"}, http.StatusOK},
		"цепочка как у сервера":  {[]string{TrustSeqHeader, "1"}, http.StatusNotModified},
		"шлюз прежней версии":    {nil, http.StatusNotModified},
		"отрицательный номер":    {[]string{TrustSeqHeader, "-1"}, http.StatusBadRequest},
		"не число":               {[]string{TrustSeqHeader, "x"}, http.StatusBadRequest},
		"два заголовка":          {[]string{TrustSeqHeader, "1", TrustSeqHeader, "1"}, http.StatusBadRequest},
		"слишком длинный":        {[]string{TrustSeqHeader, strings.Repeat("9", 20)}, http.StatusBadRequest},
	} {
		hdr := append([]string{BundleKeyHeader, key, "If-None-Match", etag}, tc.hdr...)
		if w := do(hh, http.MethodGet, path, "", hdr...); w.Code != tc.code {
			t.Errorf("%s: %d, ожидается %d", name, w.Code, tc.code)
		}
	}
	// Шлюз без цепочки не принимает пакет с заявлениями (формат).
	if _, err := e.fx.Opener(t).Open(w.Body.Bytes(), 0); bundle.Reason(err) != bundle.ReasonFormat {
		t.Fatalf("пакет с заявлениями без цепочки: %v", err)
	}
}
