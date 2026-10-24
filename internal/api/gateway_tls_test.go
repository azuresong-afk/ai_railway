package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

func gatewayTLSBody(t *testing.T, host string, chain, key []byte) string {
	t.Helper()
	b, err := json.Marshal(GatewayTLSRequest{Host: host, ChainPEM: string(chain), KeyPEM: string(key)})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Сертификат заказчика для адреса шлюза через API (задача 3.27): загрузка
// администратором системы, сведения без ключа, отказы в доступе, неверные
// данные, замена и удаление с записями аудита. Отказ в доступе по всем
// маршрутам — ещё и в TestRBACMatrixDenials.
func TestGatewayTLSViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"aisec-gw.example.ru"}})
	if err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/gateway-certificate"

	if w := e.call(sys, "GET", path, "", false); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"configured":false,"key_set":false}` {
		t.Fatalf("без сертификата: %d %s", w.Code, w.Body)
	}
	body := gatewayTLSBody(t, "AISEC-GW.example.ru", chain.Full(), chain.Key)
	// Отказ в доступе: аналитик, аудитор и владелец приложения не загружают.
	for _, s := range []session{analyst, auditor, owner} {
		mustProblem(t, e.call(s, "PUT", path, body, true), 403, CodeForbidden)
		mustProblem(t, e.call(s, "DELETE", path, "", true), 403, CodeForbidden)
	}
	mustProblem(t, e.call(analyst, "GET", path, "", false), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", path, "", false), 403, CodeForbidden)

	w := e.call(sys, "PUT", path, body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	v := decode[GatewayTLSView](t, w.Body.Bytes())
	if !v.Configured || !v.KeySet || v.Host != "aisec-gw.example.ru" || v.ChainLen != 3 || v.KeyAlg != "ECDSA P-256" ||
		v.DaysLeft == nil || *v.DaysLeft < 360 || len(v.Fingerprint) != 64 {
		t.Fatalf("сведения: %+v", v)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("ключ или цепочка в ответе")
	}
	// Аудитор видит сведения (чтение), но не ключ.
	if w := e.call(auditor, "GET", path, "", false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), v.Fingerprint) ||
		strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatalf("чтение аудитором: %d %s", w.Code, w.Body)
	}
	rec, n := e.appAction("gateway_tls.set")
	if n != 1 || rec.Actor.ID != tSysAdminID {
		t.Fatalf("аудит загрузки: %d %+v", n, rec)
	}
	d := rec.Details.(map[string]any)
	if d["replaced"] != false || d["fingerprint"] != v.Fingerprint || d["host"] != "aisec-gw.example.ru" {
		t.Fatalf("подробности аудита: %+v", d)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "CERTIFICATE") {
		t.Fatal("ключ или цепочка в аудите")
	}

	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"aisec-gw.example.ru"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"чужой ключ":  gatewayTLSBody(t, "aisec-gw.example.ru", chain.Full(), other.Key),
		"чужое имя":   gatewayTLSBody(t, "other.example.ru", chain.Full(), chain.Key),
		"без корня":   gatewayTLSBody(t, "aisec-gw.example.ru", append(append([]byte{}, chain.Leaf...), chain.Intermediate...), chain.Key),
		"без ключа":   gatewayTLSBody(t, "aisec-gw.example.ru", chain.Full(), nil),
		"лишнее поле": `{"host":"a","chain_pem":"","key_pem":"","x":1}`,
	} {
		w := e.call(sys, "PUT", path, bad, true)
		mustProblem(t, w, 400, CodeInvalidRequest)
		if strings.Contains(w.Body.String(), "PRIVATE KEY-----") {
			t.Fatalf("%s: ключ в ответе об ошибке", name)
		}
	}
	// Администратор безопасности заменяет сертификат.
	if w := e.call(admin, "PUT", path, gatewayTLSBody(t, "aisec-gw.example.ru", other.Full(), other.Key), true); w.Code != http.StatusOK {
		t.Fatalf("замена: %d %s", w.Code, w.Body)
	}
	if rec, n := e.appAction("gateway_tls.set"); n != 2 || rec.Details.(map[string]any)["replaced"] != true ||
		rec.Details.(map[string]any)["previous_fingerprint"] != v.Fingerprint {
		t.Fatalf("аудит замены: %d %+v", n, rec)
	}
	if w := e.call(sys, "DELETE", path, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "DELETE", path, "", true), 404, CodeNotFound)
	if _, n := e.appAction("gateway_tls.delete"); n != 1 {
		t.Fatal("нет записи gateway_tls.delete")
	}
}
