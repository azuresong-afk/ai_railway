package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// gatewayTLSMaxBody — тело загрузки: цепочка и ключ в PEM внутри JSON
// (переводы строк экранируются, поэтому запас вдвое).
const gatewayTLSMaxBody = 2 * (aisecCrypto.MaxServerChainPEM + aisecCrypto.MaxServerKeyPEM)

const gatewayTLSNotFound = "Сертификат заказчика для адреса шлюза не задан."

// gatewayTLSRoutes — сертификат заказчика для адреса шлюза (S1, ТЗ 5.4;
// решение Р9 этапа 3, задача 3.27): загрузка цепочки и закрытого ключа в
// PEM, сведения о сертификате, удаление. Ключ в ответах не возвращается.
func gatewayTLSRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/gateway-certificate", Permission: auth.PermGatewayTLSRead,
			Handler: needApps(d, d.getGatewayTLS)},
		{Method: http.MethodPut, Path: "/api/v1/gateway-certificate", Permission: auth.PermGatewayTLSManage,
			MaxBody: gatewayTLSMaxBody, Handler: needApps(d, d.setGatewayTLS)},
		{Method: http.MethodDelete, Path: "/api/v1/gateway-certificate", Permission: auth.PermGatewayTLSManage,
			Handler: needApps(d, d.deleteGatewayTLS)},
	}
}

// GatewayTLSView — сведения о сертификате заказчика. Configured = false —
// сертификата нет: адрес шлюза обслуживает сертификат внутреннего УЦ.
type GatewayTLSView struct {
	Configured  bool       `json:"configured"`
	Host        string     `json:"host,omitempty"`
	Subject     string     `json:"subject,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	Serial      string     `json:"serial,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	DaysLeft    *int       `json:"days_left,omitempty"`
	DNSNames    []string   `json:"dns_names,omitempty"`
	IPAddresses []string   `json:"ip_addresses,omitempty"`
	KeyAlg      string     `json:"key_alg,omitempty"`
	ChainLen    int        `json:"chain_len,omitempty"`
	// KeySet — закрытый ключ задан (сам ключ не показывается).
	KeySet    bool       `json:"key_set"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func gatewayTLSView(t apps.GatewayTLS, now time.Time) GatewayTLSView {
	nb, na, up := t.Cert.NotBefore.UTC(), t.Cert.NotAfter.UTC(), t.UpdatedAt.UTC()
	days := max(int(na.Sub(now)/(24*time.Hour)), 0)
	return GatewayTLSView{Configured: true, Host: t.Host, Subject: t.Cert.Subject, Issuer: t.Cert.Issuer, Serial: t.Cert.Serial,
		Fingerprint: t.Cert.Fingerprint, NotBefore: &nb, NotAfter: &na, DaysLeft: &days, DNSNames: t.Cert.DNSNames,
		IPAddresses: t.Cert.IPAddresses, KeyAlg: t.Cert.KeyAlg, ChainLen: t.Cert.ChainLen, KeySet: len(t.Key.Data) > 0, UpdatedAt: &up}
}

func (d Deps) getGatewayTLS(w http.ResponseWriter, r *http.Request) {
	t, err := d.Apps.GatewayTLS(r.Context())
	switch {
	case errors.Is(err, apps.ErrNoGatewayTLS):
		WriteJSON(w, http.StatusOK, GatewayTLSView{})
	case err != nil:
		WriteProblem(w, appsProblem(d.Logger, err, gatewayTLSNotFound))
	default:
		WriteJSON(w, http.StatusOK, gatewayTLSView(t, time.Now()))
	}
}

// GatewayTLSRequest — тело PUT /api/v1/gateway-certificate.
type GatewayTLSRequest struct {
	Host     string `json:"host"`
	ChainPEM string `json:"chain_pem"`
	KeyPEM   string `json:"key_pem"`
}

func (d Deps) setGatewayTLS(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req GatewayTLSRequest
	if p := DecodeJSON(w, r, &req, gatewayTLSMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	key := []byte(req.KeyPEM)
	t, err := d.Apps.SetGatewayTLS(r.Context(), by, apps.GatewayTLSInput{Host: req.Host, ChainPEM: []byte(req.ChainPEM), KeyPEM: key})
	clear(key)
	if err != nil {
		if errors.Is(err, apps.ErrNoDataKey) {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Ключ данных не подключён: ключ сертификата сохранить нельзя. Выполните aisec-cli init и перезапустите сервер."))
			return
		}
		WriteProblem(w, appsProblem(d.Logger, err, gatewayTLSNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, gatewayTLSView(t, time.Now()))
}

func (d Deps) deleteGatewayTLS(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if _, err := d.Apps.DeleteGatewayTLS(r.Context(), by); err != nil {
		if errors.Is(err, apps.ErrNoGatewayTLS) {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, gatewayTLSNotFound))
			return
		}
		WriteProblem(w, appsProblem(d.Logger, err, gatewayTLSNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
