package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Перевыпуск сертификата шлюза (ADR-0018, п. 6.3): по признаку из ответа
// heartbeat шлюз создаёт новый ключ и CSR, получает сертификат по mTLS с
// прежним, проверяет его, атомарно сохраняет пару в client.pem и
// переключает клиент TLS без перезапуска. Сбой на любом шаге оставляет
// прежний сертификат: сервер принимает оба, пока шлюз не придёт с новым.

// ReissueConfig — параметры перевыпуска.
type ReissueConfig struct {
	// Client — HTTP-клиент с транспортом Transport.
	Client    *http.Client
	Transport *http.Transport
	Server    *url.URL
	GatewayID string
	Switch    *aisecCrypto.ClientCertSwitch
	State     *BundleState
	// Roots — корни УЦ из заявления о доверии с неистёкшим перекрытием:
	// новый сертификат должен вести к одному из них. Пусто — корни не
	// менялись, сертификат проверяется по ключу, имени и сроку.
	Roots  func() [][]byte
	Logger *slog.Logger
	Clock  func() time.Time
}

// Reissuer выполняет перевыпуск.
type Reissuer struct{ c ReissueConfig }

// NewReissuer проверяет параметры.
func NewReissuer(c ReissueConfig) (*Reissuer, error) {
	if c.Client == nil || c.Transport == nil || c.Server == nil || c.GatewayID == "" || c.Switch == nil || c.State == nil {
		return nil, errors.New("перевыпуск сертификата: не заданы клиент, сервер, ID шлюза, переключатель или каталог состояния")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Roots == nil {
		c.Roots = func() [][]byte { return nil }
	}
	return &Reissuer{c: c}, nil
}

// Reissue — один перевыпуск.
func (r *Reissuer) Reissue(ctx context.Context) error {
	keyPEM, csrPEM, err := aisecCrypto.NewClientCSR(r.c.GatewayID)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	var resp struct {
		Certificate string    `json:"certificate"`
		NotAfter    time.Time `json:"not_after"`
	}
	u := r.c.Server.JoinPath("/internal/v1/certificate").String()
	if err := postControl(ctx, r.c.Client, u, map[string]string{"csr": string(csrPEM)}, &resp, http.StatusOK); err != nil {
		return err
	}
	certPEM := []byte(resp.Certificate)
	if err := aisecCrypto.VerifyClientCert(certPEM, keyPEM, r.c.GatewayID, r.c.Roots(), r.c.Clock()); err != nil {
		return fmt.Errorf("сервер выдал неподходящий сертификат: %w", err)
	}
	// Сначала на диск: после перезапуска шлюз придёт с тем же сертификатом,
	// что и сейчас.
	if err := r.c.State.SaveClientPair(certPEM, keyPEM); err != nil {
		return err
	}
	if err := r.c.Switch.Set(certPEM, keyPEM); err != nil {
		return err
	}
	r.c.Transport.CloseIdleConnections()
	info, _ := aisecCrypto.ParseCertInfo(certPEM) //nolint:gosec // G104: сертификат уже проверен VerifyClientCert
	r.c.Logger.Info("сертификат шлюза перевыпущен", "cert_serial", info.Serial, "not_after", info.NotAfter.UTC())
	return nil
}
