package cliclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// readyTimeout — срок одной проверки готовности.
const readyTimeout = 15 * time.Second

// Ready — проверка готовности своего сервера при обновлении (aisec-cli
// update, ADR-0036, раздел 4): GET адреса /readyz по https с доверием
// только корню из caFile, без прокси и перенаправлений; готов — ответ 200.
// Адрес задаёт администратор (флаг или AISEC_SERVER_LISTEN своего сервера).
func Ready(ctx context.Context, p aisecCrypto.Provider, rawURL, caFile string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/readyz" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("адрес проверки готовности: ожидается https://узел:порт/readyz без учётных данных")
	}
	if p == nil {
		return errors.New("проверка готовности: не задан криптопрофиль")
	}
	roots, err := aisecCrypto.ReadPEMFile(caFile)
	if err != nil {
		return fmt.Errorf("корень проверки готовности: %w", err)
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		return err
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:        cfg,
		TLSHandshakeTimeout:    tlsTimeout,
		ResponseHeaderTimeout:  readyTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: readyTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect }}
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("сервер не ответил на %s: %w", u.Redacted(), err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:gosec // G104: тело не нужно
	_ = resp.Body.Close()                                       //nolint:gosec // G104: ответ прочитан
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер не готов: %s ответил %d", u.Redacted(), resp.StatusCode)
	}
	return nil
}
