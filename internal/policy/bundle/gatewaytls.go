package bundle

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// GatewayTLS — раздел gateway_tls (задача 3.27 этапа 3, решение Р9):
// сертификат заказчика для адреса шлюза. Цепочка — в открытом содержимом,
// закрытый ключ — среди секретов пакета (зашифрован для шлюза, HPKE).
// Раздела нет — шлюз обслуживает приложения своим сертификатом
// (-tls-cert). Полную проверку (пара ключу, цепочка до корня, имя, срок)
// шлюз выполняет при применении пакета (aisecCrypto.ParseServerCert).
type GatewayTLS struct {
	Host     string `json:"host"`
	ChainPEM string `json:"chain_pem"`
	// Fingerprint — SHA-256 листового сертификата: по нему сервер сверяет
	// ключ при выдаче, шлюз — пару при применении.
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
}

// validate — пределы раздела; nil — раздела нет.
func (t *GatewayTLS) validate() []error {
	if t == nil {
		return nil
	}
	var errs []error
	if h, err := aisecCrypto.NormalizeHost(t.Host); err != nil || h != t.Host {
		errs = append(errs, errors.New("gateway_tls: неверное имя адреса шлюза"))
	}
	if t.ChainPEM == "" || len(t.ChainPEM) > aisecCrypto.MaxServerChainPEM {
		errs = append(errs, fmt.Errorf("gateway_tls: chain_pem — от 1 байта до %d байт", aisecCrypto.MaxServerChainPEM))
	}
	if !sha256Re.MatchString(t.Fingerprint) {
		errs = append(errs, errors.New("gateway_tls: fingerprint — 64 шестнадцатеричные цифры"))
	}
	if t.NotAfter.IsZero() {
		errs = append(errs, errors.New("gateway_tls: not_after обязателен"))
	}
	return errs
}

// checkTLSKey — ключ сертификата заказчика среди секретов: PEM видимыми
// символами ASCII и переводами строк, не длиннее MaxServerKeyPEM.
func checkTLSKey(s string) error {
	if s == "" || len(s) > aisecCrypto.MaxServerKeyPEM {
		return fmt.Errorf("ключ сертификата заказчика — от 1 байта до %d байт", aisecCrypto.MaxServerKeyPEM)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 || c > 0x7e) && c != '\n' && c != '\r' {
			return errors.New("ключ сертификата заказчика — только PEM")
		}
	}
	return nil
}

// KeyPEM — закрытый ключ в PEM только в памяти: при выводе через fmt и
// slog показывается лишь признак наличия.
type KeyPEM []byte

// Format выводит только признак наличия ключа при любом глаголе fmt.
func (k KeyPEM) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, k.summary()) //nolint:gosec // G104: у fmt.Formatter нет способа вернуть ошибку записи
}

// LogValue выводит в slog только признак наличия ключа.
func (k KeyPEM) LogValue() slog.Value { return slog.StringValue(k.summary()) }

func (k KeyPEM) summary() string {
	if len(k) == 0 {
		return "KeyPEM(нет)"
	}
	return "KeyPEM(скрыт)"
}
