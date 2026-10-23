package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Сертификат заказчика на адресе приложений (S1, ТЗ 5.4; решение Р9 этапа
// 3, задача 3.27). Раздел gateway_tls пакета проверяется так же, как при
// загрузке на сервере (aisecCrypto.ParseServerCert), и TLS переключается
// без перезапуска: новые соединения получают новую пару, установленные
// дорабатывают на прежней. Без раздела — сертификат шлюза (-tls-cert).

// TLSSwitch — сертификат TLS адреса приложений шлюза.
type TLSSwitch struct {
	sw     *aisecCrypto.ServerCertSwitch
	logger *slog.Logger
}

// NewTLSSwitch — переключатель над парой по умолчанию из файлов шлюза.
func NewTLSSwitch(sw *aisecCrypto.ServerCertSwitch, logger *slog.Logger) (*TLSSwitch, error) {
	if sw == nil {
		return nil, errors.New("TLS адреса приложений: нет переключателя сертификата")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TLSSwitch{sw: sw, logger: logger}, nil
}

// PreparedTLS — проверенный раздел gateway_tls, готовый к включению.
type PreparedTLS struct {
	pair *aisecCrypto.ServerPair
	host string
	// notAfter — срок цепочки (для журнала).
	notAfter time.Time
}

// Prepare проверяет раздел gateway_tls и ключ из секретов пакета. Неверный
// раздел (ключ не от сертификата, цепочка не до корня, чужое имя, отпечаток
// не совпадает) — ошибка: пакет отклоняется целиком, шлюз остаётся на
// прежнем пакете и прежнем сертификате. Сертификат, который по часам шлюза
// истёк или ещё не действует, ошибкой не считается: шлюз применяет пакет и
// возвращается к своему сертификату (иначе после перезапуска без связи с
// сервером он остался бы без конфигурации). Нет раздела — nil.
func (s *TLSSwitch) Prepare(sec *bundle.GatewayTLS, key bundle.KeyPEM, now time.Time) (*PreparedTLS, error) {
	if sec == nil {
		return nil, nil
	}
	sc, canon, err := aisecCrypto.ParseServerCert([]byte(sec.ChainPEM), key, sec.Host, now)
	if errors.Is(err, aisecCrypto.ErrCertNotValidNow) {
		s.logger.Error("сертификат заказчика из пакета конфигурации не действует по часам шлюза: адрес приложений обслуживается сертификатом шлюза",
			"host", sec.Host, "fingerprint", sec.Fingerprint, "not_after", sec.NotAfter, "error", err)
		return &PreparedTLS{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("раздел gateway_tls: %w", err)
	}
	defer clear(canon)
	if sc.Fingerprint != sec.Fingerprint {
		return nil, errors.New("раздел gateway_tls: отпечаток сертификата не совпадает с цепочкой")
	}
	pair, err := aisecCrypto.NewServerPair(sc.ChainPEM, canon)
	if err != nil {
		return nil, fmt.Errorf("раздел gateway_tls: %w", err)
	}
	return &PreparedTLS{pair: pair, host: sec.Host, notAfter: sc.NotAfter}, nil
}

// Use включает подготовленный раздел: nil или пустой — сертификат шлюза.
// Вызывается после того, как пакет применён целиком.
func (s *TLSSwitch) Use(p *PreparedTLS) {
	prev := s.sw.Current()
	if p == nil || p.pair == nil {
		s.sw.Use(nil)
		if prev != "" {
			s.logger.Warn("адрес приложений переключён на сертификат шлюза: сертификата заказчика в пакете нет или он не действует",
				"previous_fingerprint", prev)
		}
		return
	}
	s.sw.Use(p.pair)
	if prev != p.pair.Fingerprint {
		s.logger.Info("адрес приложений переключён на сертификат заказчика без перезапуска", "host", p.host,
			"fingerprint", p.pair.Fingerprint, "not_after", p.notAfter)
	}
}

// Current — отпечаток действующего сертификата заказчика; пусто — шлюз на
// своём сертификате.
func (s *TLSSwitch) Current() string { return s.sw.Current() }
