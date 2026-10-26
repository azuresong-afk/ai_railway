package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Сертификат заказчика на адресе приложений (S1, ТЗ 5.4; решение Р9 этапа
// 3, задача 3.27). Раздел gateway_tls пакета проверяется так же, как при
// загрузке на сервере (aisecCrypto.ParseServerCert), и TLS переключается
// без перезапуска: новые соединения получают новую пару, установленные
// дорабатывают на прежней. Без раздела — сертификат шлюза (-tls-cert).

// tlsNotYetSkew — допуск часов шлюза: сертификат, который начинает
// действовать в пределах допуска, включается сразу (часы отдельного хоста
// отстают на минуты, а клиенты проверяют срок по своим часам; 3Н43 ревью
// 3.r3).
const tlsNotYetSkew = 5 * time.Minute

// tlsPendingRetry — период повторной проверки сертификата, который ещё не
// действует по часам шлюза: та же версия пакета повторно не применяется,
// поэтому без повтора шлюз остался бы на своём сертификате до перезапуска.
var tlsPendingRetry = time.Minute

// TLSSwitch — сертификат TLS адреса приложений шлюза.
type TLSSwitch struct {
	sw     *aisecCrypto.ServerCertSwitch
	logger *slog.Logger
	// clock — часы для повторной проверки; nil — time.Now.
	clock func() time.Time

	mu sync.Mutex
	// gen — номер последнего Use: повтор от прежнего раздела не включает
	// сертификат поверх нового. retry — таймер повторной проверки.
	gen   uint64
	retry *time.Timer
	// waiting — раздел, который ждёт начала действия (его копия ключа
	// стирается, когда раздел включён или заменён).
	waiting *PreparedTLS
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
	// pending и key — раздел, который по часам шлюза ещё не действует (и не
	// истёк): Use включает сертификат шлюза и повторяет проверку, пока
	// раздел не начнёт действовать или не истечёт (3Н43 ревью 3.r3).
	pending *bundle.GatewayTLS
	key     bundle.KeyPEM
}

// Prepare проверяет раздел gateway_tls и ключ из секретов пакета. Неверный
// раздел (ключ не от сертификата, цепочка не до корня, чужое имя, отпечаток
// не совпадает) — ошибка: пакет отклоняется целиком, шлюз остаётся на
// прежнем пакете и прежнем сертификате. Сертификат, который по часам шлюза
// истёк или ещё не действует, ошибкой не считается: шлюз применяет пакет и
// возвращается к своему сертификату (иначе после перезапуска без связи с
// сервером он остался бы без конфигурации). Нет раздела — nil.
func (s *TLSSwitch) Prepare(sec *bundle.GatewayTLS, key bundle.KeyPEM, now time.Time) (*PreparedTLS, error) {
	return s.prepare(sec, key, now, false)
}

// prepare — Prepare; quiet — повторная проверка: ещё не действующий
// сертификат не пишется в журнал на каждом повторе.
func (s *TLSSwitch) prepare(sec *bundle.GatewayTLS, key bundle.KeyPEM, now time.Time, quiet bool) (*PreparedTLS, error) {
	if sec == nil {
		return nil, nil
	}
	sc, canon, err := aisecCrypto.ParseServerCert([]byte(sec.ChainPEM), key, sec.Host, now)
	if errors.Is(err, aisecCrypto.ErrCertNotValidNow) && now.Before(sec.NotAfter) {
		// Не истёк — значит, ещё не действует: в пределах допуска часов
		// включается сразу, иначе — когда начнёт действовать.
		sc, canon, err = aisecCrypto.ParseServerCert([]byte(sec.ChainPEM), key, sec.Host, now.Add(tlsNotYetSkew))
		if err == nil {
			s.logger.Warn("сертификат заказчика начинает действовать в пределах допуска часов: часы шлюза, вероятно, отстают",
				"host", sec.Host, "fingerprint", sec.Fingerprint)
		} else if errors.Is(err, aisecCrypto.ErrCertNotValidNow) {
			if !quiet {
				s.logger.Error("сертификат заказчика из пакета конфигурации ещё не действует по часам шлюза: до начала его действия "+
					"адрес приложений обслуживается сертификатом шлюза, затем переключится без перезапуска",
					"host", sec.Host, "fingerprint", sec.Fingerprint, "error", err)
			}
			// Пару, имя и отпечаток сверяем сразу — на конце срока цепочки,
			// когда все её сертификаты действуют: неверный раздел отклоняет
			// пакет до ответа applied, а не при повторе.
			vsc, vcanon, verr := aisecCrypto.ParseServerCert([]byte(sec.ChainPEM), key, sec.Host, sec.NotAfter.Add(-time.Second))
			clear(vcanon)
			switch {
			case verr != nil && !errors.Is(verr, aisecCrypto.ErrCertNotValidNow):
				return nil, fmt.Errorf("раздел gateway_tls: %w", verr)
			case verr == nil && vsc.Fingerprint != sec.Fingerprint:
				return nil, errors.New("раздел gateway_tls: отпечаток сертификата не совпадает с цепочкой")
			}
			cp := *sec
			return &PreparedTLS{host: sec.Host, pending: &cp, key: bytes.Clone(key)}, nil
		}
	}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	if s.retry != nil {
		s.retry.Stop()
		s.retry = nil
	}
	// Копия ключа ожидавшего раздела больше не нужна.
	if s.waiting != nil {
		clear(s.waiting.key)
		s.waiting = nil
	}
	if p != nil && p.pending != nil {
		s.waiting = p
		s.armRetry(p, s.gen)
	}
	s.use(p)
}

// use переключает пару; вызывается под s.mu.
func (s *TLSSwitch) use(p *PreparedTLS) {
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

// armRetry ставит повторную проверку ещё не действующего раздела p для
// Use номер gen; вызывается под s.mu.
func (s *TLSSwitch) armRetry(p *PreparedTLS, gen uint64) {
	s.retry = time.AfterFunc(tlsPendingRetry, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gen != gen {
			return // раздел сменил новый пакет
		}
		now := time.Now()
		if s.clock != nil {
			now = s.clock()
		}
		q, err := s.prepare(p.pending, p.key, now, true)
		switch {
		case err != nil:
			s.logger.Error("сертификат заказчика из пакета конфигурации не включён при повторной проверке", "host", p.host, "error", err)
		case q.pending != nil:
			clear(q.key)
			s.armRetry(p, gen)
		default:
			clear(p.key)
			s.waiting = nil
			s.use(q)
		}
	})
}

// Current — отпечаток действующего сертификата заказчика; пусто — шлюз на
// своём сертификате.
func (s *TLSSwitch) Current() string { return s.sw.Current() }
