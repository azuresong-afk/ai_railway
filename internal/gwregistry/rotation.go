package gwregistry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ротация корня внутреннего УЦ, перевыпуск сертификатов шлюзов и
// закрепление ключа получателя HPKE (ADR-0018, п. 6–7; задача 3.3 этапа 3).

// ReissueBefore — за сколько до истечения сертификата шлюз получает
// признак перевыпуска в ответе heartbeat.
const ReissueBefore = 30 * 24 * time.Hour

// reissueEvery — не чаще одного перевыпуска в минуту на шлюз: подпись УЦ
// не становится нагрузкой по запросу шлюза.
const reissueEvery = time.Minute

// bundleKeyMismatchEvery — не чаще одной записи аудита о чужом ключе
// получателя в минуту на шлюз.
const bundleKeyMismatchEvery = time.Minute

// Ошибки ротации.
var (
	// ErrBundleKeyMismatch — ключ получателя в запросе пакета не совпадает с
	// закреплённым (Н27): секреты для него не шифруются.
	ErrBundleKeyMismatch = errors.New("ключ получателя не совпадает с закреплённым при регистрации")
)

// Issued — выпущенный сертификат шлюза: сведения для учёта, корень УЦ,
// которым он выпущен, и (при регистрации) ключ получателя HPKE.
type Issued struct {
	Info      aisecCrypto.CertInfo
	CA        string
	BundleKey []byte
}

// RootSet — корни внутреннего УЦ из заявления о доверии (ADR-0018, п. 6):
// Active — корень, которым сервер выпускает сертификаты; NotAfter — конец
// перекрытия прежних корней (нулевое время — без срока). Корень, которого
// нет в наборе, не принимается.
type RootSet struct {
	Active   string
	NotAfter map[string]time.Time
}

// RootID — идентификатор корня УЦ: первые 8 байт хеша сертификата (DER),
// как bundle.RootID.
func RootID(h aisecCrypto.Hasher, der []byte) string { return hex.EncodeToString(h.Sum(der)[:8]) }

// SetRoots задаёт корни УЦ после загрузки цепочки доверия; без вызова —
// один корень Options.CA без ограничений.
func (s *Service) SetRoots(r RootSet) {
	if r.Active == "" {
		s.roots.Store(nil)
		return
	}
	s.roots.Store(&r)
}

// activeRoot — ID корня, которым выпускаются сертификаты.
func (s *Service) activeRoot() string {
	if r := s.roots.Load(); r != nil {
		return r.Active
	}
	if s.ca != nil {
		return RootID(s.hasher, s.ca.CertDER())
	}
	return ""
}

// checkRoot — корень проверенной цепочки сертификата есть в наборе и его
// перекрытие не истекло; пустая причина — корень принят.
func (s *Service) checkRoot(rootDER []byte, now time.Time) string {
	r := s.roots.Load()
	if r == nil {
		return ""
	}
	end, ok := r.NotAfter[RootID(s.hasher, rootDER)]
	switch {
	case !ok:
		return "ca_unknown"
	case !end.IsZero() && !now.Before(end):
		return "ca_expired"
	}
	return ""
}

// needReissue — сертификат шлюза выпущен не действующим корнем или
// истекает через ReissueBefore и меньше. certCA = "" — сертификат выпущен до
// ротаций корнем из -ca-cert.
func (s *Service) needReissue(certCA string, notAfter, now time.Time) bool {
	if s.ca == nil {
		return false
	}
	if certCA == "" && s.ca != nil {
		certCA = s.anchorRoot
	}
	return certCA != s.activeRoot() || notAfter.Sub(now) <= ReissueBefore
}

// Reissue выпускает шлюзу новый сертификат по CSR (POST
// /internal/v1/certificate, ADR-0018, п. 6.3). Сертификат сохраняется как
// следующий: прежний действует, пока шлюз не придёт с новым.
func (s *Service) Reissue(ctx context.Context, gatewayID string, csr []byte, ip netip.Addr) ([]byte, aisecCrypto.CertInfo, error) {
	if s.ca == nil {
		return nil, aisecCrypto.CertInfo{}, ErrNoCA
	}
	if err := aisecCrypto.CheckCSR(csr); err != nil {
		return nil, aisecCrypto.CertInfo{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err) //nolint:errorlint // причина CSR — только текстом
	}
	now := s.clock().UTC()
	s.mu.Lock()
	if last, ok := s.lastReissue[gatewayID]; ok && now.Sub(last) < reissueEvery {
		s.mu.Unlock()
		return nil, aisecCrypto.CertInfo{}, ErrTooFrequent
	}
	prune(s.lastReissue, now, reissueEvery)
	s.lastReissue[gatewayID] = now
	s.mu.Unlock()
	certPEM, info, err := s.ca.IssueClient(csr, gatewayID, s.validity, now)
	if err != nil {
		return nil, aisecCrypto.CertInfo{}, err
	}
	root := s.activeRoot()
	_, err = s.store.SetNextCert(ctx, gatewayID, Issued{Info: info, CA: root}, func(gw Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID, Name: gw.Name}, SourceIP: ip,
			Action: "gateway.cert_reissue", Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{"stage": "issued", "cert_serial": info.Serial, "cert_not_after": info.NotAfter.UTC().Format(time.RFC3339),
				"root_id": root, "previous_serial": gw.CertSerial},
		}
	})
	if err != nil {
		return nil, aisecCrypto.CertInfo{}, err
	}
	return certPEM, info, nil
}

// promote делает следующий сертификат действующим при первом запросе с ним.
func (s *Service) promote(ctx context.Context, gw Gateway, ip netip.Addr) (Gateway, error) {
	return s.store.PromoteNext(ctx, gw.ID, gw.NextCertSerial, func(cur Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: cur.ID, Name: cur.Name}, SourceIP: ip,
			Action: "gateway.cert_reissue", Object: audit.Object{Type: "gateway", ID: cur.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{"stage": "activated", "cert_serial": cur.CertSerial, "root_id": cur.CertCA,
				"cert_not_after": cur.CertNotAfter.UTC().Format(time.RFC3339), "previous_serial": gw.CertSerial},
		}
	})
}

// CheckBundleKey сверяет ключ получателя из запроса пакета с закреплённым
// (Н27, ADR-0018, п. 7). Шлюз без закреплённого ключа (зарегистрирован без
// него) закрепляет этот ключ: запись gateway.bundle_key_pinned. Другой
// ключ — ErrBundleKeyMismatch с записью gateway.bundle_key_mismatch не чаще
// раза в минуту на шлюз.
func (s *Service) CheckBundleKey(ctx context.Context, gatewayID string, key []byte, ip netip.Addr) error {
	if len(key) != aisecCrypto.RecipientPublicKeySize {
		return ErrInvalidRequest
	}
	pinned := false
	gw, err := s.store.PinBundleKey(ctx, gatewayID, key, func(gw Gateway) audit.Entry {
		pinned = true
		return audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID, Name: gw.Name}, SourceIP: ip,
			Action: "gateway.bundle_key_pinned", Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{"key_hash": hex.EncodeToString(s.hasher.Sum(key)[:8]), "source": "first_bundle_request"},
		}
	})
	if err != nil {
		return err
	}
	if pinned || aisecCrypto.Equal(gw.BundleKey, key) {
		return nil
	}
	now := s.clock()
	s.mu.Lock()
	last, seen := s.lastMismatch[gatewayID]
	write := !seen || now.Sub(last) >= bundleKeyMismatchEvery
	if write {
		prune(s.lastMismatch, now, bundleKeyMismatchEvery)
		s.lastMismatch[gatewayID] = now
	}
	s.mu.Unlock()
	if write {
		if err := s.audit.Record(ctx, audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID, Name: gw.Name}, SourceIP: ip,
			Action: "gateway.bundle_key_mismatch", Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultDenied,
			Details: map[string]any{"key_hash": hex.EncodeToString(s.hasher.Sum(key)[:8]),
				"pinned_key_hash": hex.EncodeToString(s.hasher.Sum(gw.BundleKey)[:8])},
		}); err != nil {
			return fmt.Errorf("аудит чужого ключа получателя: %w", err)
		}
	}
	return ErrBundleKeyMismatch
}
